"""Opt-in DCP Runner Agent.

The agent polls the Gateway and executes only pinned Git commits. Execution is
disabled by default; enabling it means trusting selected repository build code
on this host. Use a dedicated, disposable runner account/VM.
"""
from __future__ import annotations

import argparse
import json
import queue
import threading
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path
from urllib.parse import urlparse

from .preflight import collect_preflight, resolve_capabilities
from tools.local_runner_agent.execution import FlutterBuildExecutor


class GatewayError(RuntimeError):
    pass


class JobCancelled(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward a Runner bearer token to a redirected origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GatewayClient:
    def __init__(self, base_url: str, token: str, timeout: int = 30):
        parsed = urlparse(base_url)
        try:
            loopback_http = (
                parsed.scheme == "http"
                and parsed.hostname in ("127.0.0.1", "localhost", "::1")
            )
            valid_origin = (
                (parsed.scheme == "https" or loopback_http)
                and bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
                and parsed.path in ("", "/")
                and not parsed.params
                and not parsed.query
                and not parsed.fragment
                and (parsed.port is None or 1 <= parsed.port <= 65535)
            )
        except ValueError:
            valid_origin = False
        if not valid_origin:
            raise ValueError("DCP_GATEWAY_URL must be an HTTPS origin (HTTP is allowed only on loopback)")
        if not isinstance(token, str) or len(token) < 32:
            raise ValueError("DCP_RUNNER_TOKEN must contain at least 32 characters")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 60:
            raise ValueError("Gateway timeout must be between 1 and 60 seconds")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.opener = urllib.request.build_opener(_NoRedirect())

    def request(self, path, payload=None, data=None, headers=None):
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise ValueError("Gateway request path must be an absolute API path")
        body = data
        request_headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        request_headers.update(headers or {})
        request_headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.base_url + path, data=body, headers=request_headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                raw = response.read(32769)
                if len(raw) > 32768:
                    raise GatewayError("Gateway response exceeded the 32 KiB limit")
                return json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as exc:
            raise GatewayError("Gateway returned HTTP %s" % exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise GatewayError("Gateway connection failed") from None
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise GatewayError("Gateway returned an invalid JSON response") from None

    @staticmethod
    def _validate_job_id(job_id):
        if not isinstance(job_id, str) or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            job_id,
        ):
            raise ValueError("invalid job UUID")

    def register(self, host_os, capabilities):
        return self.request("/v1/runner/register", {"host_os": host_os, "capabilities": capabilities})

    def enroll(self, host_os, capabilities):
        return self.request("/v1/runner/enroll", {"host_os": host_os, "capabilities": capabilities})

    def ping(self):
        return self.request("/v1/runner/ping", {})

    def claim(self, lease_seconds):
        return self.request("/v1/runner/claim", {"lease_seconds": lease_seconds}).get("job")

    def heartbeat(self, job_id, lease_seconds):
        self._validate_job_id(job_id)
        return self.request("/v1/runner/" + job_id + "/heartbeat", {"lease_seconds": lease_seconds})

    def log(self, job_id, message, stream="stdout"):
        self._validate_job_id(job_id)
        return self.request("/v1/runner/" + job_id + "/logs", {"message": message[:8000], "stream": stream})

    def finish(self, job_id, outcome, result=None, error_code=None):
        self._validate_job_id(job_id)
        return self.request("/v1/runner/" + job_id + "/finish", {
            "outcome": outcome, "result": result, "error_code": error_code,
        })

    def upload(self, job_id, path: Path, max_bytes: int = 100 * 1024 * 1024):
        self._validate_job_id(job_id)
        if path.is_symlink() or not path.is_file():
            raise ValueError("artifact path must be a regular file")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= 1024 * 1024 * 1024:
            raise ValueError("artifact size limit is invalid")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", path.name):
            raise ValueError("artifact filename is invalid")
        size = path.stat().st_size
        if not 1 <= size <= max_bytes:
            raise ValueError("artifact size is outside allowed bounds")
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
        if len(data) != size or len(data) > max_bytes:
            raise ValueError("artifact changed or exceeded its size limit")
        result = self.request(
            "/v1/runner/" + job_id + "/artifacts", data=data,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
                "X-DCP-Artifact-Name": path.name,
            },
        )
        artifact = result.get("artifact") if isinstance(result, dict) else None
        if not isinstance(artifact, dict):
            raise GatewayError("Gateway returned an invalid artifact response")
        return artifact

def host_os():
    value = platform.system().lower()
    if value == "darwin":
        return "macos"
    if value in ("windows", "linux"):
        return value
    raise RuntimeError("Unsupported Runner host OS: " + value)


def build_command(target):
    commands = {
        "test": ["flutter", "test"],
        "build": ["flutter", "build", "apk", "--release"],
        "package": ["flutter", "build", "appbundle", "--release"],
        "build_android": ["flutter", "build", "apk", "--release"],
        "build_web": ["flutter", "build", "web", "--release"],
        "build_linux": ["flutter", "build", "linux", "--release"],
        "build_windows": ["flutter", "build", "windows", "--release"],
        "build_macos": ["flutter", "build", "macos", "--release"],
        "build_ios": ["flutter", "build", "ios", "--release", "--no-codesign"],
    }
    if target not in commands:
        raise ValueError("Unsupported build target: " + str(target))
    return commands[target]


def package_output(workspace: Path, target: str, *, max_bytes: int = 100 * 1024 * 1024,
                   max_files: int = 100_000) -> Path | None:
    if target == "test":
        return None
    candidates = {
        "build": [workspace / "build/app/outputs/flutter-apk/app-release.apk"],
        "package": [workspace / "build/app/outputs/bundle/release/app-release.aab"],
        "build_android": [workspace / "build/app/outputs/flutter-apk/app-release.apk"],
        "build_web": [workspace / "build/web"],
        "build_linux": [workspace / "build/linux/x64/release/bundle"],
        "build_windows": [
            workspace / "build/windows/x64/runner/Release",
            workspace / "build/windows/runner/Release",
        ],
        "build_macos": [workspace / "build/macos/Build/Products/Release"],
        "build_ios": [workspace / "build/ios/iphoneos/Runner.app"],
    }.get(target, [])
    output = next((item for item in candidates if item.exists()), None)
    if output is None or output.is_symlink():
        raise RuntimeError("Expected Flutter output is missing or unsafe for " + target)
    if output.is_file():
        info = output.lstat()
        if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= max_bytes:
            raise RuntimeError("Flutter output file is outside allowed bounds")
        return output
    archive = workspace / ("dcp-" + target + ".zip")
    if archive.exists() or archive.is_symlink():
        raise RuntimeError("Artifact destination already exists")
    if output.is_dir():
        entries = []
        total = 0
        for current, dirs, files in os.walk(output, topdown=True, followlinks=False):
            for dirname in list(dirs):
                if (Path(current) / dirname).is_symlink():
                    raise RuntimeError("Flutter output contains a symlink directory")
            for filename in files:
                item = Path(current) / filename
                info = item.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise RuntimeError("Flutter output contains a non-regular file")
                relative = item.relative_to(output.parent)
                if relative.is_absolute() or ".." in relative.parts:
                    raise RuntimeError("Flutter output contains an unsafe path")
                total += info.st_size
                entries.append((item, relative.as_posix()))
                if len(entries) > max_files or total > max_bytes:
                    raise RuntimeError("Flutter output exceeds artifact limits")
        if not entries:
            raise RuntimeError("Flutter output directory is empty")
    else:
        raise RuntimeError("Flutter output is not a regular file or directory")

    try:
        with zipfile.ZipFile(archive, "x", zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
            for item, arcname in entries:
                bundle.write(item, arcname=arcname)
        if not 1 <= archive.stat().st_size <= max_bytes:
            raise RuntimeError("Compressed artifact is outside allowed bounds")
        return archive
    except Exception:
        archive.unlink(missing_ok=True)
        raise


class RunnerAgent:
    def __init__(self, client, worker_id, capabilities, lease_seconds=120,
                 command_timeout=3600, trusted_repositories=()):
        self.client = client
        self.worker_id = worker_id
        self.capabilities = frozenset(capabilities)
        self.lease_seconds = lease_seconds
        self.command_timeout = command_timeout
        self.trusted_repositories = frozenset(trusted_repositories)

    def execute(self, job):
        job_id = job["id"]
        GatewayClient._validate_job_id(job_id)
        target = job["target"]
        if target not in self.client_targets:
            raise ValueError("unsupported target")
        repository = job["repository"]
        commit = job["commit_sha"]
        if not isinstance(repository, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository
        ):
            raise ValueError("invalid GitHub repository")
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError("invalid immutable commit SHA")

        required_os = {
            "build_linux": "linux", "build_windows": "windows",
            "build_macos": "macos", "build_ios": "macos",
        }.get(target)
        if required_os and host_os() != required_os:
            raise RuntimeError("Job target does not match this Runner host")
        if repository not in self.trusted_repositories:
            raise RuntimeError("repository is not in the Runner trusted-repository allowlist")
        required_capabilities = {
            "test": {"flutter"},
            "build": {"android"},
            "package": {"android"},
            "build_android": {"android"},
            "build_web": {"web"},
            "build_linux": {"linux"},
            "build_windows": {"windows"},
            "build_macos": {"macos"},
            "build_ios": {"macos", "ios"},
        }[target]
        if not required_capabilities.issubset(self.capabilities):
            raise RuntimeError("Runner does not advertise the required build capabilities")

        self.client.log(job_id, "Runner accepted pinned job " + job_id, "system")
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="dcp-job-") as temp:
            workspace = Path(temp) / "workspace"
            remote = "https://github.com/" + repository + ".git"
            self._run(["git", "clone", "--no-checkout", "--depth", "1", remote, str(workspace)], Path(temp), job_id)
            self._run(["git", "-C", str(workspace), "fetch", "--depth", "1", "origin", commit], Path(temp), job_id)
            self._run(["git", "-C", str(workspace), "checkout", "--detach", commit], Path(temp), job_id)
            actual = subprocess.check_output(
                ["git", "-C", str(workspace), "rev-parse", "HEAD"],
                text=True, encoding="utf-8", errors="replace", timeout=15,
                env=FlutterBuildExecutor._execution_environment(workspace),
                shell=False,
            ).strip()
            if actual != commit:
                raise RuntimeError("Checked-out commit SHA does not match requested immutable SHA")
            self._run(["flutter", "pub", "get"], workspace, job_id)
            self._run(build_command(target), workspace, job_id)
            heartbeat = self.client.heartbeat(job_id, self.lease_seconds)
            if heartbeat.get("state") == "cancel_requested":
                raise JobCancelled("Job cancellation was requested")
            artifact_path = package_output(workspace, target)
            artifact = self.client.upload(job_id, artifact_path) if artifact_path else None
            result = {
                "repository": repository, "commit_sha": actual, "target": target,
                "duration_seconds": round(time.monotonic() - started, 2),
                "artifact": artifact,
            }
            try:
                self.client.finish(job_id, "succeeded", result)
            except GatewayError:
                heartbeat = self.client.heartbeat(job_id, self.lease_seconds)
                if heartbeat.get("state") == "cancel_requested":
                    raise JobCancelled("Job cancellation was requested")
                raise
            return result

    @property
    def client_targets(self):
        return {
            "test", "build", "package", "build_android", "build_web",
            "build_linux", "build_windows", "build_macos", "build_ios",
        }

    def _run(self, command, cwd, job_id):
        self.client.log(job_id, "Executing: " + " ".join(command), "system")
        env = FlutterBuildExecutor._execution_environment(Path(cwd))
        process_command = FlutterBuildExecutor._process_command(tuple(command))
        process = subprocess.Popen(
            process_command, cwd=str(cwd), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", shell=False,
            bufsize=1, close_fds=True,
            start_new_session=(os.name != "nt"),
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0,
        )
        output_queue = queue.Queue(maxsize=256)

        def collect_output():
            try:
                for output_line in process.stdout:
                    output_queue.put(output_line)
            finally:
                output_queue.put(None)

        reader = threading.Thread(target=collect_output, daemon=True)
        reader.start()
        deadline = time.monotonic() + self.command_timeout
        last_heartbeat = time.monotonic()
        lines = []
        buffered_chars = 0
        total_output_bytes = 0
        stream_closed = False
        try:
            while process.poll() is None or not stream_closed:
                if time.monotonic() >= deadline:
                    FlutterBuildExecutor._terminate_tree(process)
                    raise TimeoutError("Runner command exceeded configured timeout")
                try:
                    line = output_queue.get(timeout=1)
                    if line is None:
                        stream_closed = True
                    else:
                        total_output_bytes += len(line.encode("utf-8", errors="replace"))
                        if total_output_bytes > 5 * 1024 * 1024:
                            FlutterBuildExecutor._terminate_tree(process)
                            raise RuntimeError("Runner command output exceeded its 5 MiB limit")
                        lines.append(line)
                        buffered_chars += len(line)
                        if buffered_chars >= 7000:
                            self.client.log(job_id, "".join(lines)[-7500:])
                            lines.clear()
                            buffered_chars = 0
                except queue.Empty:
                    pass
                if time.monotonic() - last_heartbeat >= max(5, self.lease_seconds // 3):
                    heartbeat = self.client.heartbeat(job_id, self.lease_seconds)
                    last_heartbeat = time.monotonic()
                    if heartbeat.get("state") == "cancel_requested":
                        FlutterBuildExecutor._terminate_tree(process)
                        raise JobCancelled("Job cancellation was requested")
            if lines:
                self.client.log(job_id, "".join(lines)[-7500:])
            reader.join(timeout=2)
            if process.returncode:
                raise RuntimeError("Runner command failed with exit code %s" % process.returncode)
        finally:
            if process.poll() is None:
                FlutterBuildExecutor._terminate_tree(process)
            reader.join(timeout=2)
            if process.stdout and not process.stdout.closed:
                process.stdout.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="DCP local Runner Agent")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--once", action="store_true", help="claim and process at most one job")
    modes.add_argument(
        "--enroll-only", action="store_true",
        help="register this host as offline; never ping, claim, checkout, or execute jobs",
    )
    args = parser.parse_args(argv)
    base_url = os.environ.get("DCP_GATEWAY_URL", "").strip()
    token = os.environ.get("DCP_RUNNER_TOKEN", "")
    worker = os.environ.get("DCP_RUNNER_ID", "").strip()
    configured_caps = os.environ.get("DCP_RUNNER_CAPABILITIES", "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", worker):
        parser.error("DCP_RUNNER_ID is invalid")
    if len(token) < 32:
        parser.error("DCP_RUNNER_TOKEN must contain at least 32 characters")

    report = collect_preflight()
    current_host = host_os()
    if report.get("host_os") != current_host:
        parser.error("Runner preflight host OS does not match this machine")
    configured = (
        [part.strip() for part in configured_caps.split(",") if part.strip()]
        if configured_caps else None
    )
    try:
        caps = resolve_capabilities(report, configured)
        client = GatewayClient(base_url, token)
    except ValueError as exc:
        parser.error(str(exc))

    if args.enroll_only:
        result = client.enroll(current_host, caps)
        runner = result.get("runner", {}) if isinstance(result, dict) else {}
        print(json.dumps({
            "enrolled": True,
            "worker_id": runner.get("worker_id", worker),
            "host_os": runner.get("host_os", current_host),
            "capabilities": runner.get("capabilities", caps),
            "state": runner.get("state", "offline"),
            "execution_enabled": False,
        }, sort_keys=True))
        return 0

    if os.environ.get("DCP_RUNNER_EXECUTION_ENABLED", "").lower() != "true":
        parser.error("Execution is disabled. Use --enroll-only to register without executing jobs.")
    try:
        raw_repositories = json.loads(os.environ.get("DCP_RUNNER_TRUSTED_REPOSITORIES", "[]"))
    except (TypeError, ValueError):
        parser.error("DCP_RUNNER_TRUSTED_REPOSITORIES must be a JSON string array")
    if (
        not isinstance(raw_repositories, list)
        or not raw_repositories
        or any(
            not isinstance(item, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", item)
            for item in raw_repositories
        )
        or len(raw_repositories) != len(set(raw_repositories))
    ):
        parser.error("DCP_RUNNER_TRUSTED_REPOSITORIES must contain unique owner/repository names")

    try:
        client.register(current_host, caps)
    except GatewayError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    agent = RunnerAgent(
        client, worker, caps, trusted_repositories=frozenset(raw_repositories)
    )
    while True:
        try:
            client.ping()
            job = client.claim(120)
            job_failed = False
            if job:
                try:
                    agent.execute(job)
                except JobCancelled:
                    try:
                        client.finish(job["id"], "cancelled", {"message": "Cancellation acknowledged"})
                    except Exception:
                        pass
                except Exception as exc:
                    job_failed = True
                    try:
                        client.log(job["id"], "Execution failed safely: " + type(exc).__name__, "stderr")
                        client.finish(
                            job["id"], "failed", {"error": type(exc).__name__},
                            "RUNNER_EXECUTION_FAILED",
                        )
                    except Exception:
                        pass
            if args.once:
                return 1 if job_failed else 0
        except GatewayError as exc:
            print(str(exc), file=sys.stderr)
            if args.once:
                return 2
        if args.once:
            return 0
        time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
