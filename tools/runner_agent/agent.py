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
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path
from urllib.parse import quote

from .preflight import collect_preflight


class GatewayError(RuntimeError):
    pass


class JobCancelled(RuntimeError):
    pass


class GatewayClient:
    def __init__(self, base_url: str, token: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def request(self, path, payload=None, data=None, headers=None):
        body = data
        request_headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        request_headers.update(headers or {})
        req = urllib.request.Request(self.base_url + path, data=body, headers=request_headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                raw = response.read()
                return json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", "replace")
            raise GatewayError("Gateway returned HTTP %s: %s" % (exc.code, detail)) from None
        except (urllib.error.URLError, TimeoutError) as exc:
            raise GatewayError("Gateway connection failed: %s" % exc) from None

    def register(self, host_os, capabilities):
        return self.request("/v1/runner/register", {"host_os": host_os, "capabilities": capabilities})

    def enroll(self, host_os, capabilities):
        return self.request("/v1/runner/enroll", {"host_os": host_os, "capabilities": capabilities})

    def ping(self):
        return self.request("/v1/runner/ping", {})

    def claim(self, lease_seconds):
        return self.request("/v1/runner/claim", {"lease_seconds": lease_seconds}).get("job")

    def heartbeat(self, job_id, lease_seconds):
        return self.request("/v1/runner/" + job_id + "/heartbeat", {"lease_seconds": lease_seconds})

    def log(self, job_id, message, stream="stdout"):
        return self.request("/v1/runner/" + job_id + "/logs", {"message": message[:8000], "stream": stream})

    def finish(self, job_id, outcome, result=None, error_code=None):
        return self.request("/v1/runner/" + job_id + "/finish", {
            "outcome": outcome, "result": result, "error_code": error_code,
        })

    def upload(self, job_id, path: Path):
        data = path.read_bytes()
        return self.request(
            "/v1/runner/" + job_id + "/artifacts", data=data,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(data)),
                "X-DCP-Artifact-Name": path.name,
            },
        ).get("artifact")


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
        "package": ["flutter", "build", "apk", "--release"],
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


def package_output(workspace: Path, target: str) -> Path | None:
    if target == "test":
        return None
    candidates = {
        "build": [workspace / "build/app/outputs/flutter-apk/app-release.apk"],
        "package": [workspace / "build/app/outputs/flutter-apk/app-release.apk"],
        "build_android": [workspace / "build/app/outputs/flutter-apk/app-release.apk"],
        "build_web": [workspace / "build/web"],
        "build_linux": [workspace / "build/linux/x64/release/bundle"],
        "build_windows": [workspace / "build/windows/x64/runner/Release"],
        "build_macos": [workspace / "build/macos/Build/Products/Release"],
        "build_ios": [workspace / "build/ios/iphoneos/Runner.app"],
    }.get(target, [])
    output = next((item for item in candidates if item.exists()), None)
    if output is None:
        raise RuntimeError("Expected Flutter output was not produced for " + target)
    archive = workspace / ("dcp-" + target + ".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        if output.is_dir():
            for item in output.rglob("*"):
                if item.is_file():
                    bundle.write(item, item.relative_to(output.parent))
        else:
            bundle.write(output, output.name)
    return archive


class RunnerAgent:
    def __init__(self, client, worker_id, capabilities, lease_seconds=120, command_timeout=3600):
        self.client = client
        self.worker_id = worker_id
        self.capabilities = sorted(set(capabilities))
        self.lease_seconds = lease_seconds
        self.command_timeout = command_timeout

    def execute(self, job):
        job_id = job["id"]
        target = job["target"]
        if target not in self.client_targets:
            raise ValueError("unsupported target")
        required_os = {
            "build_linux": "linux", "build_windows": "windows",
            "build_macos": "macos", "build_ios": "macos",
        }.get(target)
        if required_os and host_os() != required_os:
            raise RuntimeError("Job target does not match this Runner host")
        self.client.log(job_id, "Runner accepted pinned job " + job_id, "system")
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="dcp-job-") as temp:
            workspace = Path(temp) / "workspace"
            repository = job["repository"]
            commit = job["commit_sha"]
            remote = "https://github.com/" + repository + ".git"
            self._run(["git", "clone", "--no-checkout", "--depth", "1", remote, str(workspace)], Path(temp), job_id)
            self._run(["git", "-C", str(workspace), "fetch", "--depth", "1", "origin", commit], Path(temp), job_id)
            self._run(["git", "-C", str(workspace), "checkout", "--detach", commit], Path(temp), job_id)
            actual = subprocess.check_output(
                ["git", "-C", str(workspace), "rev-parse", "HEAD"], text=True, timeout=15
            ).strip()
            if actual != commit:
                raise RuntimeError("Checked-out commit SHA does not match requested immutable SHA")
            self._run(["flutter", "pub", "get"], workspace, job_id)
            self._run(build_command(target), workspace, job_id)
            # A cancellation can arrive after the final build command has exited.
            # Re-check the lease before publishing an artifact or reporting success.
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
                # Close the race where cancellation lands between the last
                # heartbeat and finish(succeeded). The Gateway correctly rejects
                # success for cancel_requested jobs; acknowledge cancellation.
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
        process = subprocess.Popen(
            command, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace", shell=False, bufsize=1,
        )
        output_queue = queue.Queue()
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
        stream_closed = False
        try:
            while process.poll() is None or not stream_closed:
                if time.monotonic() >= deadline:
                    process.kill()
                    raise TimeoutError("Runner command exceeded configured timeout")
                try:
                    line = output_queue.get(timeout=1)
                    if line is None:
                        stream_closed = True
                    else:
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
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                        raise JobCancelled("Job cancellation was requested")
            if lines:
                self.client.log(job_id, "".join(lines)[-7500:])
            reader.join(timeout=2)
            if process.returncode:
                raise RuntimeError("Command failed with exit code %s: %s" % (process.returncode, command[0]))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            reader.join(timeout=2)


def main(argv=None):
    parser = argparse.ArgumentParser(description="DCP local Runner Agent")
    parser.add_argument("--once", action="store_true", help="claim and process at most one job")
    parser.add_argument(
        "--enroll-only", action="store_true",
        help="register this host as offline; never ping, claim, checkout, or execute jobs",
    )
    args = parser.parse_args(argv)
    base_url = os.environ.get("DCP_GATEWAY_URL", "").strip()
    token = os.environ.get("DCP_RUNNER_TOKEN", "")
    worker = os.environ.get("DCP_RUNNER_ID", "").strip()
    configured_caps = os.environ.get("DCP_RUNNER_CAPABILITIES", "").strip()
    if not base_url.startswith("https://") and not base_url.startswith("http://127.0.0.1"):
        parser.error("DCP_GATEWAY_URL must use HTTPS (HTTP is allowed only for loopback)")
    if len(token) < 32 or not worker:
        parser.error("Set DCP_RUNNER_ID and a DCP_RUNNER_TOKEN of at least 32 characters")

    # Both enrollment and execution use the same conservative, local-only probe.
    # Capabilities explicitly configured by an operator may only reduce the detected set.
    report = collect_preflight()
    if not report["minimum_agent_prerequisites_met"]:
        parser.error("Runner host preflight failed: Git and Flutter are required")
    current_host = host_os()
    if report["host_os"] != current_host or current_host not in report["detected_capabilities"]:
        parser.error("Runner host preflight did not verify the complete host platform toolchain")
    detected = set(report["detected_capabilities"])
    if configured_caps:
        caps = sorted({part.strip() for part in configured_caps.split(",") if part.strip()})
        if not caps or not set(caps).issubset(detected):
            parser.error("DCP_RUNNER_CAPABILITIES must be a non-empty subset of preflight-detected capabilities")
    else:
        caps = sorted(detected)
    # The registry requires the physical host OS in the capability set. This is
    # safe because the preflight check above verified that platform toolchain.
    caps = sorted(set(caps) | {current_host})

    client = GatewayClient(base_url, token)
    if args.enroll_only:
        # This endpoint persists an offline registration. It cannot receive work.
        result = client.enroll(current_host, caps)
        runner = result.get("runner", {})
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
    client.register(current_host, caps)
    agent = RunnerAgent(client, worker, caps)
    while True:
        client.ping()
        try:
            job = client.claim(120)
            if job:
                try:
                    agent.execute(job)
                except JobCancelled:
                    try:
                        client.finish(job["id"], "cancelled", {"message": "Cancellation acknowledged"})
                    except Exception:
                        pass
                except Exception as exc:
                    try:
                        client.log(job["id"], "Execution failed: " + str(exc), "stderr")
                        client.finish(job["id"], "failed", {"message": str(exc)}, "RUNNER_EXECUTION_FAILED")
                    except Exception:
                        pass
        except GatewayError as exc:
            print(str(exc), file=sys.stderr)
            if args.once:
                return 2
        if args.once:
            return 0
        time.sleep(5)


if __name__ == "__main__":
    raise SystemExit(main())
