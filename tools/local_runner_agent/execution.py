"""Policy-gated Flutter build execution for DCP local Runner Agents.

Commands are selected from a fixed allowlist. No shell, user-supplied command,
or user-supplied environment is accepted. Execution is disabled by default.
"""
from __future__ import annotations

import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .workspace import WorkspaceError, WorkspaceManager


class ExecutionError(RuntimeError):
    """A build was rejected or could not be safely executed."""


@dataclass(frozen=True)
class BuildResult:
    outcome: str
    command: tuple[str, ...]
    return_code: int | None
    duration_seconds: float
    output_bytes: int
    error_code: str | None = None


_COMMANDS = {
    "test": ("test", "--no-pub"),
    "build": ("build", "apk", "--release", "--no-pub"),
    "build_android": ("build", "apk", "--release", "--no-pub"),
    "package": ("build", "appbundle", "--release", "--no-pub"),
    "build_web": ("build", "web", "--release", "--no-pub"),
    "build_windows": ("build", "windows", "--release", "--no-pub"),
    "build_linux": ("build", "linux", "--release", "--no-pub"),
    "build_macos": ("build", "macos", "--release", "--no-pub"),
    "build_ios": ("build", "ios", "--release", "--no-codesign", "--no-pub"),
}


class FlutterBuildExecutor:
    """Run only fixed Flutter targets inside an already prepared workspace."""

    def __init__(
        self,
        workspace_manager: WorkspaceManager,
        *,
        enabled: bool = False,
        timeout_seconds: int = 1800,
        max_output_bytes: int = 5 * 1024 * 1024,
        log: Callable[[str, str], None] | None = None,
        flutter_executable: str = "flutter",
    ):
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be boolean")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 7200:
            raise ValueError("timeout_seconds must be between 1 and 7200")
        if isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int) or not 1024 <= max_output_bytes <= 50 * 1024 * 1024:
            raise ValueError("max_output_bytes must be between 1 KiB and 50 MiB")
        if flutter_executable != "flutter":
            raise ValueError("only the Flutter executable is permitted")
        self.workspaces = workspace_manager
        self.enabled = enabled
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.log = log or (lambda stream, message: None)
        self.flutter_executable = flutter_executable

    @staticmethod
    def command_for(target: str) -> tuple[str, ...]:
        if target not in _COMMANDS:
            raise ExecutionError("unsupported Flutter build target")
        return ("flutter", *_COMMANDS[target])

    @staticmethod
    def _terminate_tree(process: subprocess.Popen) -> None:
        if os.name == "nt":
            taskkill = shutil.which("taskkill")
            if taskkill and process.poll() is None:
                subprocess.run(
                    [taskkill, "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=10, check=False,
                )
            elif process.poll() is None:
                process.kill()
        else:
            try:
                # Kill the process group even if its leader exited but a child still holds pipes.
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    def run(
        self,
        job_id: str,
        worker_id: str,
        target: str,
        *,
        cancel_requested: Callable[[], bool] | None = None,
    ) -> BuildResult:
        if not self.enabled:
            raise ExecutionError("build execution is disabled by runner policy")
        command = self.command_for(target)
        workspace = self.workspaces.get(job_id, worker_id)
        project_root = workspace / "source" if (workspace / "source").is_dir() else workspace
        if target in ("build_macos", "build_ios") and sys.platform != "darwin":
            raise ExecutionError("macOS and iOS builds require a macOS Runner host")
        if target == "build_windows" and sys.platform != "win32":
            raise ExecutionError("Windows builds require a Windows Runner host")
        if target == "build_linux" and not sys.platform.startswith("linux"):
            raise ExecutionError("Linux builds require a Linux Runner host")
        if not (project_root / "pubspec.yaml").is_file():
            raise ExecutionError("Flutter project manifest is missing")
        if shutil.which(self.flutter_executable) is None:
            raise ExecutionError("Flutter SDK executable is not available on PATH")
        self.workspaces.check_quota(job_id, worker_id)

        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(workspace / ".runner-home"),
            "USERPROFILE": str(workspace / ".runner-home"),
            "PUB_CACHE": str(workspace / ".pub-cache"),
            "CI": "true",
            "FLUTTER_SUPPRESS_ANALYTICS": "true",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C.UTF-8",
        }
        Path(env["HOME"]).mkdir(mode=0o700, exist_ok=True)
        Path(env["PUB_CACHE"]).mkdir(mode=0o700, exist_ok=True)
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
        started = time.monotonic()
        process = subprocess.Popen(
            list(command), cwd=str(project_root), env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, close_fds=True, start_new_session=(os.name != "nt"),
            creationflags=creationflags,
        )
        messages: queue.Queue = queue.Queue()

        def pump(pipe, stream):
            try:
                while True:
                    chunk = pipe.read1(4096) if hasattr(pipe, "read1") else pipe.read(4096)
                    if not chunk:
                        break
                    messages.put((stream, chunk))
            finally:
                messages.put((stream, None))

        threads = [
            threading.Thread(target=pump, args=(process.stdout, "stdout"), daemon=True),
            threading.Thread(target=pump, args=(process.stderr, "stderr"), daemon=True),
        ]
        for thread in threads:
            thread.start()

        finished_streams = set()
        output_bytes = 0
        outcome = "succeeded"
        error_code = None
        deadline = started + self.timeout_seconds
        try:
            while len(finished_streams) < 2 or process.poll() is None:
                now = time.monotonic()
                if now >= deadline:
                    outcome, error_code = "failed", "BUILD_TIMEOUT"
                    self._terminate_tree(process)
                elif cancel_requested and cancel_requested():
                    outcome, error_code = "cancelled", None
                    self._terminate_tree(process)
                try:
                    stream, chunk = messages.get(timeout=0.1)
                except queue.Empty:
                    if process.poll() is not None and len(finished_streams) == 2:
                        break
                    continue
                if chunk is None:
                    finished_streams.add(stream)
                    continue
                output_bytes += len(chunk)
                if output_bytes > self.max_output_bytes:
                    outcome, error_code = "failed", "OUTPUT_LIMIT_EXCEEDED"
                    self._terminate_tree(process)
                    continue
                text = chunk.decode("utf-8", errors="replace")
                for offset in range(0, len(text), 7000):
                    self.log(stream, text[offset:offset + 7000])
                if process.poll() is not None and len(finished_streams) == 2:
                    break
        finally:
            if process.poll() is None:
                self._terminate_tree(process)
            for thread in threads:
                thread.join(timeout=2)
            for pipe in (process.stdout, process.stderr):
                if pipe and not pipe.closed:
                    pipe.close()

        return_code = process.returncode
        if outcome == "succeeded" and return_code != 0:
            outcome, error_code = "failed", "BUILD_FAILED"
        if outcome == "succeeded":
            self.workspaces.check_quota(job_id, worker_id)
        return BuildResult(
            outcome=outcome, command=command, return_code=return_code,
            duration_seconds=round(time.monotonic() - started, 3),
            output_bytes=output_bytes, error_code=error_code,
        )
