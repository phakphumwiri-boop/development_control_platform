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
from pathlib import Path, PureWindowsPath
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
    def _process_command(command: tuple[str, ...], *, windows: bool | None = None,
                         executable: str | None = None) -> list[str] | str:
        """Resolve Flutter to an absolute executable and safely invoke Windows batch shims.

        cmd.exe expands percent variables even inside quotes. The executable path
        is therefore always quoted, percent/control characters are rejected, and
        delayed expansion is disabled. Arguments come only from the fixed target
        allowlist; shell=True is never used.
        """
        is_windows = os.name == "nt" if windows is None else windows
        resolved = executable or shutil.which(command[0])
        if not resolved:
            return list(command)
        if not isinstance(resolved, str) or any(char in resolved for char in ('"', "%", "\r", "\n", "\x00")):
            raise ExecutionError("Flutter executable path contains unsafe command characters")
        if not is_windows:
            return [resolved, *command[1:]]

        executable_path = PureWindowsPath(resolved)
        if not executable_path.is_absolute() or not executable_path.drive.startswith(tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")):
            raise ExecutionError("Flutter executable must resolve to an absolute local Windows path")
        if executable_path.drive.startswith("\\\\"):
            raise ExecutionError("Flutter executable cannot be loaded from a network share")
        if executable_path.suffix.lower() not in (".bat", ".cmd"):
            return [resolved, *command[1:]]

        command_processor = os.environ.get("COMSPEC") or str(
            PureWindowsPath(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"
        )
        if (
            not isinstance(command_processor, str)
            or any(char in command_processor for char in ('"', "%", "\r", "\n", "\x00"))
        ):
            raise ExecutionError("Windows command processor path is unsafe")
        processor_path = PureWindowsPath(command_processor)
        if (
            not processor_path.is_absolute()
            or processor_path.drive.startswith("\\\\")
            or processor_path.name.lower() != "cmd.exe"
        ):
            raise ExecutionError("Windows command processor must be the trusted cmd.exe")

        arguments = subprocess.list2cmdline(list(command[1:]))
        command_line = f'"{resolved}"' + (f" {arguments}" if arguments else "")
        return f'"{command_processor}" /d /v:off /s /c "{command_line}"'

    @staticmethod
    def _execution_environment(workspace: Path, *, environ=None,
                               windows: bool | None = None) -> dict[str, str]:
        """Build an isolated environment while preserving required host toolchain paths.

        Never forward arbitrary environment variables (which may contain tokens).
        Windows Flutter/Android builds need OS variables and SDK/Visual Studio paths;
        user-writable caches and temporary files remain inside the job workspace.
        """
        inherited = os.environ if environ is None else environ
        is_windows = os.name == "nt" if windows is None else windows
        home = workspace / ".runner-home"
        pub_cache = workspace / ".pub-cache"
        temp = workspace / ".tmp"
        gradle_home = workspace / ".gradle"
        app_data = workspace / ".appdata"
        local_app_data = workspace / ".localappdata"
        for directory in (home, pub_cache, temp, gradle_home, app_data, local_app_data):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)

        env = {
            "PATH": inherited.get("PATH", ""),
            "HOME": str(home),
            "USERPROFILE": str(home),
            "PUB_CACHE": str(pub_cache),
            "GRADLE_USER_HOME": str(gradle_home),
            "CI": "true",
            "FLUTTER_SUPPRESS_ANALYTICS": "true",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C.UTF-8",
        }
        if is_windows:
            env.update({
                "TEMP": str(temp),
                "TMP": str(temp),
                "APPDATA": str(app_data),
                "LOCALAPPDATA": str(local_app_data),
            })
            host_path_variables = (
                "SystemRoot", "WINDIR", "SystemDrive", "COMSPEC", "PATHEXT",
                "OS", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
                "ANDROID_HOME", "ANDROID_SDK_ROOT", "JAVA_HOME", "FLUTTER_ROOT",
                "VSINSTALLDIR", "VCINSTALLDIR", "VCToolsInstallDir",
                "WindowsSdkDir", "WindowsSDKVersion", "VisualStudioVersion",
                "VSCMD_VER", "VSCMD_ARG_TGT_ARCH", "VSCMD_ARG_HOST_ARCH",
                "INCLUDE", "LIB", "LIBPATH",
            )
            for name in host_path_variables:
                value = inherited.get(name)
                if isinstance(value, str) and value and "\\x00" not in value:
                    env[name] = value

            # Android tooling uses both names across Flutter/Gradle versions.
            # If the host supplies either variable, expose the same SDK through
            # both names while keeping the host SDK path outside isolated app data.
            sdk_path = env.get("ANDROID_SDK_ROOT") or env.get("ANDROID_HOME")
            if sdk_path:
                env["ANDROID_SDK_ROOT"] = sdk_path
                env["ANDROID_HOME"] = sdk_path
            else:
                # Preflight also recognizes the standard per-user Android SDK location.
                # Preserve that SDK explicitly because LOCALAPPDATA is isolated above.
                inherited_local = inherited.get("LOCALAPPDATA")
                if isinstance(inherited_local, str) and inherited_local:
                    default_sdk = Path(inherited_local) / "Android" / "Sdk"
                    if default_sdk.is_dir():
                        env["ANDROID_SDK_ROOT"] = str(default_sdk)
                        env["ANDROID_HOME"] = str(default_sdk)
        else:
            env["TMPDIR"] = str(temp)
        return env

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

    def _run_process(
        self,
        command: tuple[str, ...],
        project_root: Path,
        env: dict[str, str],
        *,
        deadline: float,
        cancel_requested: Callable[[], bool] | None,
        output_bytes: int,
    ) -> tuple[str, str | None, int | None, int]:
        process = subprocess.Popen(
            self._process_command(command), cwd=str(project_root), env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, close_fds=True, start_new_session=(os.name != "nt"),
            creationflags=(
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                if os.name == "nt" else 0
            ),
        )
        messages: queue.Queue = queue.Queue(maxsize=256)

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
        outcome = "succeeded"
        error_code = None
        try:
            while len(finished_streams) < 2 or process.poll() is None:
                now = time.monotonic()
                if outcome == "succeeded" and now >= deadline:
                    outcome, error_code = "failed", "BUILD_TIMEOUT"
                    self._terminate_tree(process)
                elif outcome == "succeeded" and cancel_requested and cancel_requested():
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
                decoded = chunk.decode("utf-8", errors="replace")
                for offset in range(0, len(decoded), 7000):
                    self.log(stream, decoded[offset:offset + 7000])
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
        return outcome, error_code, return_code, output_bytes

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
        lockfile = project_root / "pubspec.lock"
        if lockfile.is_symlink() or not lockfile.is_file():
            raise ExecutionError("Flutter lockfile is missing or unsafe")
        if shutil.which(self.flutter_executable) is None:
            raise ExecutionError("Flutter SDK executable is not available on PATH")
        self.workspaces.check_quota(job_id, worker_id)

        env = self._execution_environment(workspace)
        started = time.monotonic()
        deadline = started + self.timeout_seconds
        output_bytes = 0
        outcome = "succeeded"
        error_code = None
        return_code = 0

        # Resolve dependencies from the committed lockfile before invoking a
        # build/test command. --enforce-lockfile prevents silent dependency drift.
        steps = (
            (("flutter", "pub", "get", "--enforce-lockfile"), "DEPENDENCY_RESOLUTION_FAILED"),
            (command, "BUILD_FAILED"),
        )
        for step_command, failure_code in steps:
            self.log("system", "Executing: " + " ".join(step_command))
            outcome, error_code, return_code, output_bytes = self._run_process(
                step_command, project_root, env, deadline=deadline,
                cancel_requested=cancel_requested, output_bytes=output_bytes,
            )
            if outcome != "succeeded":
                break
            if return_code != 0:
                outcome, error_code = "failed", failure_code
                break
            self.workspaces.check_quota(job_id, worker_id)

        if outcome == "succeeded":
            self.workspaces.check_quota(job_id, worker_id)
        return BuildResult(
            outcome=outcome, command=command, return_code=return_code,
            duration_seconds=round(time.monotonic() - started, 3),
            output_bytes=output_bytes, error_code=error_code,
        )
