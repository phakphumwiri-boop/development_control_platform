"""Tests for the policy-gated Flutter build executor."""
import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from tools.local_runner_agent.workspace import WorkspaceManager
from tools.local_runner_agent.execution import ExecutionError, FlutterBuildExecutor


class FlutterBuildExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.job_id = str(uuid.uuid4())
        self.worker = "runner-test"
        self.manager = WorkspaceManager(self.root / "workspaces")
        self.workspace = self.manager.create(self.job_id, self.worker)
        (self.workspace / "pubspec.yaml").write_text(
            "name: fixture_app\n\nenvironment:\n  sdk: '>=3.0.0 <4.0.0'\n"
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_target_commands_are_fixed_allowlist(self):
        self.assertEqual(FlutterBuildExecutor.command_for("test"),
                         ("flutter", "test", "--no-pub"))
        self.assertEqual(FlutterBuildExecutor.command_for("build_macos"),
                         ("flutter", "build", "macos", "--release", "--no-pub"))
        self.assertEqual(FlutterBuildExecutor.command_for("build_ios"),
                         ("flutter", "build", "ios", "--release", "--no-codesign", "--no-pub"))
        with self.assertRaises(ExecutionError):
            FlutterBuildExecutor.command_for("bash -c whoami")

    def test_windows_flutter_batch_shim_uses_quoted_cmd_wrapper(self):
        command = ("flutter", "build", "apk", "--release", "--no-pub")
        executable = r"C:\Program Files\Flutter SDK\bin\flutter.bat"
        actual = FlutterBuildExecutor._process_command(
            command, windows=True, executable=executable
        )
        self.assertIsInstance(actual, str)
        expected = (
            subprocess.list2cmdline([
                os.environ.get("COMSPEC") or str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe")
            ])
            + " /d /s /c "
            + '"' + subprocess.list2cmdline([executable, *command[1:]]) + '"'
        )
        self.assertEqual(actual, expected)
        self.assertEqual(
            FlutterBuildExecutor._process_command(
                command, windows=True, executable=r"C:\Flutter\bin\flutter.exe"
            ),
            list(command),
        )
        self.assertEqual(
            FlutterBuildExecutor._process_command(command, windows=False, executable=executable),
            list(command),
        )

    def test_execution_is_disabled_by_default(self):
        executor = FlutterBuildExecutor(self.manager)
        with self.assertRaises(ExecutionError):
            executor.run(self.job_id, self.worker, "test")

    @unittest.skipIf(os.name == "nt", "POSIX fixture executable used for deterministic process tests")
    def test_runs_only_fixed_flutter_command_and_collects_logs(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        flutter = bin_dir / "flutter"
        flutter.write_text("#!/bin/sh\nprintf 'flutter-fixture-ok\\n'\nexit 0\n")
        flutter.chmod(0o700)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(bin_dir) + os.pathsep + old_path
        logs = []
        try:
            executor = FlutterBuildExecutor(
                self.manager, enabled=True, timeout_seconds=10,
                log=lambda stream, message: logs.append((stream, message)),
            )
            result = executor.run(self.job_id, self.worker, "test")
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(result.outcome, "succeeded")
        self.assertEqual(result.return_code, 0)
        self.assertEqual(result.command, ("flutter", "test", "--no-pub"))
        self.assertTrue(any("flutter-fixture-ok" in message for _, message in logs))

    @unittest.skipIf(os.name == "nt", "POSIX fixture executable used for deterministic process tests")
    def test_timeout_terminates_process_group(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        flutter = bin_dir / "flutter"
        flutter.write_text("#!/bin/sh\nsleep 5\n")
        flutter.chmod(0o700)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(bin_dir) + os.pathsep + old_path
        try:
            executor = FlutterBuildExecutor(
                self.manager, enabled=True, timeout_seconds=1,
                max_output_bytes=1024,
            )
            result = executor.run(self.job_id, self.worker, "test")
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(result.outcome, "failed")
        self.assertEqual(result.error_code, "BUILD_TIMEOUT")

    def test_requires_project_manifest(self):
        (self.workspace / "pubspec.yaml").unlink()
        executor = FlutterBuildExecutor(self.manager, enabled=True)
        with self.assertRaises(ExecutionError):
            executor.run(self.job_id, self.worker, "test")


@unittest.skipUnless(os.name == "nt", "Requires the real Windows cmd.exe batch-file launcher")
class WindowsFlutterBatchShimAcceptanceTests(FlutterBuildExecutorTests):
    def test_executes_flutter_cmd_shim_from_path_with_spaces(self):
        bin_dir = self.root / "Flutter SDK" / "bin"
        bin_dir.mkdir(parents=True)
        args_file = self.root / "captured Flutter args.txt"
        flutter_cmd = bin_dir / "flutter.cmd"
        flutter_cmd.write_text(
            "@echo off\r\n"
            + "echo %* > \"" + str(args_file) + "\"\r\n"
            + "exit /b 0\r\n",
            encoding="utf-8",
        )
        old_path = os.environ.get("PATH", "")
        with patch.dict(os.environ, {"PATH": str(bin_dir) + os.pathsep + old_path}):
            executor = FlutterBuildExecutor(
                self.manager, enabled=True, timeout_seconds=10,
                max_output_bytes=1024,
            )
            result = executor.run(self.job_id, self.worker, "test")
        self.assertEqual(result.outcome, "succeeded")
        self.assertEqual(result.return_code, 0)
        self.assertEqual(args_file.read_text(encoding="utf-8").strip(), "test --no-pub")


if __name__ == "__main__":
    unittest.main()
