"""Local Runner end-to-end tests: authenticated claim, checkout, Flutter process, finish."""
import os
import tempfile
import threading
import unittest
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

from tools.cloud_gateway.job_control import JobStore
from tools.cloud_gateway.artifacts import ArtifactStore
from tools.cloud_gateway.runner_registry import RunnerRegistry
from tools.cloud_gateway.server import make_handler
from tools.local_runner_agent.client import GatewayClient, RunnerAgentConfig
from tools.local_runner_agent.execution import FlutterBuildExecutor
from tools.local_runner_agent.pipeline import RunnerPipeline
from tools.local_runner_agent.workspace import WorkspaceManager


TOKEN = "runner-pipeline-e2e-token-which-is-long-enough"


class _Service:
    def __init__(self, jobs, artifacts=None, registry=None):
        self.job_store = jobs
        self.artifact_store = artifacts
        self.runner_registry = registry


class _FixtureCheckout:
    def __init__(self, manager, cancel_job=None):
        self.manager = manager
        self.cancel_job = cancel_job

    def checkout(self, job_id, worker_id, repository, commit_sha):
        source = self.manager.get(job_id, worker_id) / "source"
        source.mkdir()
        (source / "pubspec.yaml").write_text("name: fixture_app\n")
        (source / "lib").mkdir()
        (source / "lib" / "main.dart").write_text("void main() {}\n")
        if self.cancel_job:
            self.cancel_job(job_id)
        return source


class RunnerPipelineEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.jobs = JobStore(str(self.root / "jobs.sqlite3"))
        self.artifacts = ArtifactStore(self.root / "artifacts")
        self.registry = RunnerRegistry(self.root / "runners.sqlite3")
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(_Service(self.jobs, self.artifacts, self.registry), "internal-gateway-token", runner_tokens={
                "runner-e2e": TOKEN,
            }),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        config = RunnerAgentConfig(
            gateway_url=f"http://127.0.0.1:{self.server.server_port}",
            worker_id="runner-e2e", token=TOKEN,
        )
        self.client = GatewayClient(config)
        self.manager = WorkspaceManager(self.root / "workspaces")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def _fake_flutter(self, script):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        executable = bin_dir / "flutter"
        executable.write_text(script)
        executable.chmod(0o700)
        return str(bin_dir) + os.pathsep + os.environ.get("PATH", "")

    @unittest.skipIf(os.name == "nt", "POSIX fixture executable used for deterministic process tests")
    def test_job_runs_from_claim_through_checkout_flutter_and_terminal_state(self):
        job, created = self.jobs.create({
            "repository": "owner/mobile-app",
            "commit_sha": "a" * 40,
            "target": "test",
        }, "runner-pipeline-success-001")
        self.assertTrue(created)
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = self._fake_flutter(
            "#!/bin/sh\nprintf 'fixture-flutter-build-ok\n'\nexit 0\n"
        )
        logs = []
        try:
            executor = FlutterBuildExecutor(
                self.manager, enabled=True, timeout_seconds=10,
                log=lambda stream, message: logs.append((stream, message)),
            )
            pipeline = RunnerPipeline(
                self.client, self.manager, _FixtureCheckout(self.manager), executor,
                trusted_repositories={"owner/mobile-app"},
                capabilities={"flutter", "linux", "android"},
            )
            result = pipeline.run_once()
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual(result["job"]["state"], "succeeded")
        self.assertTrue(any("fixture-flutter-build-ok" in row["message"] for row in self.jobs.logs(job["id"])))
        self.assertFalse((self.root / "workspaces" / job["id"]).exists())
        events = self.jobs.events(job["id"])
        self.assertIn("running", [event["event"] for event in events])
        self.assertIn("succeeded", [event["event"] for event in events])
        self.assertTrue(any(row["message"] == "Workspace cleaned" for row in self.jobs.logs(job["id"])))

    @unittest.skipIf(os.name == "nt", "POSIX fixture executable used for deterministic process tests")
    def test_cancel_requested_during_build_stops_process_and_finishes_cancelled(self):
        job, _ = self.jobs.create({
            "repository": "owner/mobile-app",
            "commit_sha": "b" * 40,
            "target": "test",
        }, "runner-pipeline-cancel-001")
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = self._fake_flutter("#!/bin/sh\nsleep 5\n")
        try:
            executor = FlutterBuildExecutor(
                self.manager, enabled=True, timeout_seconds=10,
            )
            checkout = _FixtureCheckout(self.manager, cancel_job=lambda job_id: self.jobs.cancel(job_id))
            pipeline = RunnerPipeline(self.client, self.manager, checkout, executor,
                                      trusted_repositories={"owner/mobile-app"})
            result = pipeline.run_once()
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(result["outcome"], "cancelled")
        self.assertEqual(result["job"]["state"], "cancelled")
        self.assertFalse((self.root / "workspaces" / job["id"]).exists())


    @unittest.skipIf(os.name == "nt", "POSIX fixture executable used for deterministic process tests")
    def test_flutter_build_artifact_is_uploaded_hashed_and_available_after_job_finishes(self):
        job, _ = self.jobs.create({
            "repository": "owner/mobile-app",
            "commit_sha": "c" * 40,
            "target": "build_android",
        }, "runner-pipeline-artifact-001")
        old_path = os.environ.get("PATH", "")
        script = (
            "#!/bin/sh\n"
            "mkdir -p build/app/outputs/flutter-apk\n"
            "printf 'fixture-apk-bytes' > build/app/outputs/flutter-apk/app-release.apk\n"
            "exit 0\n"
        )
        os.environ["PATH"] = self._fake_flutter(script)
        try:
            executor = FlutterBuildExecutor(self.manager, enabled=True, timeout_seconds=10)
            pipeline = RunnerPipeline(
                self.client, self.manager, _FixtureCheckout(self.manager), executor,
                trusted_repositories={"owner/mobile-app"},
                capabilities={"flutter", "linux", "android"},
            )
            result = pipeline.run_once()
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(result["outcome"], "succeeded")
        artifact = result["result"]["artifact"]
        self.assertEqual(artifact["name"], "app-release.apk")
        metadata, handle = self.artifacts.open(artifact["id"])
        with handle:
            self.assertEqual(handle.read(), b"fixture-apk-bytes")
        self.assertEqual(metadata["sha256"], artifact["sha256"])
        self.assertFalse((self.root / "workspaces" / job["id"]).exists())


@unittest.skipUnless(os.name == "nt", "Requires the real Windows cmd.exe batch-file launcher")
class WindowsRunnerPipelineAcceptanceTests(RunnerPipelineEndToEndTests):
    def test_windows_cmd_flutter_build_runs_through_gateway_and_artifact_pipeline(self):
        job, created = self.jobs.create({
            "repository": "owner/mobile-app",
            "commit_sha": "d" * 40,
            "target": "build_android",
        }, "runner-windows-full-e2e-001")
        self.assertTrue(created)

        bin_dir = self.root / "Flutter SDK" / "bin"
        bin_dir.mkdir(parents=True)
        flutter_cmd = bin_dir / "flutter.cmd"
        flutter_cmd.write_text(
            "@echo off\r\n"
            "if /I \"%1\"==\"build\" if /I \"%2\"==\"apk\" (\r\n"
            "  if not exist \"build\\app\\outputs\\flutter-apk\" mkdir \"build\\app\\outputs\\flutter-apk\"\r\n"
            "  > \"build\\app\\outputs\\flutter-apk\\app-release.apk\" echo dcp-fixture-apk\r\n"
            "  exit /b 0\r\n"
            ")\r\n"
            "exit /b 91\r\n",
            encoding="utf-8",
        )

        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(bin_dir) + os.pathsep + old_path
        try:
            executor = FlutterBuildExecutor(
                self.manager, enabled=True, timeout_seconds=30,
                max_output_bytes=1024 * 1024,
            )
            pipeline = RunnerPipeline(
                self.client, self.manager, _FixtureCheckout(self.manager), executor,
                trusted_repositories={"owner/mobile-app"},
                worker_os="windows",
                capabilities={"flutter", "windows", "android"},
            )
            result = pipeline.run_once()
        finally:
            os.environ["PATH"] = old_path

        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual(result["job"]["id"], job["id"])
        self.assertEqual(result["job"]["state"], "succeeded")
        artifact = result["result"]["artifact"]
        self.assertEqual(artifact["name"], "app-release.apk")
        metadata, handle = self.artifacts.open(artifact["id"])
        with handle:
            self.assertEqual(handle.read().strip(), b"dcp-fixture-apk")
        self.assertEqual(metadata["sha256"], artifact["sha256"])
        self.assertFalse((self.root / "workspaces" / job["id"]).exists())
        self.assertTrue(any(
            row["message"] == "Workspace cleaned" for row in self.jobs.logs(job["id"])
        ))

if __name__ == "__main__":
    unittest.main()
