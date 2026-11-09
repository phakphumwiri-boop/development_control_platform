"""Local Runner end-to-end tests: authenticated claim, checkout, Flutter process, finish."""
import os
import tempfile
import threading
import unittest
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

from tools.cloud_gateway.job_control import JobStore
from tools.cloud_gateway.server import make_handler
from tools.local_runner_agent.client import GatewayClient, RunnerAgentConfig
from tools.local_runner_agent.execution import FlutterBuildExecutor
from tools.local_runner_agent.pipeline import RunnerPipeline
from tools.local_runner_agent.workspace import WorkspaceManager


TOKEN = "runner-pipeline-e2e-token-which-is-long-enough"


class _Service:
    def __init__(self, jobs):
        self.job_store = jobs


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
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(_Service(self.jobs), "internal-gateway-token", runner_tokens={
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
            "#!/bin/sh\nprintf 'fixture-flutter-build-ok\\n'\nexit 0\n"
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
            )
            result = pipeline.run_once()
        finally:
            os.environ["PATH"] = old_path
        self.assertEqual(result["outcome"], "succeeded")
        self.assertEqual(result["job"]["state"], "succeeded")
        self.assertTrue(any("fixture-flutter-build-ok" in message for _, message in logs))
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


if __name__ == "__main__":
    unittest.main()
