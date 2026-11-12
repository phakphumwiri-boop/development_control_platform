"""Runner Agent <-> Gateway HTTP contract tests; no repository code is executed."""
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

from tools.cloud_gateway.artifacts import ArtifactStore
from tools.cloud_gateway.job_control import JobStore
from tools.cloud_gateway.runner_registry import RunnerRegistry
from tools.cloud_gateway.server import make_handler
from tools.runner_agent.agent import GatewayClient, GatewayError


class RunnerAgentGatewayE2ETests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.jobs = JobStore(root / "jobs.sqlite3")
        self.registry = RunnerRegistry(root / "runners.sqlite3")
        self.artifacts = ArtifactStore(root / "artifacts", max_artifact_bytes=1024 * 1024)
        self.service = SimpleNamespace(
            job_store=self.jobs,
            runner_registry=self.registry,
            artifact_store=self.artifacts,
            infrastructure_manager=None,
            runner_scheduler=None,
        )
        self.worker_id = "linux-e2e-runner"
        self.runner_token = "runner-e2e-secret-" + ("x" * 40)
        handler = make_handler(
            self.service, "unused-dashboard-token",
            runner_tokens={self.worker_id: self.runner_token},
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = GatewayClient(
            "http://127.0.0.1:%s" % self.server.server_address[1],
            self.runner_token,
        )

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()

    def test_register_claim_heartbeat_logs_artifact_and_finish(self):
        commit = "a" * 40
        job, created = self.jobs.create(
            {"repository": "owner/repo", "commit_sha": commit, "target": "test"},
            "runner-e2e-job-0001",
        )
        self.assertTrue(created)

        registration = self.client.register("linux", ["flutter", "linux"])
        self.assertEqual(registration["runner"]["worker_id"], self.worker_id)
        self.client.ping()

        claimed = self.client.claim(30)
        self.assertEqual(claimed["id"], job["id"])
        self.assertEqual(claimed["state"], "running")
        self.assertEqual(claimed["worker"], self.worker_id)

        heartbeat = self.client.heartbeat(job["id"], 30)
        self.assertEqual(heartbeat["state"], "running")
        self.assertEqual(heartbeat["worker"], self.worker_id)
        self.client.log(job["id"], "Gateway E2E log line", "stdout")
        logs = self.jobs.logs(job["id"])
        self.assertEqual(logs[-1]["message"], "Gateway E2E log line")

        artifact_path = Path(self.temp.name) / "dcp-test-artifact.zip"
        artifact_path.write_bytes(b"safe-test-artifact" * 128)
        uploaded = self.client.upload(job["id"], artifact_path)
        self.assertEqual(uploaded["name"], artifact_path.name)
        self.assertEqual(uploaded["size"], artifact_path.stat().st_size)
        self.assertEqual(len(uploaded["sha256"]), 64)

        finished = self.client.finish(job["id"], "succeeded", {
            "commit_sha": commit,
            "artifact": uploaded,
        })
        self.assertEqual(finished["state"], "succeeded")
        self.assertEqual(self.jobs.get(job["id"])["state"], "succeeded")

    def test_enroll_only_registration_is_offline_and_cannot_claim_jobs(self):
        job, created = self.jobs.create(
            {"repository": "owner/repo", "commit_sha": "b" * 40, "target": "test"},
            "runner-enroll-job-0001",
        )
        self.assertTrue(created)

        registration = self.client.enroll("linux", ["flutter", "linux"])
        runner = registration["runner"]
        self.assertEqual(runner["worker_id"], self.worker_id)
        self.assertEqual(runner["state"], "offline")
        self.assertEqual(self.registry.allowed_targets(self.worker_id), [])
        with self.assertRaises(GatewayError):
            self.client.claim(30)
        self.assertEqual(self.jobs.get(job["id"])["state"], "queued")

        # A separate live-agent registration is the only transition to schedulable.
        live = self.client.register("linux", ["flutter", "linux"])
        self.assertEqual(live["runner"]["state"], "online")
        self.assertIn("test", self.registry.allowed_targets(self.worker_id))

    def test_runner_credentials_are_required_and_scoped_to_worker(self):
        import urllib.error
        import urllib.request

        for endpoint in ("ping", "enroll"):
            request = urllib.request.Request(
                self.client.base_url + "/v1/runner/" + endpoint,
                data=b'{"host_os":"linux","capabilities":["flutter","linux"]}',
                headers={"Content-Type": "application/json"},
            )
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(request, timeout=3)
                self.assertEqual(caught.exception.code, 401)


if __name__ == "__main__":
    unittest.main()
