"""Local Runner registry and capability-aware queue tests."""
import tempfile
import unittest
from pathlib import Path

from tools.cloud_gateway.job_control import JobStore
from tools.cloud_gateway.runner_registry import RunnerRegistry, WorkerNotFound


class RunnerRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.registry = RunnerRegistry(self.root / "runners.sqlite3", stale_after_seconds=15)

    def tearDown(self):
        self.temp.cleanup()

    def test_register_heartbeat_drain_enable_and_target_capabilities(self):
        row = self.registry.register("runner-linux", "linux", ["flutter", "linux", "android", "web"])
        self.assertEqual(row["state"], "online")
        targets = self.registry.allowed_targets("runner-linux")
        self.assertIn("test", targets)
        self.assertIn("build_android", targets)
        self.assertIn("build_web", targets)
        self.assertNotIn("build_macos", targets)

        drained = self.registry.drain("runner-linux")
        self.assertEqual(drained["state"], "draining")
        self.assertEqual(self.registry.allowed_targets("runner-linux"), [])
        self.assertEqual(self.registry.heartbeat("runner-linux")["state"], "draining")
        enabled = self.registry.enable("runner-linux")
        self.assertEqual(enabled["state"], "online")
        self.assertIn("build_android", self.registry.allowed_targets("runner-linux"))

    def test_enrollment_records_host_offline_until_agent_starts(self):
        enrolled = self.registry.register(
            "runner-enrolled", "windows", ["flutter", "windows"], online=False
        )
        self.assertEqual(enrolled["state"], "offline")
        self.assertEqual(self.registry.allowed_targets("runner-enrolled"), [])

        active = self.registry.register(
            "runner-enrolled", "windows", ["flutter", "windows"], online=True
        )
        self.assertEqual(active["state"], "online")
        self.assertIn("build_windows", self.registry.allowed_targets("runner-enrolled"))

    def test_windows_host_without_windows_toolchain_can_only_claim_verified_targets(self):
        self.registry.register(
            "windows-android-only", "windows", ["flutter", "android", "web"]
        )
        targets = self.registry.allowed_targets("windows-android-only")
        self.assertIn("test", targets)
        self.assertIn("build_android", targets)
        self.assertIn("build_web", targets)
        self.assertNotIn("build_windows", targets)
        self.assertIn("build", targets)

    def test_stale_runner_is_reported_offline_and_cannot_claim(self):
        self.registry.register("runner-stale", "linux", ["flutter", "linux"])
        with self.registry.db() as conn:
            conn.execute(
                "UPDATE local_runners SET last_seen='2000-01-01T00:00:00+00:00' WHERE worker_id=?",
                ("runner-stale",),
            )
        self.assertEqual(self.registry.get("runner-stale")["state"], "offline")
        self.assertEqual(self.registry.allowed_targets("runner-stale"), [])

    def test_rejects_invalid_worker_capabilities(self):
        with self.assertRaises(ValueError):
            self.registry.register("../worker", "linux", ["flutter", "linux"])
        with self.assertRaises(ValueError):
            self.registry.register("runner-bad", "linux", ["flutter", "macos"])
        with self.assertRaises(ValueError):
            self.registry.register("runner-bad", "linux", ["flutter", "linux", "unknown"])

    def test_unknown_worker_operations_are_not_silently_accepted(self):
        with self.assertRaises(WorkerNotFound):
            self.registry.heartbeat("unknown-worker")
        with self.assertRaises(WorkerNotFound):
            self.registry.drain("unknown-worker")


    def test_ios_target_requires_explicit_ios_capability_on_macos(self):
        self.registry.register("runner-mac", "macos", ["flutter", "macos"])
        self.assertIn("build_macos", self.registry.allowed_targets("runner-mac"))
        self.assertNotIn("build_ios", self.registry.allowed_targets("runner-mac"))
        self.registry.register("runner-mac", "macos", ["flutter", "macos", "ios"])
        self.assertIn("build_ios", self.registry.allowed_targets("runner-mac"))


class CapabilityAwareJobClaimTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.jobs = JobStore(str(Path(self.temp.name) / "jobs.sqlite3"))

    def tearDown(self):
        self.temp.cleanup()

    def test_claim_skips_jobs_not_supported_by_runner(self):
        mac_job, _ = self.jobs.create({
            "repository": "owner/repo", "commit_sha": "a" * 40, "target": "build_macos"
        }, "claim-macos-key-001")
        web_job, _ = self.jobs.create({
            "repository": "owner/repo", "commit_sha": "b" * 40, "target": "build_web"
        }, "claim-web-key-0001")
        claimed = self.jobs.claim("linux-runner", 30, ["test", "build_web", "build_linux"])
        self.assertEqual(claimed["id"], web_job["id"])
        self.assertNotEqual(claimed["id"], mac_job["id"])
        self.assertIsNone(self.jobs.claim("linux-runner-2", 30, ["test", "build_linux"]))


if __name__ == "__main__":
    unittest.main()
