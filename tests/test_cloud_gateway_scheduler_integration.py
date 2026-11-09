"""Runner Scheduler integration tests; no VM or cloud resource is created."""
import tempfile
import unittest
from pathlib import Path

from tools.cloud_gateway.infrastructure import (
    FakeInfrastructureProvider, InfrastructureManager, InfrastructureStore,
)
from tools.cloud_gateway.job_control import JobStore
from tools.cloud_gateway.runner_registry import RunnerRegistry
from tools.cloud_gateway.scheduler import (
    RunnerNotEligible, RunnerNotRegistered, RunnerScheduler,
)


class RunnerSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.jobs = JobStore(root / "jobs.sqlite3")
        self.registry = RunnerRegistry(root / "runners.sqlite3", stale_after_seconds=15)
        self.infrastructure = InfrastructureManager(
            InfrastructureStore(root / "infra.sqlite"),
            {"fake": FakeInfrastructureProvider()},
            provisioning_enabled=False,
        )
        self.scheduler = RunnerScheduler(self.jobs, self.registry, self.infrastructure)

    def tearDown(self):
        self.temp.cleanup()

    def create_job(self, target, key):
        row, _ = self.jobs.create({
            "repository": "owner/repo", "commit_sha": "a" * 40, "target": target,
        }, key)
        return row

    def test_linux_runner_only_claims_linux_and_generic_work(self):
        linux_job = self.create_job("build_linux", "sched-linux-0001")
        windows_job = self.create_job("build_windows", "sched-win-0001")
        self.registry.register("linux-runner", "linux", ["flutter", "linux"])
        claimed = self.scheduler.claim("linux-runner")
        self.assertEqual(claimed["id"], linux_job["id"])
        self.assertNotEqual(claimed["id"], windows_job["id"])
        self.assertEqual(self.jobs.get(windows_job["id"])["state"], "queued")

    def test_windows_runner_cannot_claim_linux_or_macos_build(self):
        self.create_job("build_linux", "sched-linux-0002")
        self.create_job("build_macos", "sched-mac-0002")
        self.registry.register("windows-runner", "windows", ["flutter", "windows"])
        self.assertIsNone(self.scheduler.claim("windows-runner"))
        self.assertEqual(
            self.scheduler.eligible_runners("build_macos"), []
        )

    def test_macos_requires_registered_online_macos_runner(self):
        mac_job = self.create_job("build_macos", "sched-mac-0003")
        # A catalog entry or simulated VM does not create a Runner registration.
        self.assertEqual(self.infrastructure.catalog()["images"][2]["target_os"], "macos")
        self.assertEqual(self.scheduler.eligible_runners("build_macos"), [])
        with self.assertRaises(RunnerNotRegistered):
            self.scheduler.claim("unregistered-mac")
        self.registry.register("mac-runner", "macos", ["flutter", "macos"])
        self.assertEqual(self.scheduler.eligible_runners("build_macos")[0]["worker_id"], "mac-runner")
        claimed = self.scheduler.claim("mac-runner")
        self.assertEqual(claimed["id"], mac_job["id"])

    def test_ios_requires_macos_runner_with_explicit_ios_capability(self):
        ios_job = self.create_job("build_ios", "sched-ios-0001")
        self.registry.register("mac-no-ios", "macos", ["flutter", "macos"])
        self.assertIsNone(self.scheduler.claim("mac-no-ios"))
        self.registry.register("mac-with-ios", "macos", ["flutter", "macos", "ios"])
        self.assertEqual(self.scheduler.claim("mac-with-ios")["id"], ios_job["id"])

    def test_draining_or_offline_runner_cannot_claim(self):
        self.create_job("test", "sched-test-0001")
        self.registry.register("linux-draining", "linux", ["flutter", "linux"])
        self.registry.drain("linux-draining")
        with self.assertRaises(RunnerNotEligible):
            self.scheduler.claim("linux-draining")
        with self.assertRaises(RunnerNotRegistered):
            self.scheduler.claim("missing-runner")

    def test_status_never_treats_fake_infrastructure_as_executable(self):
        self.registry.register("linux-status", "linux", ["flutter", "linux"])
        status = self.scheduler.status()
        self.assertEqual(status["online"], 1)
        self.assertFalse(status["provision_on_demand"])
        self.assertFalse(status["fake_infrastructure_is_executable"])
        self.assertFalse(status["infrastructure_provisioning_enabled"])


if __name__ == "__main__":
    unittest.main()
