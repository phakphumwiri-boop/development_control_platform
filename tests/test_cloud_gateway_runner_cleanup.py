"""Mock-only runner deregistration and lifecycle retry tests."""
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tools.cloud_gateway.policy import GatewaySettings, PolicyDenied, PROFILES
from tools.cloud_gateway.runner_cleanup import GitHubRunnerCleanup
from tools.cloud_gateway.service import GatewayService
from tools.cloud_gateway.store import RunnerStore
from tools.runner_backend.provider import RunnerInstance


REPOSITORY = "phakphum12345/generated-A4-pdf"


def request_payload():
    profile = PROFILES["linux"]
    return {
        "repository": REPOSITORY,
        "workflow_run_id": 123,
        "commit_sha": "a" * 40,
        "target_os": "linux",
        "image": profile["image"],
        "labels": list(profile["labels"]),
        "ephemeral": True,
        "max_runtime_minutes": 30,
        "network_policy": "restricted-egress",
        "registration_token_handling": "provider-side-only",
    }


def settings():
    return GatewaySettings(
        provisioning_enabled=True,
        owner_approved=True,
        allowed_repositories=(REPOSITORY,),
        budget_limit_usd=100,
        current_spend_usd=0,
        projected_run_cost_usd=1,
        max_concurrent_runners=2,
        max_runtime_minutes=180,
    )


class FakeGitHubApp:
    def __init__(self, runner=None, retain_after_delete=False):
        self.runner = runner
        self.retain_after_delete = retain_after_delete
        self.removals = []

    def is_repository_accessible(self, repository, refresh=False):
        return repository == REPOSITORY

    def find_runner(self, repository, runner_name):
        if self.runner and self.runner["name"] == runner_name:
            return dict(self.runner)
        return None

    def remove_runner(self, repository, runner_id):
        self.removals.append((repository, runner_id))
        if not self.retain_after_delete:
            self.runner = None
        return True


class CleanupProvider:
    requires_runner_cleanup = True

    def __init__(self, terminal_state="terminated"):
        self.calls = []
        self.terminal_state = terminal_state

    def readiness(self, os_name):
        return {"ready": os_name == "linux"}

    def provision(self, payload):
        self.calls.append(("provision", payload["repository"]))
        return RunnerInstance("dcp-123-abcdef12", "provisioning", "dcp-123-abcdef12", tuple(payload["labels"]))

    def status(self, provider_id):
        self.calls.append(("status", provider_id))
        return RunnerInstance(provider_id, self.terminal_state, provider_id)

    def terminate(self, provider_id):
        self.calls.append(("terminate", provider_id))
        return RunnerInstance(provider_id, self.terminal_state, provider_id)


class GitHubRunnerCleanupTests(unittest.TestCase):
    def test_already_absent_runner_is_idempotent(self):
        cleanup = GitHubRunnerCleanup(FakeGitHubApp())
        result = cleanup(
            {"repository": REPOSITORY, "provider_id": "dcp-123-abcdef12"},
            RunnerInstance("dcp-123-abcdef12", "terminated"),
        )
        self.assertEqual(result, "already_absent")

    def test_offline_runner_is_removed_and_absence_verified(self):
        app = FakeGitHubApp({
            "id": 77, "name": "dcp-123-abcdef12", "status": "offline", "labels": ()
        })
        cleanup = GitHubRunnerCleanup(app)
        result = cleanup(
            {"repository": REPOSITORY, "provider_id": "azure:dcp-123-abcdef12"},
            RunnerInstance("dcp-123-abcdef12", "terminated"),
        )
        self.assertEqual(result, "removed")
        self.assertEqual(app.removals, [(REPOSITORY, 77)])
        self.assertIsNone(app.runner)

    def test_uninstalled_repository_is_rejected_before_runner_lookup(self):
        app = FakeGitHubApp({
            "id": 77, "name": "dcp-123-abcdef12", "status": "offline", "labels": ()
        })
        with self.assertRaisesRegex(Exception, "not accessible"):
            GitHubRunnerCleanup(app)(
                {"repository": "attacker/repo", "provider_id": "azure:dcp-123-abcdef12"},
                RunnerInstance("dcp-123-abcdef12", "terminated"),
            )
        self.assertEqual(app.removals, [])

    def test_online_runner_is_not_deregistered(self):
        app = FakeGitHubApp({
            "id": 77, "name": "dcp-123-abcdef12", "status": "online", "labels": ()
        })
        with self.assertRaisesRegex(Exception, "offline"):
            GitHubRunnerCleanup(app)(
                {"repository": REPOSITORY, "provider_id": "dcp-123-abcdef12"},
                RunnerInstance("dcp-123-abcdef12", "terminated"),
            )
        self.assertEqual(app.removals, [])

    def test_deregistration_waits_until_absence_is_confirmed(self):
        app = FakeGitHubApp({
            "id": 77, "name": "dcp-123-abcdef12", "status": "offline", "labels": ()
        }, retain_after_delete=True)
        with self.assertRaisesRegex(Exception, "not yet confirmed"):
            GitHubRunnerCleanup(app)(
                {"repository": REPOSITORY, "provider_id": "dcp-123-abcdef12"},
                RunnerInstance("dcp-123-abcdef12", "terminated"),
            )


class GatewayCleanupIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = RunnerStore(str(Path(self.temp.name) / "gateway.sqlite"))
        self.provider = CleanupProvider()

    def tearDown(self):
        self.temp.cleanup()

    def service(self, cleanup):
        return GatewayService(settings(), self.store, self.provider, runner_cleanup=cleanup)

    def test_provider_requires_cleanup_callback_before_provisioning(self):
        service = GatewayService(settings(), self.store, self.provider)
        with self.assertRaises(PolicyDenied):
            service.create(request_payload(), "cleanup-key-001")
        self.assertEqual(self.provider.calls, [])

    def test_terminal_provider_state_deregisters_before_terminal_state(self):
        calls = []
        service = self.service(lambda row, instance: calls.append(row["provider_id"]) or "removed")
        row, _ = service.create(request_payload(), "cleanup-key-002")
        result = service.terminate(row["id"])
        self.assertEqual(result["state"], "terminated")
        self.assertEqual(calls, ["dcp-123-abcdef12"])
        events = self.store.audit_events(row["id"])
        self.assertIn("runner_cleanup_confirmed", [event["event"] for event in events])
        summary = self.store.lifecycle_summary()
        self.assertEqual(summary["cleanup_pending"], 0)
        self.assertEqual(summary["cleanup_confirmed"], 1)
        self.assertEqual(summary["state_counts"]["terminated"], 1)

    def test_cleanup_failure_keeps_runner_retryable(self):
        calls = []
        def cleanup(row, instance):
            calls.append(row["provider_id"])
            if len(calls) == 1:
                raise RuntimeError("private token must not enter audit")
            return "removed"
        service = self.service(cleanup)
        row, _ = service.create(request_payload(), "cleanup-key-003")
        with self.assertRaises(RuntimeError):
            service.terminate(row["id"])
        self.assertEqual(self.store.get(row["id"])["state"], "terminating")
        self.assertEqual(service.terminate(row["id"])["state"], "terminated")
        events = self.store.audit_events(row["id"])
        self.assertIn("cleanup_retry", [event["event"] for event in events])
        self.assertNotIn("private token", str(events))

    def test_partial_provider_failure_persists_cleanup_identity(self):
        class PartialFailure(CleanupProvider):
            def provision(self, payload):
                error = RuntimeError("provider failed after resource creation")
                error.provider_id = "dcp-123-abcdef12"
                raise error
        provider = PartialFailure()
        service = GatewayService(settings(), self.store, provider, runner_cleanup=lambda *_: "removed")
        with self.assertRaises(RuntimeError):
            service.create(request_payload(), "cleanup-key-partial")
        row = self.store.get_by_key("cleanup-key-partial")
        self.assertEqual(row["state"], "terminated")
        self.assertEqual(row["provider_id"], "dcp-123-abcdef12")
        self.assertIn(("terminate", "dcp-123-abcdef12"), provider.calls)
        self.assertEqual(self.store.active_count(), 0)

    def test_provider_still_terminating_is_scheduled_for_immediate_retry(self):
        class PendingProvider(CleanupProvider):
            def terminate(self, provider_id):
                self.calls.append(("terminate", provider_id))
                return RunnerInstance(provider_id, "terminating", provider_id)
            def status(self, provider_id):
                self.calls.append(("status", provider_id))
                return RunnerInstance(provider_id, "terminating", provider_id)
        provider = PendingProvider()
        service = GatewayService(
            settings(), self.store, provider,
            runner_cleanup=lambda *_: "removed",
        )
        row, _ = service.create(request_payload(), "cleanup-key-pending")
        result = service.terminate(row["id"])
        self.assertEqual(result["state"], "terminating")
        self.assertEqual(len(self.store.expired_active(datetime.now(timezone.utc).isoformat())), 1)

    def test_idempotent_replay_returns_existing_runner_even_if_provider_not_ready(self):
        class MutableReadiness(CleanupProvider):
            ready = True
            def readiness(self, os_name):
                return {"ready": self.ready}
        provider = MutableReadiness()
        service = GatewayService(settings(), self.store, provider, runner_cleanup=lambda *_: "removed")
        first, created = service.create(request_payload(), "cleanup-key-replay")
        provider.ready = False
        replay, replay_created = service.create(request_payload(), "cleanup-key-replay")
        self.assertTrue(created)
        self.assertFalse(replay_created)
        self.assertEqual(first["id"], replay["id"])
        self.assertEqual(len([call for call in provider.calls if call[0] == "provision"]), 1)

    def test_provider_readiness_must_be_pass(self):
        class NotReady(CleanupProvider):
            def readiness(self, os_name):
                return {"ready": False, "message": "not ready"}
        provider = NotReady()
        service = GatewayService(settings(), self.store, provider, runner_cleanup=lambda *_: "removed")
        with self.assertRaises(PolicyDenied):
            service.create(request_payload(), "cleanup-key-004")
        self.assertEqual(provider.calls, [])


class FailedRunnerAccountingTests(unittest.TestCase):
    def test_failed_record_stops_counting_after_cleanup_confirmation(self):
        with tempfile.TemporaryDirectory() as temp:
            store = RunnerStore(str(Path(temp) / "gateway.sqlite"))
            expiry = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            store.create("runner-id", "failed-key", "fingerprint", request_payload(), expiry)
            store.transition("runner-id", "failed", provider_id="dcp-123-abcdef12")
            store.record_event("runner-id", "provider_cleanup_confirmed", "provider_only")
            self.assertEqual(store.active_count(), 0)
            self.assertEqual(store.expired_active(datetime.now(timezone.utc).isoformat()), [])

    def test_failed_record_with_provider_id_counts_until_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            store = RunnerStore(str(Path(temp) / "gateway.sqlite"))
            expiry = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
            row, _ = store.create("runner-id", "failed-key", "fingerprint", request_payload(), expiry)
            store.transition("runner-id", "failed", provider_id="dcp-123-abcdef12")
            self.assertEqual(store.active_count(), 1)
            self.assertEqual(len(store.expired_active(datetime.now(timezone.utc).isoformat())), 1)


if __name__ == "__main__":
    unittest.main()
