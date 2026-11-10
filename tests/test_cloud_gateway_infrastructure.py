"""Contract tests for DCP Infrastructure Manager; fake provider only."""
import tempfile
import unittest
from pathlib import Path

from tools.cloud_gateway.infrastructure import (
    FakeInfrastructureProvider, InfrastructureManager, InfrastructureStore,
    LifecycleConflict, ResourceNotFound,
)


class InfrastructureManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.provider = FakeInfrastructureProvider()
        self.store = InfrastructureStore(Path(self.temp.name) / "infra.sqlite3")
        self.manager = InfrastructureManager(self.store, {"fake": self.provider})

    def tearDown(self):
        self.temp.cleanup()

    def create(self, key="infra-create-0001"):
        return self.manager.create(target_os="linux",
            image_id="dcp-linux-ubuntu-24.04", template_id="flutter-linux-small",
            idempotency_key=key)

    def test_catalog_is_provider_neutral_and_external_provisioning_disabled(self):
        catalog = self.manager.catalog()
        self.assertEqual(catalog["providers"][0]["id"], "fake")
        self.assertFalse(catalog["provisioning_enabled"])
        self.assertEqual(len(catalog["images"]), 3)
        self.assertEqual(len(catalog["templates"]), 3)

    def test_fake_lifecycle_and_audit_are_durable(self):
        row, created = self.create()
        self.assertTrue(created)
        self.assertEqual(row["state"], "provisioned")
        resource_id = row["id"]
        self.assertEqual(self.manager.start(resource_id)["state"], "running")
        self.assertEqual(self.manager.inspect(resource_id)["state"], "running")
        self.assertEqual(self.manager.stop(resource_id)["state"], "stopped")
        self.assertEqual(self.manager.restart(resource_id)["state"], "running")
        self.assertEqual(self.manager.delete(resource_id)["state"], "deleted")
        self.assertEqual(self.manager.delete(resource_id)["state"], "deleted")
        events = [event["event"] for event in self.store.events(resource_id)]
        self.assertEqual(events, ["resource_created", "running", "stopped", "running", "deleted"])

    def test_idempotency_returns_existing_without_second_provider_create(self):
        first, created = self.create()
        second, created_again = self.create()
        self.assertTrue(created)
        self.assertFalse(created_again)
        self.assertEqual(first["id"], second["id"])
        self.assertEqual([c[0] for c in self.provider.calls].count("create"), 1)

    def test_idempotency_key_cannot_be_reused_for_different_request(self):
        self.create()
        with self.assertRaises(LifecycleConflict):
            self.manager.create(target_os="windows", image_id="dcp-windows-2025",
                template_id="flutter-windows-small", idempotency_key="infra-create-0001")

    def test_image_and_template_os_must_match(self):
        with self.assertRaisesRegex(ValueError, "match target OS"):
            self.manager.create(target_os="linux", image_id="dcp-linux-ubuntu-24.04",
                template_id="flutter-windows-small", idempotency_key="infra-mismatch-001")

    def test_invalid_transitions_are_rejected(self):
        row, _ = self.create()
        with self.assertRaises(LifecycleConflict):
            self.manager.stop(row["id"])
        self.manager.delete(row["id"])
        with self.assertRaises(LifecycleConflict):
            self.manager.start(row["id"])

    def test_unknown_resource_is_not_silently_accepted(self):
        with self.assertRaises(ResourceNotFound):
            self.manager.inspect("missing-resource")

    def test_external_provider_fails_closed_when_provisioning_disabled(self):
        class External(FakeInfrastructureProvider):
            provider_id = "external"
        external = External()
        manager = InfrastructureManager(self.store, {"external": external},
                                        default_provider="external", provisioning_enabled=False)
        with self.assertRaisesRegex(Exception, "disabled"):
            manager.create(target_os="linux", image_id="dcp-linux-ubuntu-24.04",
                template_id="flutter-linux-small", idempotency_key="external-create-001")
        self.assertEqual(external.calls, [])


if __name__ == "__main__":
    unittest.main()
