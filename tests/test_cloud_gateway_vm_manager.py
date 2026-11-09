"""VM manager tests use a fake provider; no hypervisor or VM is started."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from tools.cloud_gateway.vm_manager import (
    VMConflict, VMManager, VMManagerError, VMProvisioningDisabled, VMQuotaExceeded,
)


class FakeProvider:
    provider_id = "fake"

    def __init__(self, ready=True):
        self.ready = ready
        self.calls = []
        self.fail_create = False

    def available(self):
        return self.ready

    def create(self, spec):
        self.calls.append(("create", spec["id"]))
        if self.fail_create:
            raise RuntimeError("fake provider failure")
        return "fake-ref-" + spec["id"]

    def start(self, vm):
        self.calls.append(("start", vm["id"]))

    def stop(self, vm):
        self.calls.append(("stop", vm["id"]))

    def delete(self, vm):
        self.calls.append(("delete", vm["id"]))


class VMManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.image = self.root / "base-image.qcow2"
        self.image.write_bytes(b"fake-immutable-vm-image")
        self.provider = FakeProvider()
        self.manager = VMManager(
            self.root / "vm-manager.sqlite3", {"fake": self.provider},
            provisioning_enabled=True, max_vms=2, max_vcpus=8,
            max_memory_mb=8192, max_disk_gb=200,
        )
        self.image_record = self.manager.register_image(
            "linux-base", "fake", "linux", "x86_64", self.image,
            hashlib.sha256(self.image.read_bytes()).hexdigest(),
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_create_is_idempotent_and_lifecycle_is_stateful(self):
        vm, created = self.manager.create(
            name="builder-01", provider_id="fake", image_id=self.image_record["id"],
            cpu=2, memory_mb=2048, disk_gb=40, idempotency_key="vm-create-key-0001",
        )
        self.assertTrue(created)
        self.assertEqual(vm["state"], "stopped")
        again, created_again = self.manager.create(
            name="builder-01", provider_id="fake", image_id=self.image_record["id"],
            cpu=2, memory_mb=2048, disk_gb=40, idempotency_key="vm-create-key-0001",
        )
        self.assertFalse(created_again)
        self.assertEqual(again["id"], vm["id"])
        self.assertEqual(len([call for call in self.provider.calls if call[0] == "create"]), 1)

        self.assertEqual(self.manager.start(vm["id"])["state"], "running")
        self.assertEqual(self.manager.start(vm["id"])["state"], "running")
        self.assertEqual(self.manager.stop(vm["id"])["state"], "stopped")
        self.assertEqual(self.manager.delete(vm["id"])["state"], "deleted")
        self.assertEqual(self.provider.calls[-3:], [
            ("start", vm["id"]), ("stop", vm["id"]), ("delete", vm["id"])
        ])

    def test_disabled_manager_never_calls_provider(self):
        disabled = VMManager(self.root / "disabled.sqlite3", {"fake": self.provider})
        image = disabled.register_image("linux-base", "fake", "linux", "x86_64", self.image)
        with self.assertRaises(VMProvisioningDisabled):
            disabled.create(
                name="blocked-vm", provider_id="fake", image_id=image["id"],
                idempotency_key="vm-disabled-key-001",
            )
        self.assertEqual(self.provider.calls, [])

    def test_quota_and_idempotency_conflicts_are_enforced(self):
        self.manager.create(
            name="builder-01", provider_id="fake", image_id=self.image_record["id"],
            cpu=4, memory_mb=4096, disk_gb=100, idempotency_key="vm-quota-key-0001",
        )
        with self.assertRaises(VMQuotaExceeded):
            self.manager.create(
                name="builder-02", provider_id="fake", image_id=self.image_record["id"],
                cpu=4, memory_mb=4096, disk_gb=100, idempotency_key="vm-quota-key-0002",
            )
        with self.assertRaises(VMConflict):
            self.manager.create(
                name="different-vm", provider_id="fake", image_id=self.image_record["id"],
                cpu=1, memory_mb=512, disk_gb=10, idempotency_key="vm-quota-key-0001",
            )

    def test_image_digest_is_reverified_before_provider_create(self):
        self.image.write_bytes(b"modified-image")
        with self.assertRaises(VMManagerError):
            self.manager.create(
                name="tampered-vm", provider_id="fake", image_id=self.image_record["id"],
                idempotency_key="vm-tamper-key-0001",
            )
        self.assertEqual(self.provider.calls, [])

    def test_provider_failure_records_failed_state(self):
        self.provider.fail_create = True
        with self.assertRaises(VMManagerError):
            self.manager.create(
                name="failed-vm", provider_id="fake", image_id=self.image_record["id"],
                idempotency_key="vm-failure-key-001",
            )
        failed = self.manager.list()[0]
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(failed["last_error"], "RuntimeError")

    def test_rejects_invalid_resource_bounds_and_image_hash(self):
        with self.assertRaises(VMManagerError):
            self.manager.register_image(
                "bad-image", "fake", "linux", "x86_64", self.image, "0" * 64
            )
        with self.assertRaises(ValueError):
            self.manager.create(
                name="../unsafe", provider_id="fake", image_id=self.image_record["id"],
                idempotency_key="vm-invalid-key-001",
            )
        with self.assertRaises(ValueError):
            self.manager.create(
                name="bad-cpu", provider_id="fake", image_id=self.image_record["id"],
                cpu=0, idempotency_key="vm-invalid-key-002",
            )


if __name__ == "__main__":
    unittest.main()
