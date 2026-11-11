"""Regression tests for private local SQLite database files."""
import os
import stat
import tempfile
import unittest
from pathlib import Path

from tools.cloud_gateway.infrastructure import InfrastructureStore
from tools.cloud_gateway.job_control import JobStore
from tools.cloud_gateway.runner_registry import RunnerRegistry
from tools.cloud_gateway.sqlite_security import prepare_private_sqlite_file
from tools.cloud_gateway.store import RunnerStore


@unittest.skipUnless(os.name == "posix", "POSIX file mode assertions do not apply to Windows ACLs")
class PrivateSQLitePermissionsTests(unittest.TestCase):
    def test_all_local_control_plane_databases_are_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stores = (
                (JobStore, "jobs.sqlite3"),
                (RunnerRegistry, "runners.sqlite3"),
                (InfrastructureStore, "infrastructure.sqlite3"),
                (RunnerStore, "lifecycle.sqlite3"),
            )
            for store_type, filename in stores:
                with self.subTest(database=filename):
                    path = root / filename
                    store_type(path)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_existing_database_permissions_are_restricted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing.sqlite3"
            path.write_bytes(b"")
            path.chmod(0o644)
            prepare_private_sqlite_file(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_symlink_database_path_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "real.sqlite3"
            target.write_bytes(b"preserve")
            link = root / "linked.sqlite3"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "regular file"):
                prepare_private_sqlite_file(link)
            self.assertEqual(target.read_bytes(), b"preserve")

    def test_memory_database_needs_no_filesystem_permissions(self):
        prepare_private_sqlite_file(":memory:")


if __name__ == "__main__":
    unittest.main()
