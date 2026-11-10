"""Tests for isolated local Runner Agent workspaces; no code is executed."""
import os
import tempfile
import unittest
import uuid
from pathlib import Path

from tools.local_runner_agent.workspace import WorkspaceError, WorkspaceManager
from tools.cloud_gateway.job_control import JobStore


class WorkspaceManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "workspaces"
        self.manager = WorkspaceManager(self.root, max_active=2, max_workspace_bytes=32)
        self.job_a = str(uuid.uuid4())
        self.job_b = str(uuid.uuid4())

    def tearDown(self):
        self.temp.cleanup()

    def test_allocates_private_distinct_workspaces_and_tracks_owner(self):
        a = self.manager.create(self.job_a, "worker-a")
        b = self.manager.create(self.job_b, "worker-b")
        self.assertNotEqual(a, b)
        self.assertEqual(a.parent, self.root)
        self.assertEqual(a.stat().st_mode & 0o777, 0o700)
        self.assertEqual((a / ".dcp-workspace.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.manager.get(self.job_a, "worker-a"), a)
        self.assertEqual(self.manager.check_quota(self.job_a, "worker-a"), 0)

    def test_rejects_cross_job_and_cross_worker_access(self):
        self.manager.create(self.job_a, "worker-a")
        with self.assertRaises(WorkspaceError):
            self.manager.get(self.job_a, "worker-b")
        with self.assertRaises(WorkspaceError):
            self.manager.get(self.job_b, "worker-a")
        with self.assertRaises(WorkspaceError):
            self.manager.cleanup(self.job_a, "worker-b")
        self.assertTrue((self.root / self.job_a).exists())

    def test_rejects_invalid_ids_and_duplicate_workspace(self):
        with self.assertRaises(ValueError):
            self.manager.create("../escape", "worker-a")
        with self.assertRaises(ValueError):
            self.manager.create(self.job_a, "../worker")
        self.manager.create(self.job_a, "worker-a")
        with self.assertRaises(WorkspaceError):
            self.manager.create(self.job_a, "worker-a")

    def test_enforces_active_workspace_limit(self):
        self.manager.create(self.job_a, "worker-a")
        self.manager.create(self.job_b, "worker-b")
        with self.assertRaises(WorkspaceError):
            self.manager.create(str(uuid.uuid4()), "worker-c")

    def test_enforces_byte_quota_and_rejects_symlinks(self):
        path = self.manager.create(self.job_a, "worker-a")
        (path / "payload.bin").write_bytes(b"x" * 33)
        with self.assertRaises(WorkspaceError):
            self.manager.check_quota(self.job_a, "worker-a")
        (path / "payload.bin").unlink()
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("outside")
        try:
            os.symlink(outside, path / "linked.txt")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable on this platform")
        with self.assertRaises(WorkspaceError):
            self.manager.check_quota(self.job_a, "worker-a")

    def test_cleanup_removes_only_owned_workspace(self):
        a = self.manager.create(self.job_a, "worker-a")
        b = self.manager.create(self.job_b, "worker-b")
        (a / "file.txt").write_text("job A")
        self.manager.cleanup(self.job_a, "worker-a")
        self.assertFalse(a.exists())
        self.assertTrue(b.exists())

    def test_rejects_symlink_workspace_root(self):
        link = Path(self.temp.name) / "root-link"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(WorkspaceError):
            WorkspaceManager(link)


    def test_job_claim_workspace_and_cleanup_end_to_end(self):
        database = self.root.parent / "jobs.sqlite3"
        store = JobStore(str(database))
        job, created = store.create({
            "repository": "example/mobile-app",
            "commit_sha": "f" * 40,
            "target": "build",
        }, "workspace-e2e-key-0001")
        self.assertTrue(created)
        claimed = store.claim("runner-e2e")
        self.assertEqual(claimed["id"], job["id"])
        workspace = self.manager.create(claimed["id"], claimed["worker"])
        (workspace / "checkout-placeholder.txt").write_text(
            "x"
        )
        self.assertGreater(self.manager.check_quota(job["id"], "runner-e2e"), 0)
        self.assertEqual(self.manager.get(job["id"], "runner-e2e"), workspace)
        self.manager.cleanup(job["id"], "runner-e2e")
        self.assertFalse(workspace.exists())
        completed = store.finish(job["id"], "runner-e2e", "cancelled",
                                 {"workspace_cleaned": True})
        self.assertEqual(completed["state"], "cancelled")

if __name__ == "__main__":
    unittest.main()
