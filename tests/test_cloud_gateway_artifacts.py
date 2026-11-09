"""ArtifactStore tests for ownership, bounded uploads, checksums, and retention."""
import hashlib
import io
import tempfile
import unittest
import uuid
from pathlib import Path

from tools.cloud_gateway.artifacts import ArtifactError, ArtifactStore
from tools.cloud_gateway.job_control import JobStore


class ArtifactStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.jobs = JobStore(str(self.root / "jobs.sqlite3"))
        self.artifacts = ArtifactStore(self.root / "artifacts", max_artifact_bytes=2048)
        self.job, _ = self.jobs.create({
            "repository": "owner/repo", "commit_sha": "a" * 40, "target": "build"
        }, "artifact-test-key-001")
        self.claimed = self.jobs.claim("runner-artifact")
        self.assertEqual(self.claimed["id"], self.job["id"])

    def tearDown(self):
        self.temp.cleanup()

    def test_stores_hash_and_returns_immutable_metadata(self):
        payload = b"flutter-build-output"
        metadata = self.artifacts.store(
            self.jobs, self.job["id"], "runner-artifact", "app-release.apk",
            io.BytesIO(payload), len(payload),
        )
        self.assertEqual(metadata["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(metadata["size"], len(payload))
        self.assertEqual(self.artifacts.list_for_job(self.job["id"])[0]["id"], metadata["id"])
        read_metadata, handle = self.artifacts.open(metadata["id"])
        with handle:
            self.assertEqual(handle.read(), payload)
        self.assertEqual(read_metadata["name"], "app-release.apk")

    def test_rejects_path_names_oversize_and_non_owner(self):
        payload = b"payload"
        with self.assertRaises(ArtifactError):
            self.artifacts.store(self.jobs, self.job["id"], "runner-artifact",
                                 "../escape.apk", io.BytesIO(payload), len(payload))
        with self.assertRaises(ArtifactError):
            self.artifacts.store(self.jobs, self.job["id"], "other-runner",
                                 "app.apk", io.BytesIO(payload), len(payload))
        with self.assertRaises(ArtifactError):
            self.artifacts.store(self.jobs, self.job["id"], "runner-artifact",
                                 "huge.bin", io.BytesIO(b"x" * 2049), 2049)

    def test_rejects_truncated_upload_and_does_not_leave_blob(self):
        with self.assertRaises(ArtifactError):
            self.artifacts.store(self.jobs, self.job["id"], "runner-artifact",
                                 "partial.zip", io.BytesIO(b"x"), 10)
        self.assertEqual(self.artifacts.list_for_job(self.job["id"]), [])

    def test_rejects_invalid_artifact_id(self):
        with self.assertRaises(ArtifactError):
            self.artifacts.get("../../metadata.sqlite3")


if __name__ == "__main__":
    unittest.main()
