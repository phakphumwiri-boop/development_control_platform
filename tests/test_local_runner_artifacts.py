"""Artifact packaging must never turn a host hardlink into an upload."""
import os
import tempfile
import unittest
import uuid
from pathlib import Path

from tools.local_runner_agent.artifacts import ArtifactPackageError, FlutterArtifactPackager
from tools.local_runner_agent.workspace import WorkspaceManager


class FlutterArtifactHardlinkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.job_id = str(uuid.uuid4())
        self.worker_id = "artifact-hardlink-test"
        self.workspaces = WorkspaceManager(self.root / "workspaces")
        self.workspace = self.workspaces.create(self.job_id, self.worker_id)
        self.source = self.workspace / "source"
        self.source.mkdir()
        self.packager = FlutterArtifactPackager(self.workspaces)

    def tearDown(self):
        self.temp.cleanup()

    def _hardlink(self, source: Path, destination: Path):
        try:
            os.link(source, destination)
        except (OSError, NotImplementedError):
            self.skipTest("hardlinks are unavailable on this platform")

    def test_web_archive_rejects_hardlinked_host_file(self):
        output = self.source / "build" / "web"
        output.mkdir(parents=True)
        outside = self.root / "outside-secret.txt"
        outside.write_text("must-not-be-uploaded", encoding="utf-8")
        self._hardlink(outside, output / "index.html")
        with self.assertRaisesRegex(ArtifactPackageError, "hardlinked"):
            self.packager.package(self.job_id, self.worker_id, "build_web")

    def test_single_file_artifact_rejects_hardlinked_host_file(self):
        output = self.source / "build" / "app" / "outputs" / "flutter-apk"
        output.mkdir(parents=True)
        outside = self.root / "outside-secret.apk"
        outside.write_bytes(b"must-not-be-uploaded")
        self._hardlink(outside, output / "app-release.apk")
        with self.assertRaisesRegex(ArtifactPackageError, "hardlinked"):
            self.packager.package(self.job_id, self.worker_id, "build_android")


if __name__ == "__main__":
    unittest.main()
