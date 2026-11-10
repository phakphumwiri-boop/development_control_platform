"""Collect bounded Flutter outputs into a single uploadable artifact."""
from __future__ import annotations

import os
import shutil
import stat
import zipfile
from pathlib import Path

from .execution import ExecutionError
from .workspace import WorkspaceManager


class ArtifactPackageError(RuntimeError):
    """Flutter output is missing or cannot be safely packaged."""


class FlutterArtifactPackager:
    def __init__(self, workspaces: WorkspaceManager, max_bytes: int = 100 * 1024 * 1024,
                 max_files: int = 100_000):
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1024 <= max_bytes <= 1024 * 1024 * 1024:
            raise ValueError("max_bytes must be between 1 KiB and 1 GiB")
        if isinstance(max_files, bool) or not isinstance(max_files, int) or not 1 <= max_files <= 1_000_000:
            raise ValueError("max_files must be between 1 and 1,000,000")
        self.workspaces = workspaces
        self.max_bytes = max_bytes
        self.max_files = max_files

    @staticmethod
    def _output_for(source: Path, target: str):
        if target == "test":
            return None, None
        if target in ("build", "build_android"):
            return source / "build/app/outputs/flutter-apk/app-release.apk", "app-release.apk"
        if target == "package":
            return source / "build/app/outputs/bundle/release/app-release.aab", "app-release.aab"
        if target == "build_web":
            return source / "build/web", "flutter-web-build.zip"
        if target == "build_linux":
            return source / "build/linux/x64/release/bundle", "flutter-linux-build.zip"
        if target == "build_windows":
            candidates = (
                source / "build/windows/x64/runner/Release",
                source / "build/windows/runner/Release",
            )
            return next((item for item in candidates if item.is_dir()), candidates[0]), "flutter-windows-build.zip"
        if target == "build_macos":
            parent = source / "build/macos/Build/Products/Release"
            apps = sorted(parent.glob("*.app")) if parent.is_dir() else []
            return (apps[0] if len(apps) == 1 else parent / "Runner.app"), "flutter-macos-build.zip"
        if target == "build_ios":
            return source / "build/ios/iphoneos/Runner.app", "flutter-ios-build.zip"
        raise ArtifactPackageError("unsupported Flutter artifact target")

    def package(self, job_id: str, worker_id: str, target: str) -> tuple[Path, str] | None:
        workspace = self.workspaces.get(job_id, worker_id)
        source = workspace / "source" if (workspace / "source").is_dir() else workspace
        output, name = self._output_for(source, target)
        if output is None:
            return None
        if output.is_symlink() or not output.exists():
            raise ArtifactPackageError("expected Flutter build output is missing or unsafe")
        destination_dir = workspace / ".dcp-artifacts"
        if destination_dir.is_symlink() or (destination_dir.exists() and not destination_dir.is_dir()):
            raise ArtifactPackageError("artifact staging directory is unsafe")
        destination_dir.mkdir(mode=0o700, exist_ok=True)
        if destination_dir.resolve(strict=True).parent != workspace.resolve(strict=True):
            raise ArtifactPackageError("artifact staging directory escaped workspace")
        destination = destination_dir / name
        if destination.exists() or destination.is_symlink():
            raise ArtifactPackageError("artifact destination already exists")

        if output.is_file():
            info = output.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > self.max_bytes:
                raise ArtifactPackageError("Flutter output file is outside allowed bounds")
            shutil.copyfile(output, destination)
            destination.chmod(0o600)
        elif output.is_dir():
            entries = []
            total = 0
            for current, dirs, files in os.walk(output, topdown=True, followlinks=False):
                for dirname in list(dirs):
                    item = Path(current) / dirname
                    if item.is_symlink():
                        raise ArtifactPackageError("Flutter output contains a symlink directory")
                for filename in files:
                    item = Path(current) / filename
                    info = item.lstat()
                    if not stat.S_ISREG(info.st_mode):
                        raise ArtifactPackageError("Flutter output contains a non-regular file")
                    relative = item.relative_to(output)
                    if relative.is_absolute() or ".." in relative.parts:
                        raise ArtifactPackageError("Flutter output path is unsafe")
                    total += info.st_size
                    entries.append((item, relative))
                    if len(entries) > self.max_files or total > self.max_bytes:
                        raise ArtifactPackageError("Flutter output exceeds artifact limits")
            if not entries:
                raise ArtifactPackageError("Flutter output directory is empty")
            with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
                for item, relative in entries:
                    bundle.write(item, arcname=relative.as_posix())
            if destination.stat().st_size > self.max_bytes:
                destination.unlink(missing_ok=True)
                raise ArtifactPackageError("compressed Flutter output exceeds artifact limit")
            destination.chmod(0o600)
        else:
            raise ArtifactPackageError("Flutter output is not a regular file or directory")
        self.workspaces.check_quota(job_id, worker_id)
        return destination, name
