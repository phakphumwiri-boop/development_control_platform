"""Bounded, path-safe checkout of one immutable GitHub commit.

Uses GitHub's source archive endpoint; it does not run git hooks, submodules,
package scripts, or any repository code during extraction.
"""
from __future__ import annotations

import os
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from .workspace import WorkspaceError, WorkspaceManager


class CheckoutError(RuntimeError):
    """Repository source could not be safely retrieved or extracted."""


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        from urllib.parse import urlparse
        old, new = urlparse(req.full_url), urlparse(newurl)
        if new.scheme != "https" or new.hostname not in ("api.github.com", "codeload.github.com"):
            raise CheckoutError("GitHub archive redirected to an untrusted host")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected and old.hostname != new.hostname:
            redirected.remove_header("Authorization")
        return redirected


class GitHubCommitCheckout:
    """Download and safely extract a single repository commit into workspace/source."""

    def __init__(
        self,
        workspace_manager: WorkspaceManager,
        *,
        token: str | None = None,
        max_archive_bytes: int = 100 * 1024 * 1024,
        max_expanded_bytes: int = 1024 * 1024 * 1024,
        max_files: int = 100_000,
        timeout_seconds: int = 60,
    ):
        for name, value, minimum, maximum in (
            ("max_archive_bytes", max_archive_bytes, 1024, 1024 * 1024 * 1024),
            ("max_expanded_bytes", max_expanded_bytes, 1024, 10 * 1024 * 1024 * 1024),
            ("max_files", max_files, 1, 1_000_000),
            ("timeout_seconds", timeout_seconds, 1, 300),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise ValueError(f"{name} is outside its allowed range")
        if token is not None and (not isinstance(token, str) or len(token) < 20):
            raise ValueError("GitHub token is invalid")
        self.workspaces = workspace_manager
        self.token = token
        self.max_archive_bytes = max_archive_bytes
        self.max_expanded_bytes = max_expanded_bytes
        self.max_files = max_files
        self.timeout_seconds = timeout_seconds
        self.opener = urllib.request.build_opener(_SafeRedirect())

    @staticmethod
    def _validate(repository: str, commit_sha: str):
        import re
        if (not isinstance(repository, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository
        ) or any(part in (".", "..") for part in repository.split("/"))):
            raise CheckoutError("invalid GitHub repository")
        if not isinstance(commit_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
            raise CheckoutError("invalid immutable commit SHA")

    def checkout(self, job_id: str, worker_id: str, repository: str, commit_sha: str) -> Path:
        self._validate(repository, commit_sha)
        workspace = self.workspaces.get(job_id, worker_id)
        source = workspace / "source"
        if source.exists():
            raise CheckoutError("workspace source directory already exists")
        source.mkdir(mode=0o700)
        url = f"https://api.github.com/repos/{repository}/zipball/{commit_sha}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "DCP-Runner-Agent",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(url, headers=headers, method="GET")
        total_written = 0
        try:
            with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b") as archive:
                with self.opener.open(request, timeout=self.timeout_seconds) as response:
                    length = response.headers.get("Content-Length")
                    if length and int(length) > self.max_archive_bytes:
                        raise CheckoutError("source archive exceeds download limit")
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        total_written += len(chunk)
                        if total_written > self.max_archive_bytes:
                            raise CheckoutError("source archive exceeds download limit")
                        archive.write(chunk)
                archive.seek(0)
                with zipfile.ZipFile(archive) as bundle:
                    entries = bundle.infolist()
                    if len(entries) > self.max_files:
                        raise CheckoutError("source archive contains too many entries")
                    roots = set()
                    expanded = 0
                    safe_entries = []
                    for info in entries:
                        raw = info.filename
                        path = PurePosixPath(raw)
                        if path.is_absolute() or not path.parts or ".." in path.parts or "\\" in raw:
                            raise CheckoutError("source archive contains an unsafe path")
                        roots.add(path.parts[0])
                        if len(path.parts) < 2:
                            continue
                        relative = Path(*path.parts[1:])
                        if relative == Path("."):
                            continue
                        mode = (info.external_attr >> 16) & 0o170000
                        if mode == 0o120000:
                            raise CheckoutError("source archive contains a symlink")
                        if mode not in (0, 0o100000, 0o040000):
                            raise CheckoutError("source archive contains a special file")
                        if not info.is_dir():
                            expanded += info.file_size
                            if expanded > self.max_expanded_bytes:
                                raise CheckoutError("expanded source exceeds size limit")
                        safe_entries.append((info, relative))
                    if len(roots) != 1:
                        raise CheckoutError("source archive has an unexpected root layout")
                    root = source.resolve(strict=True)
                    for info, relative in safe_entries:
                        destination = source.joinpath(relative)
                        resolved = destination.resolve(strict=False)
                        if resolved != root and root not in resolved.parents:
                            raise CheckoutError("source archive path escaped workspace")
                        if info.is_dir():
                            destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                            continue
                        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        written = 0
                        with bundle.open(info, "r") as src, destination.open("xb") as dst:
                            while True:
                                chunk = src.read(1024 * 1024)
                                if not chunk:
                                    break
                                written += len(chunk)
                                if written > info.file_size:
                                    raise CheckoutError("source archive entry exceeded declared size")
                                dst.write(chunk)
                        if written != info.file_size:
                            raise CheckoutError("source archive entry was truncated")
                        file_mode = (info.external_attr >> 16) & 0o777
                        destination.chmod(0o700 if file_mode & 0o111 else 0o600)
            if not (source / "pubspec.yaml").is_file():
                raise CheckoutError("selected commit is not a Flutter project")
            self.workspaces.check_quota(job_id, worker_id)
            return source
        except CheckoutError:
            raise
        except (OSError, zipfile.BadZipFile, urllib.error.URLError, ValueError) as exc:
            raise CheckoutError("GitHub source checkout failed") from exc
