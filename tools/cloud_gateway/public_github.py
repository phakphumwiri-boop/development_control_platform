"""Read-only GitHub REST catalog for explicitly allowlisted public repositories."""
from __future__ import annotations

import base64
import binascii
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


class PublicGitHubError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PublicGitHubRepositoryCatalog:
    """Resolve public repository metadata only for an operator-supplied allowlist."""

    API = "https://api.github.com"
    REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
    SHA_RE = re.compile(r"[0-9a-fA-F]{40}")
    MAX_RESPONSE_BYTES = 5 * 1024 * 1024

    def __init__(self, allowed_repositories, timeout: int = 10):
        if not isinstance(allowed_repositories, (list, tuple)):
            raise ValueError("Public repository allowlist must be a list")
        if len(allowed_repositories) > 20:
            raise ValueError("Public repository allowlist exceeds 20 entries")
        normalized = []
        seen = set()
        for repository in allowed_repositories:
            if not isinstance(repository, str) or not self.REPOSITORY_RE.fullmatch(repository):
                raise ValueError("Public repository allowlist contains an invalid name")
            key = repository.lower()
            if key in seen:
                raise ValueError("Public repository allowlist contains duplicates")
            seen.add(key)
            normalized.append(repository)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 30:
            raise ValueError("Public GitHub timeout must be 1..30 seconds")
        self.allowed_repositories = tuple(normalized)
        self._allowed = frozenset(normalized)
        self.timeout = timeout
        self.opener = urllib.request.build_opener(_NoRedirect())
        self.lock = threading.Lock()
        self.cache = {}

    def _request(self, path: str, max_bytes: int | None = None):
        if not isinstance(path, str) or not path.startswith("/repos/") or path.startswith("//"):
            raise PublicGitHubError("Invalid public GitHub API path")
        request = urllib.request.Request(
            self.API + path,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "DCP-Local-Gateway",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        limit = self.MAX_RESPONSE_BYTES if max_bytes is None else max_bytes
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(limit + 1)
                if len(raw) > limit:
                    raise PublicGitHubError("Public GitHub response exceeded its size limit")
        except urllib.error.HTTPError as exc:
            raise PublicGitHubError("Public GitHub API returned HTTP %s" % exc.code, exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise PublicGitHubError("Public GitHub API request failed") from None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise PublicGitHubError("Public GitHub API returned invalid JSON") from None

    def _require_allowed(self, repository: str):
        if repository not in self._allowed:
            raise PermissionError("Repository is not in the local Gateway allowlist")

    def _cached(self, key, ttl):
        with self.lock:
            item = self.cache.get(key)
            if item and item[0] > time.monotonic():
                return item[1]
        return None

    def _store_cache(self, key, value, ttl):
        with self.lock:
            self.cache[key] = (time.monotonic() + ttl, value)

    def _metadata(self, repository: str):
        self._require_allowed(repository)
        key = ("repo", repository)
        cached = self._cached(key, 60)
        if cached is not None:
            return dict(cached)
        owner, name = repository.split("/", 1)
        data = self._request("/repos/{}/{}".format(
            urllib.parse.quote(owner, safe=""), urllib.parse.quote(name, safe="")
        ))
        if not isinstance(data, dict) or data.get("full_name", "").lower() != repository.lower():
            raise PublicGitHubError("Public repository metadata did not match the allowlisted name")
        if data.get("private") is not False:
            raise PermissionError("Repository is private or unavailable to unauthenticated GitHub access")
        metadata = {
            "full_name": data["full_name"],
            "private": False,
            "default_branch": data.get("default_branch") if isinstance(data.get("default_branch"), str) else "",
            "html_url": data.get("html_url") if isinstance(data.get("html_url"), str) else "",
            "description": data.get("description") if isinstance(data.get("description"), str) else "",
        }
        self._store_cache(key, metadata, 60)
        return dict(metadata)

    def is_repository_accessible(self, repository: str) -> bool:
        if repository not in self._allowed:
            return False
        try:
            self._metadata(repository)
            return True
        except PermissionError:
            return False

    def list_repositories(self) -> list[dict]:
        rows = []
        for repository in self.allowed_repositories:
            try:
                rows.append(self._metadata(repository))
            except PublicGitHubError as exc:
                if exc.status == 404:
                    continue
                raise
            except PermissionError:
                continue
        return rows

    def list_repository_refs(self, repository: str, kind: str = "branches") -> list[dict]:
        self._require_allowed(repository)
        if kind not in ("branches", "tags"):
            raise ValueError("Repository ref kind must be branches or tags")
        key = ("refs", repository, kind)
        cached = self._cached(key, 30)
        if cached is not None:
            return [dict(item) for item in cached]
        owner, name = repository.split("/", 1)
        refs = []
        seen = set()
        for page in range(1, 6):
            data = self._request(
                "/repos/{}/{}/{}?per_page=100&page={}".format(
                    urllib.parse.quote(owner, safe=""),
                    urllib.parse.quote(name, safe=""), kind, page,
                )
            )
            if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
                raise PublicGitHubError("Public repository ref response is invalid")
            for item in data:
                ref_name = item.get("name")
                commit = item.get("commit")
                sha = commit.get("sha") if isinstance(commit, dict) else None
                if (not isinstance(ref_name, str) or not 1 <= len(ref_name) <= 255
                        or not isinstance(sha, str) or not self.SHA_RE.fullmatch(sha)):
                    raise PublicGitHubError("Public repository ref metadata is malformed")
                if ref_name in seen:
                    raise PublicGitHubError("Public repository refs contain duplicates")
                seen.add(ref_name)
                refs.append({"name": ref_name, "commit_sha": sha.lower()})
            if len(data) < 100:
                self._store_cache(key, refs, 30)
                return refs
        raise PublicGitHubError("Public repository ref inventory exceeded the 500-entry limit")

    def resolve_repository_commit(self, repository: str, commit_sha: str) -> dict:
        self._require_allowed(repository)
        if not isinstance(commit_sha, str) or not self.SHA_RE.fullmatch(commit_sha):
            raise ValueError("Commit SHA must be 40 hexadecimal characters")
        key = ("commit", repository, commit_sha.lower())
        cached = self._cached(key, 60)
        if cached is not None:
            return dict(cached)
        owner, name = repository.split("/", 1)
        data = self._request(
            "/repos/{}/{}/commits/{}".format(
                urllib.parse.quote(owner, safe=""),
                urllib.parse.quote(name, safe=""), commit_sha,
            )
        )
        resolved = data.get("sha") if isinstance(data, dict) else None
        if not isinstance(resolved, str) or not self.SHA_RE.fullmatch(resolved):
            raise PublicGitHubError("Public GitHub commit response omitted a valid SHA")
        if resolved.lower() != commit_sha.lower():
            raise PublicGitHubError("Public GitHub commit did not match the requested SHA")
        result = {"commit_sha": resolved.lower()}
        self._store_cache(key, result, 60)
        return result

    def inspect_repository_project(self, repository: str, commit_sha: str) -> dict:
        self._require_allowed(repository)
        if not isinstance(commit_sha, str) or not self.SHA_RE.fullmatch(commit_sha):
            raise ValueError("Commit SHA must be 40 hexadecimal characters")
        key = ("project", repository, commit_sha.lower())
        cached = self._cached(key, 60)
        if cached is not None:
            return dict(cached)
        owner, name = repository.split("/", 1)
        prefix = "/repos/{}/{}".format(
            urllib.parse.quote(owner, safe=""), urllib.parse.quote(name, safe="")
        )
        commit = self._request(prefix + "/commits/" + commit_sha)
        resolved = commit.get("sha") if isinstance(commit, dict) else None
        commit_data = commit.get("commit") if isinstance(commit, dict) else None
        tree_data = commit_data.get("tree") if isinstance(commit_data, dict) else None
        tree_sha = tree_data.get("sha") if isinstance(tree_data, dict) else None
        if (not isinstance(resolved, str) or resolved.lower() != commit_sha.lower()
                or not isinstance(tree_sha, str) or not self.SHA_RE.fullmatch(tree_sha)):
            raise PublicGitHubError("Public GitHub commit tree identity is invalid")
        tree = self._request(prefix + "/git/trees/" + tree_sha + "?recursive=1")
        entries = tree.get("tree") if isinstance(tree, dict) else None
        truncated = tree.get("truncated") if isinstance(tree, dict) else None
        if not isinstance(entries, list) or not isinstance(truncated, bool):
            raise PublicGitHubError("Public GitHub tree response is invalid")
        if any(not isinstance(item, dict) for item in entries):
            raise PublicGitHubError("Public GitHub tree metadata is malformed")
        if len(entries) > 20000:
            truncated = True

        paths = set()
        ignored = {
            ".git", ".venv", "venv", "node_modules", "__pycache__", ".dart_tool",
            "build", "dist", "target", "coverage", "pods", "deriveddata", ".gradle",
        }
        for item in entries[:20000]:
            path = item.get("path")
            if (not isinstance(path, str) or not path or path.startswith("/")
                    or any(part in ("", ".", "..") for part in path.split("/"))):
                raise PublicGitHubError("Public GitHub tree contains an unsafe path")
            parts = path.split("/")
            if (item.get("type") == "blob" and item.get("mode") != "120000"
                    and not any(part.lower() in ignored for part in parts)):
                paths.add(path)

        pubspecs = sorted(path for path in paths if path.rsplit("/", 1)[-1] == "pubspec.yaml")
        flutter_pubspecs = []
        manifest_scan_incomplete = len(pubspecs) > 20
        for pubspec in ([] if truncated else pubspecs[:20]):
            contents_path = prefix + "/contents/" + urllib.parse.quote(pubspec, safe="/")
            manifest = self._request(contents_path + "?ref=" + resolved, 512 * 1024)
            encoded = manifest.get("content") if isinstance(manifest, dict) else None
            encoding = manifest.get("encoding") if isinstance(manifest, dict) else None
            size = manifest.get("size") if isinstance(manifest, dict) else None
            if (encoding != "base64" or not isinstance(encoded, str)
                    or isinstance(size, bool) or not isinstance(size, int) or size > 256 * 1024):
                manifest_scan_incomplete = True
                continue
            try:
                raw = base64.b64decode(re.sub(r"\s+", "", encoded), validate=True)
                if len(raw) != size:
                    manifest_scan_incomplete = True
                    continue
                manifest_text = raw.decode("utf-8")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                manifest_scan_incomplete = True
                continue
            if re.search(r"(?m)^\s*flutter\s*:", manifest_text):
                flutter_pubspecs.append(pubspec)

        if manifest_scan_incomplete:
            truncated = True
        package_roots = [path.rsplit("/", 1)[0] if "/" in path else "" for path in flutter_pubspecs]
        macos_projects = []
        for root in package_roots:
            package_prefix = root + "/" if root else ""
            project = package_prefix + "macos/Runner.xcodeproj/project.pbxproj"
            info = package_prefix + "macos/Runner/Info.plist"
            if project in paths and info in paths:
                macos_projects.append(project)
        macos_supported = bool(macos_projects)
        if truncated:
            status, macos_result = "unknown", None
        elif flutter_pubspecs and macos_supported:
            status, macos_result = "target_detected", True
        elif flutter_pubspecs:
            status, macos_result = "needs_setup", False
        else:
            status, macos_result = "detected", None

        project_types = set()
        if pubspecs and not flutter_pubspecs and not truncated:
            project_types.add("dart")
        if flutter_pubspecs:
            project_types.add("flutter")
        for path in paths:
            filename = path.rsplit("/", 1)[-1].lower()
            if filename in ("pyproject.toml", "requirements.txt", "setup.py", "pipfile"):
                project_types.add("python")
            elif filename in ("package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json"):
                project_types.add("node")
            elif filename == "cargo.toml":
                project_types.add("rust")
            elif filename == "go.mod":
                project_types.add("go")
            elif filename in ("pom.xml", "build.gradle", "build.gradle.kts"):
                project_types.add("java")

        result = {
            "repository": repository,
            "commit_sha": resolved.lower(),
            "status": status,
            "project_types": sorted(project_types),
            "file_count": len(paths),
            "truncated": truncated,
            "flutter": {
                "detected": bool(flutter_pubspecs),
                "package_manifests": flutter_pubspecs,
                "macos_supported": macos_result,
                "macos_runner_projects": macos_projects if not truncated else [],
            },
            "notes": [
                "Inspection reads bounded public Git tree and pubspec manifest metadata only; no source files are executed.",
                "Only explicitly allowlisted public repositories are available without a GitHub App installation.",
                "A truncated tree is UNKNOWN and is never treated as proof that a target is absent.",
            ],
        }
        self._store_cache(key, result, 60)
        return dict(result)
