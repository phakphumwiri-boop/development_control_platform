"""GitHub App-backed, repository-scoped ephemeral runner registration.

This module is server-side only. It never writes credentials to disk or returns
them through the dashboard API. Callers must deliver the registration token
only through a provider's protected bootstrap channel.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request

from .safe_http import open_no_redirect, read_bounded, require_json_content_type


class GitHubAppError(RuntimeError):
    """Sanitized GitHub App integration error."""


@dataclass(frozen=True)
class RunnerRegistrationCredential:
    token: str = field(repr=False)
    expires_at: datetime

    def __repr__(self) -> str:
        return "RunnerRegistrationCredential(token=<redacted>, expires_at={!r})".format(
            self.expires_at.isoformat()
        )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _claims_json(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


class GitHubAppRunnerBootstrap:
    """Mint narrowly scoped registration tokens using a GitHub App installation.

    The App private key should be read from a server-side secret store (for
    example Key Vault) and passed in memory. Installation tokens used for
    runner administration are scoped to one verified repository and are never
    returned to callers.
    """

    API_ORIGIN = "https://api.github.com"
    # Installation catalog pages can contain 100 full repository objects. A
    # 64 KiB cap rejects legitimate accounts with many repositories; retain a
    # strict bound while allowing normal GitHub pagination responses.
    MAX_RESPONSE_BYTES = 2 * 1024 * 1024

    def __init__(
        self,
        app_id: str,
        installation_id: int,
        private_key_pem: str,
        allowed_repositories: tuple[str, ...] | list[str],
        *,
        clock=time.time,
        timeout: int = 10,
        opener=None,
    ):
        if not isinstance(app_id, str) or not re.fullmatch(r"[0-9]{1,20}", app_id):
            raise ValueError("GitHub App ID must be numeric")
        if isinstance(installation_id, bool) or not isinstance(installation_id, int) or installation_id < 1:
            raise ValueError("GitHub App installation ID must be positive")
        if not isinstance(private_key_pem, str) or "BEGIN" not in private_key_pem:
            raise ValueError("GitHub App private key is required")
        repos = tuple(allowed_repositories)
        if len(set(repos)) != len(repos):
            raise ValueError("Repository allowlist entries must be unique")
        if any(not isinstance(repo, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repo
        ) for repo in repos):
            raise ValueError("Invalid repository allowlist entry")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 30:
            raise ValueError("GitHub API timeout must be 1..30 seconds")
        self.app_id = app_id
        self.installation_id = installation_id
        self.private_key_pem = private_key_pem
        self.allowed_repositories = frozenset(repos)
        self._repository_catalog_cache = None
        self._repository_catalog_cache_until = 0.0
        self.clock = clock
        self.timeout = timeout
        self.opener = opener

    def _app_jwt(self) -> str:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding, rsa

            key = serialization.load_pem_private_key(
                self.private_key_pem.encode("utf-8"), password=None
            )
            if not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError("GitHub App key must be RSA")
            now = int(self.clock())
            header = _b64url(_claims_json({"alg": "RS256", "typ": "JWT"}))
            claims = _b64url(_claims_json({
                "iat": now - 30,
                "exp": now + 540,
                "iss": self.app_id,
            }))
            signing_input = (header + "." + claims).encode("ascii")
            signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
            return header + "." + claims + "." + _b64url(signature)
        except GitHubAppError:
            raise
        except Exception as exc:
            raise GitHubAppError("GitHub App JWT signing failed: " + type(exc).__name__) from exc

    def _request(self, method: str, path: str, token: str, payload: dict | None = None) -> dict | list:
        if not path.startswith("/") or ".." in path.split("/"):
            raise GitHubAppError("Invalid GitHub API path")
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "DCP-GitHub-App-Runner-Bootstrap/1.0",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = Request(self.API_ORIGIN + path, data=body, method=method, headers=headers)
        request.add_unredirected_header("Authorization", "Bearer " + token)
        try:
            with open_no_redirect(request, timeout=self.timeout, opener=self.opener) as response:
                raw = read_bounded(response, self.MAX_RESPONSE_BYTES)
                if raw:
                    require_json_content_type(response)
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except HTTPError as exc:
            try:
                raise GitHubAppError("GitHub API returned HTTP " + str(exc.code)) from exc
            finally:
                exc.close()
        except (URLError, TimeoutError) as exc:
            raise GitHubAppError("GitHub API request failed: " + type(exc).__name__) from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubAppError("GitHub API returned malformed JSON") from exc
        except ValueError as exc:
            if "size limit" in str(exc):
                raise GitHubAppError("GitHub API response exceeded size limit") from exc
            raise GitHubAppError("GitHub API response failed validation") from exc
        if not isinstance(data, (dict, list)):
            raise GitHubAppError("GitHub API returned an invalid response shape")
        return data

    @staticmethod
    def _expiry(value: object) -> datetime:
        if not isinstance(value, str):
            raise GitHubAppError("GitHub token response omitted expiry")
        try:
            expiry = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise GitHubAppError("GitHub token expiry is invalid") from exc
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise GitHubAppError("GitHub token is expired or has no timezone")
        return expiry.astimezone(timezone.utc)

    def _installation_catalog_token(self) -> str:
        """Mint an installation-wide metadata token for server-side catalog reads."""
        installation = self._request(
            "POST",
            "/app/installations/{}/access_tokens".format(self.installation_id),
            self._app_jwt(),
            {"permissions": {"metadata": "read"}},
        )
        token = installation.get("token")
        if not isinstance(token, str) or not token:
            raise GitHubAppError("GitHub installation catalog token was not issued")
        self._expiry(installation.get("expires_at"))
        permissions = installation.get("permissions")
        metadata = permissions.get("metadata") if isinstance(permissions, dict) else None
        if metadata not in ("read", "write"):
            raise GitHubAppError("GitHub App installation lacks repository metadata access")
        return token

    def list_installation_repositories(self, refresh: bool = False) -> list[dict]:
        """List repositories installed for DCP, never the user's unrelated repos."""
        now = float(self.clock())
        if (not refresh and self._repository_catalog_cache is not None
                and now < self._repository_catalog_cache_until):
            return [dict(item) for item in self._repository_catalog_cache]

        token = self._installation_catalog_token()
        catalog = []
        seen = set()
        expected_total = None
        for page in range(1, 101):
            data = self._request(
                "GET",
                "/installation/repositories?per_page=100&page={}".format(page),
                token,
            )
            total = data.get("total_count")
            batch = data.get("repositories")
            if isinstance(total, bool) or not isinstance(total, int) or total < 0:
                raise GitHubAppError("GitHub installation repository count is invalid")
            if not isinstance(batch, list) or any(not isinstance(item, dict) for item in batch):
                raise GitHubAppError("GitHub installation repository catalog is invalid")
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                raise GitHubAppError("GitHub installation repository catalog changed during pagination")
            for item in batch:
                full_name = item.get("full_name")
                private = item.get("private")
                default_branch = item.get("default_branch")
                if (not isinstance(full_name, str)
                        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", full_name)
                        or not isinstance(private, bool)
                        or (default_branch is not None and not isinstance(default_branch, str))):
                    raise GitHubAppError("GitHub installation repository metadata is malformed")
                canonical = full_name.lower()
                if canonical in seen:
                    raise GitHubAppError("GitHub installation repository catalog contains duplicates")
                seen.add(canonical)
                permissions = item.get("permissions")
                safe_permissions = {}
                if isinstance(permissions, dict):
                    for key in ("admin", "maintain", "push", "triage", "pull"):
                        if isinstance(permissions.get(key), bool):
                            safe_permissions[key] = permissions[key]
                catalog.append({
                    "full_name": full_name,
                    "private": private,
                    "default_branch": default_branch or "",
                    "permissions": safe_permissions,
                })
            if len(catalog) >= expected_total:
                if len(catalog) != expected_total:
                    raise GitHubAppError("GitHub installation repository count did not match catalog")
                break
            if not batch:
                raise GitHubAppError("GitHub installation repository pagination ended early")
        else:
            raise GitHubAppError("GitHub installation repository catalog exceeded pagination limit")

        # The DCP runner broker is private-repository-only. Public repositories
        # installed on the same GitHub App must never enter its selectable catalog.
        catalog = [item for item in catalog if item["private"] is True]
        catalog.sort(key=lambda item: item["full_name"].lower())
        self._repository_catalog_cache = tuple(dict(item) for item in catalog)
        self._repository_catalog_cache_until = now + 60.0
        return [dict(item) for item in catalog]

    def is_repository_accessible(self, repository: str, refresh: bool = False) -> bool:
        if not isinstance(repository, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository
        ):
            return False
        if (self.allowed_repositories
                and repository.lower() not in {item.lower() for item in self.allowed_repositories}):
            return False
        # A static allowlist is only a narrowing filter, never proof of current
        # installation membership or repository privacy. Require live catalog
        # evidence and fail closed when it is unavailable.
        return any(
            item["private"] is True and item["full_name"].lower() == repository.lower()
            for item in self.list_installation_repositories(refresh=refresh)
        )

    def _installation_token(self, repository: str, administration: str) -> str:
        if not self.is_repository_accessible(repository, refresh=True):
            raise GitHubAppError("Repository is not accessible to the DCP GitHub App installation")
        if administration not in ("read", "write"):
            raise ValueError("Unsupported GitHub repository administration scope")
        app_jwt = self._app_jwt()
        installation = self._request(
            "POST",
            "/app/installations/{}/access_tokens".format(self.installation_id),
            app_jwt,
            {
                "repositories": [repository],
                "permissions": {"administration": administration},
            },
        )
        token = installation.get("token")
        if not isinstance(token, str) or not token:
            raise GitHubAppError("GitHub installation token was not issued")
        permissions = installation.get("permissions")
        granted = permissions.get("administration") if isinstance(permissions, dict) else None
        acceptable = ("read", "write", "admin") if administration == "read" else ("write", "admin")
        if granted not in acceptable:
            raise GitHubAppError("GitHub App installation lacks required Administration permission")
        self._expiry(installation.get("expires_at"))
        return token

    def _repository_contents_token(self, repository: str) -> str:
        """Mint a repository-scoped, read-only token for branch/tag metadata."""
        if not self.is_repository_accessible(repository, refresh=True):
            raise GitHubAppError("Repository is not accessible to the DCP GitHub App installation")
        installation = self._request(
            "POST",
            "/app/installations/{}/access_tokens".format(self.installation_id),
            self._app_jwt(),
            {
                "repositories": [repository],
                "permissions": {"contents": "read"},
            },
        )
        token = installation.get("token")
        if not isinstance(token, str) or not token:
            raise GitHubAppError("GitHub repository contents token was not issued")
        permissions = installation.get("permissions")
        granted = permissions.get("contents") if isinstance(permissions, dict) else None
        if granted not in ("read", "write"):
            raise GitHubAppError("GitHub App installation lacks Contents read permission")
        self._expiry(installation.get("expires_at"))
        return token

    def list_repository_refs(self, repository: str, kind: str = "branches") -> list[dict]:
        """List branch or tag refs using a selected-repository Contents-read token."""
        if kind not in ("branches", "tags"):
            raise GitHubAppError("Unsupported repository ref kind")
        token = self._repository_contents_token(repository)
        owner, name = repository.split("/", 1)
        refs = []
        seen = set()
        for page in range(1, 101):
            data = self._request(
                "GET",
                "/repos/{}/{}/{}?per_page=100&page={}".format(owner, name, kind, page),
                token,
            )
            if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
                raise GitHubAppError("GitHub repository ref response is invalid")
            for item in data:
                ref_name = item.get("name")
                commit = item.get("commit")
                sha = commit.get("sha") if isinstance(commit, dict) else None
                if (not isinstance(ref_name, str) or not 1 <= len(ref_name) <= 255
                        or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", sha)):
                    raise GitHubAppError("GitHub repository ref metadata is malformed")
                key = ref_name
                if key in seen:
                    raise GitHubAppError("GitHub repository ref response contains duplicates")
                seen.add(key)
                refs.append({"name": ref_name, "commit_sha": sha.lower()})
            if len(data) < 100:
                return refs
        raise GitHubAppError("GitHub repository ref inventory exceeded the safe pagination limit")

    def resolve_repository_commit(self, repository: str, commit_sha: str) -> dict:
        """Verify that a full commit SHA resolves inside the selected installed repository."""
        if not isinstance(commit_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit_sha):
            raise GitHubAppError("Commit SHA must be 40 hexadecimal characters")
        token = self._repository_contents_token(repository)
        owner, name = repository.split("/", 1)
        data = self._request(
            "GET",
            "/repos/{}/{}/commits/{}".format(owner, name, commit_sha),
            token,
        )
        if not isinstance(data, dict):
            raise GitHubAppError("GitHub commit response is invalid")
        resolved = data.get("sha")
        if not isinstance(resolved, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", resolved):
            raise GitHubAppError("GitHub commit response omitted a valid SHA")
        if resolved.lower() != commit_sha.lower():
            raise GitHubAppError("GitHub commit response did not match the requested SHA")
        return {"commit_sha": resolved.lower()}

    def inspect_repository_project(self, repository: str, commit_sha: str) -> dict:
        """Inspect bounded Git tree metadata; never download or execute project code."""
        if not isinstance(commit_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit_sha):
            raise GitHubAppError("Commit SHA must be 40 hexadecimal characters")
        token = self._repository_contents_token(repository)
        owner, name = repository.split("/", 1)
        commit = self._request(
            "GET",
            "/repos/{}/{}/commits/{}".format(owner, name, commit_sha),
            token,
        )
        if not isinstance(commit, dict):
            raise GitHubAppError("GitHub commit response is invalid")
        resolved = commit.get("sha")
        commit_data = commit.get("commit")
        tree_data = commit_data.get("tree") if isinstance(commit_data, dict) else None
        tree_sha = tree_data.get("sha") if isinstance(tree_data, dict) else None
        if (not isinstance(resolved, str) or resolved.lower() != commit_sha.lower()
                or not isinstance(tree_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", tree_sha)):
            raise GitHubAppError("GitHub commit tree identity is invalid")
        tree = self._request(
            "GET",
            "/repos/{}/{}/git/trees/{}?recursive=1".format(owner, name, tree_sha),
            token,
        )
        if not isinstance(tree, dict) or not isinstance(tree.get("tree"), list):
            raise GitHubAppError("GitHub repository tree response is invalid")
        entries = tree["tree"]
        truncated = tree.get("truncated")
        if not isinstance(truncated, bool) or any(not isinstance(item, dict) for item in entries):
            raise GitHubAppError("GitHub repository tree metadata is malformed")
        if len(entries) > 20000:
            truncated = True
        paths = set()
        ignored_parts = {
            ".git", ".venv", "venv", "node_modules", "__pycache__", ".dart_tool",
            "build", "dist", "target", "coverage", "pods", "deriveddata", ".gradle",
        }
        for item in entries[:20000]:
            path = item.get("path")
            if (not isinstance(path, str) or not path or path.startswith("/")
                    or any(part in ("", ".", "..") for part in path.split("/"))):
                raise GitHubAppError("GitHub repository tree contains an unsafe path")
            # Symlinks, submodules, and generated dependency/build trees are not
            # treated as project manifests or source files.
            parts = path.split("/")
            if (item.get("type") == "blob" and item.get("mode") != "120000"
                    and not any(part.lower() in ignored_parts for part in parts)):
                paths.add(path)

        pubspecs = sorted(path for path in paths if path.rsplit("/", 1)[-1] == "pubspec.yaml")
        flutter_pubspecs = []
        manifest_scan_incomplete = len(pubspecs) > 20
        for pubspec in ([] if truncated else pubspecs[:20]):
            manifest = self._request(
                "GET",
                "/repos/{}/{}/contents/{}?ref={}".format(
                    owner, name, quote(pubspec, safe="/"), resolved
                ),
                token,
            )
            encoded = manifest.get("content") if isinstance(manifest, dict) else None
            encoding = manifest.get("encoding") if isinstance(manifest, dict) else None
            size = manifest.get("size") if isinstance(manifest, dict) else None
            if (encoding != "base64" or not isinstance(encoded, str)
                    or isinstance(size, bool) or not isinstance(size, int) or size > 256 * 1024):
                manifest_scan_incomplete = True
                continue
            try:
                manifest_bytes = base64.b64decode(re.sub(r"\s+", "", encoded), validate=True)
                if len(manifest_bytes) != size:
                    manifest_scan_incomplete = True
                    continue
                manifest_text = manifest_bytes.decode("utf-8")
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
            prefix = root + "/" if root else ""
            project = prefix + "macos/Runner.xcodeproj/project.pbxproj"
            info = prefix + "macos/Runner/Info.plist"
            if project in paths and info in paths:
                macos_projects.append(project)
        macos_supported = bool(macos_projects)
        if truncated:
            status = "unknown"
            macos_supported_result = None
        elif flutter_pubspecs and macos_supported:
            status = "target_detected"
            macos_supported_result = True
        elif flutter_pubspecs:
            status = "needs_setup"
            macos_supported_result = False
        else:
            status = "detected"
            # A non-Flutter repository is not evidence that a Flutter macOS
            # target is unsupported; this field is not applicable.
            macos_supported_result = None

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

        return {
            "repository": repository,
            "commit_sha": resolved.lower(),
            "status": status,
            "project_types": sorted(project_types),
            "file_count": len(paths),
            "truncated": truncated,
            "flutter": {
                "detected": bool(flutter_pubspecs),
                "package_manifests": flutter_pubspecs,
                "macos_supported": macos_supported_result,
                "macos_runner_projects": macos_projects if not truncated else [],
            },
            "notes": [
                "Inspection reads bounded pubspec manifest metadata and Git tree paths only; no source files are executed.",
                "A Flutter macOS target is detected only when its Runner Xcode project and Info.plist are present.",
                "A truncated tree is UNKNOWN and is never treated as proof that a target is absent.",
            ],
        }

    def create_registration_token(self, repository: str) -> RunnerRegistrationCredential:
        installation_token = self._installation_token(repository, "write")
        owner, name = repository.split("/", 1)
        registration = self._request(
            "POST",
            "/repos/{}/{}/actions/runners/registration-token".format(owner, name),
            installation_token,
            {},
        )
        token = registration.get("token")
        if not isinstance(token, str) or not token:
            raise GitHubAppError("GitHub runner registration token was not issued")
        expiry = self._expiry(registration.get("expires_at"))
        return RunnerRegistrationCredential(token=token, expires_at=expiry)

    def _list_runners(self, repository: str) -> list[dict]:
        token = self._installation_token(repository, "read")
        owner, name = repository.split("/", 1)
        runners = []
        for page in range(1, 11):
            data = self._request(
                "GET",
                "/repos/{}/{}/actions/runners?per_page=100&page={}".format(owner, name, page),
                token,
            )
            batch = data.get("runners")
            if not isinstance(batch, list):
                raise GitHubAppError("GitHub runner inventory response is invalid")
            if any(not isinstance(item, dict) for item in batch):
                raise GitHubAppError("GitHub runner inventory contains an invalid entry")
            runners.extend(batch)
            if len(batch) < 100:
                return runners
        raise GitHubAppError("GitHub runner inventory exceeded the safe pagination limit")

    def find_runner(self, repository: str, runner_name: str) -> dict | None:
        if not isinstance(runner_name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", runner_name):
            raise GitHubAppError("Invalid GitHub runner name")
        runners = self._list_runners(repository)
        matches = [runner for runner in runners if isinstance(runner, dict) and runner.get("name") == runner_name]
        if len(matches) > 1:
            raise GitHubAppError("GitHub returned duplicate runner names")
        if not matches:
            return None
        runner = matches[0]
        runner_id = runner.get("id")
        status = runner.get("status")
        if isinstance(runner_id, bool) or not isinstance(runner_id, int) or runner_id < 1:
            raise GitHubAppError("GitHub runner inventory omitted a valid runner ID")
        if status not in ("online", "offline"):
            raise GitHubAppError("GitHub runner inventory returned an unknown status")
        observed = runner.get("labels")
        labels = tuple(
            item["name"] for item in observed
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        ) if isinstance(observed, list) else ()
        return {"id": runner_id, "name": runner_name, "status": status, "labels": labels}

    def is_runner_online(
        self, repository: str, runner_name: str, expected_labels: list[str] | tuple[str, ...]
    ) -> bool:
        if not isinstance(expected_labels, (list, tuple)):
            raise GitHubAppError("Expected runner labels must be a list or tuple")
        labels = tuple(expected_labels)
        if not labels or any(not isinstance(label, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,64}", label
        ) for label in labels):
            raise GitHubAppError("Invalid expected GitHub runner labels")
        runner = self.find_runner(repository, runner_name)
        return bool(runner and runner["status"] == "online" and set(labels).issubset(set(runner["labels"])))

    def remove_runner(self, repository: str, runner_id: int) -> bool:
        if isinstance(runner_id, bool) or not isinstance(runner_id, int) or runner_id < 1:
            raise GitHubAppError("Invalid GitHub runner ID")
        owner, name = repository.split("/", 1) if self.is_repository_accessible(repository, refresh=True) else ("", "")
        if not owner:
            raise GitHubAppError("Repository is not accessible to the DCP GitHub App installation")
        runners = self._list_runners(repository)
        matches = [runner for runner in runners if isinstance(runner, dict) and runner.get("id") == runner_id]
        if not matches:
            return True
        if len(matches) != 1 or matches[0].get("status") != "offline":
            raise GitHubAppError("Refusing to deregister a runner that is not confirmed offline")
        write_token = self._installation_token(repository, "write")
        self._request(
            "DELETE",
            "/repos/{}/{}/actions/runners/{}".format(owner, name, runner_id),
            write_token,
        )
        return True


class GitHubRunnerOnlineChecker:
    """Adapt provider metadata to an exact GitHub runner-online check."""

    LABELS = {
        "linux": ("self-hosted", "Linux", "X64", "dcp-cloud-linux"),
        "windows": ("self-hosted", "Windows", "X64", "dcp-cloud-windows"),
        "macos": ("self-hosted", "macOS", "ARM64", "dcp-cloud-macos"),
    }

    def __init__(self, github_app: GitHubAppRunnerBootstrap):
        self.github_app = github_app

    def __call__(self, runner_name: str, repository: str, target_os: str) -> bool:
        labels = self.LABELS.get(target_os)
        if labels is None:
            return False
        return self.github_app.is_runner_online(repository, runner_name, labels)
