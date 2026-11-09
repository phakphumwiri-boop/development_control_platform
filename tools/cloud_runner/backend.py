"""DCP workflow client for the canonical multi-platform Cloud Runner Gateway."""
from __future__ import annotations
import json, os, re
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urlparse
from tools.runner_backend.cloud_api import CloudAPIProvider
from tools.runner_backend.manager import RunnerManager, RunnerRequest
from tools.runner_backend.provider import RunnerInstance

_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_TARGET_OSES = {"linux", "windows", "macos"}

@dataclass(frozen=True)
class RunnerSettings:
    endpoint: str
    bearer_token: str = field(repr=False)
    allowed_repositories: tuple[str, ...] = ("phakphum12345/generated-A4-pdf",)
    timeout_seconds: int = 20
    provisioning_enabled: bool = False
    owner_approved: bool = False

    def __post_init__(self):
        parsed = urlparse(self.endpoint)
        try:
            valid = (parsed.scheme == "https" and bool(parsed.hostname) and parsed.username is None
                and parsed.password is None and parsed.path in ("", "/") and not parsed.params
                and not parsed.query and not parsed.fragment
                and (parsed.port is None or 1 <= parsed.port <= 65535))
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("provider URL must be an HTTPS origin without path, query, fragment, or credentials")
        if not isinstance(self.bearer_token, str) or not self.bearer_token.strip():
            raise ValueError("provider bearer token is required")
        if (not self.allowed_repositories or any(not isinstance(r, str) or not _REPOSITORY.fullmatch(r) for r in self.allowed_repositories)
            or len(set(self.allowed_repositories)) != len(self.allowed_repositories)):
            raise ValueError("allowed_repositories must contain unique owner/name values")
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, int) or not 1 <= self.timeout_seconds <= 60:
            raise ValueError("provider timeout must be an integer between 1 and 60 seconds")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None):
        values = os.environ if env is None else env
        raw = values.get("DCP_RUNNER_ALLOWED_REPOSITORIES", "phakphum12345/generated-A4-pdf").strip()
        if raw.startswith("["):
            try: repos = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError("DCP_RUNNER_ALLOWED_REPOSITORIES must be a comma-separated list or JSON array") from exc
        else:
            repos = [x.strip() for x in raw.split(",") if x.strip()]
        if not isinstance(repos, list) or not all(isinstance(x, str) for x in repos):
            raise ValueError("DCP_RUNNER_ALLOWED_REPOSITORIES must contain repository strings")
        try: timeout = int(values.get("DCP_RUNNER_PROVIDER_TIMEOUT", "20"))
        except (TypeError, ValueError) as exc:
            raise ValueError("DCP_RUNNER_PROVIDER_TIMEOUT must be an integer") from exc
        enabled = values.get("DCP_CLOUD_RUNNER_PROVISIONING_ENABLED", "false").lower() == "true"
        approved = values.get("DCP_CLOUD_RUNNER_OWNER_APPROVED", "false").lower() == "true"
        return cls(
            values.get("DCP_RUNNER_PROVIDER_URL", ""),
            values.get("DCP_RUNNER_PROVIDER_TOKEN", ""),
            tuple(repos),
            timeout,
            enabled,
            approved,
        )

@dataclass(frozen=True)
class ProvisionRequest:
    repository: str
    commit_sha: str
    workflow_run_id: int
    target_os: str = "macos"

    def validate(self, settings: RunnerSettings):
        if not isinstance(self.repository, str) or not _REPOSITORY.fullmatch(self.repository):
            raise ValueError("repository must use owner/name form")
        if self.repository not in settings.allowed_repositories:
            raise ValueError("target repository is not on the provider allowlist")
        if not isinstance(self.commit_sha, str) or not _SHA.fullmatch(self.commit_sha):
            raise ValueError("commit_sha must be a full 40-character Git SHA")
        if isinstance(self.workflow_run_id, bool) or not isinstance(self.workflow_run_id, int) or self.workflow_run_id < 1:
            raise ValueError("workflow_run_id must be a positive integer")
        if self.target_os not in _TARGET_OSES:
            raise ValueError("target_os must be one of: linux, windows, macos")

@dataclass(frozen=True)
class ProvisionResult:
    runner_id: str
    state: str
    runner_name: str | None
    labels: tuple[str, ...]
    detail: str | None

def request_provisioning(settings: RunnerSettings, request: ProvisionRequest) -> ProvisionResult:
    if not settings.provisioning_enabled:
        raise RuntimeError("Cloud runner provisioning is disabled")
    if not settings.owner_approved:
        raise RuntimeError("Explicit cloud runner owner approval is required")
    request.validate(settings)
    provider = CloudAPIProvider(base_url=settings.endpoint, token=settings.bearer_token, timeout=settings.timeout_seconds)
    manager = RunnerManager(provider, set(settings.allowed_repositories))
    instance: RunnerInstance = manager.provision(RunnerRequest(
        repository=request.repository, workflow_run_id=request.workflow_run_id,
        commit_sha=request.commit_sha.lower(), target_os=request.target_os))
    return ProvisionResult(instance.provider_id, instance.state, instance.runner_name, instance.labels, instance.detail)
