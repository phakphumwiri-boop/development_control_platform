"""Authenticated, control-plane-only client for the DCP local Runner Agent."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


_WORKER_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
_ERROR_CODE = re.compile(r"^[A-Z0-9_]{1,64}$")


class _NoRedirect(HTTPRedirectHandler):
    """Never forward a Runner credential to a redirected origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RunnerGatewayError(RuntimeError):
    """Sanitized Gateway transport or contract error."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class RunnerAgentConfig:
    gateway_url: str
    worker_id: str
    token: str = field(repr=False)
    timeout_seconds: int = 20

    def __post_init__(self):
        parsed = urlparse(self.gateway_url)
        try:
            loopback_http = (
                parsed.scheme == "http"
                and parsed.hostname in ("127.0.0.1", "localhost", "::1")
            )
            secure_origin = parsed.scheme == "https" or loopback_http
            valid_origin = (
                secure_origin
                and bool(parsed.hostname)
                and parsed.username is None
                and parsed.password is None
                and parsed.path in ("", "/")
                and not parsed.params
                and not parsed.query
                and not parsed.fragment
                and (parsed.port is None or 1 <= parsed.port <= 65535)
            )
        except ValueError:
            valid_origin = False
        if not valid_origin:
            raise ValueError(
                "DCP_GATEWAY_URL must be an HTTPS origin (HTTP is allowed only on loopback)"
            )
        if not isinstance(self.worker_id, str) or not _WORKER_ID.fullmatch(self.worker_id):
            raise ValueError("DCP_RUNNER_WORKER_ID is invalid")
        if not isinstance(self.token, str) or len(self.token) < 32:
            raise ValueError("DCP_RUNNER_TOKEN must contain at least 32 characters")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or not 1 <= self.timeout_seconds <= 60
        ):
            raise ValueError("DCP_RUNNER_TIMEOUT_SECONDS must be between 1 and 60")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "RunnerAgentConfig":
        env = os.environ if environ is None else environ
        raw_timeout = env.get("DCP_RUNNER_TIMEOUT_SECONDS", "20")
        try:
            timeout = int(raw_timeout)
        except (TypeError, ValueError) as exc:
            raise ValueError("DCP_RUNNER_TIMEOUT_SECONDS must be an integer") from exc
        return cls(
            gateway_url=env.get("DCP_GATEWAY_URL", ""),
            worker_id=env.get("DCP_RUNNER_WORKER_ID", ""),
            token=env.get("DCP_RUNNER_TOKEN", ""),
            timeout_seconds=timeout,
        )


class GatewayClient:
    """Small standard-library HTTP client; never executes a claimed job."""

    def __init__(self, config: RunnerAgentConfig):
        self.config = config
        self.base_url = config.gateway_url.rstrip("/")

    def _request(self, method: str, path: str, payload=None, authenticated=True):
        headers = {"Accept": "application/json"}
        data = None
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if authenticated:
            headers["Authorization"] = "Bearer " + self.config.token
        request = Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with build_opener(_NoRedirect).open(
                request, timeout=self.config.timeout_seconds
            ) as response:
                raw = response.read(32769)
                if len(raw) > 32768:
                    raise RunnerGatewayError("Gateway response exceeded the 32 KiB limit")
        except HTTPError as exc:
            raise RunnerGatewayError(
                "Gateway rejected the Runner Agent request", status_code=exc.code
            ) from None
        except URLError:
            raise RunnerGatewayError("Gateway connection failed") from None
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RunnerGatewayError("Gateway returned an invalid JSON response") from None
        if not isinstance(result, dict):
            raise RunnerGatewayError("Gateway response must be a JSON object")
        return result

    def health(self) -> dict:
        """Read non-secret Gateway health metadata; this endpoint is intentionally public."""
        return self._request("GET", "/healthz", authenticated=False)

    def claim(self, lease_seconds: int = 30) -> dict | None:
        self._validate_lease(lease_seconds)
        result = self._request(
            "POST", "/v1/runner/claim", {"lease_seconds": lease_seconds}
        )
        job = result.get("job")
        if job is not None and not isinstance(job, dict):
            raise RunnerGatewayError("Gateway returned an invalid claimed job")
        return job

    def heartbeat(self, job_id: str, lease_seconds: int = 30) -> dict:
        self._validate_job_id(job_id)
        self._validate_lease(lease_seconds)
        return self._request(
            "POST", f"/v1/runner/{job_id}/heartbeat",
            {"lease_seconds": lease_seconds},
        )

    def append_log(self, job_id: str, message: str, stream: str = "system") -> dict:
        self._validate_job_id(job_id)
        if stream not in ("stdout", "stderr", "system"):
            raise ValueError("stream must be stdout, stderr, or system")
        if not isinstance(message, str) or not message or len(message.encode("utf-8")) > 8192:
            raise ValueError("message must contain 1..8192 UTF-8 bytes")
        return self._request(
            "POST", f"/v1/runner/{job_id}/logs",
            {"message": message, "stream": stream},
        )

    def upload_artifact(self, job_id: str, file_path: str, name: str | None = None,
                        max_bytes: int = 100 * 1024 * 1024) -> dict:
        """Upload one bounded regular file over the authenticated Runner channel."""
        self._validate_job_id(job_id)
        from pathlib import Path
        import re
        path = Path(file_path)
        if path.is_symlink() or not path.is_file():
            raise ValueError("artifact path must be a regular file")
        artifact_name = path.name if name is None else name
        if not isinstance(artifact_name, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", artifact_name
        ):
            raise ValueError("invalid artifact filename")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= 1024 * 1024 * 1024:
            raise ValueError("max_bytes must be between 1 byte and 1 GiB")
        size = path.stat().st_size
        if not 1 <= size <= max_bytes:
            raise ValueError("artifact size is outside allowed bounds")
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
        if len(data) != size or len(data) > max_bytes:
            raise ValueError("artifact changed or exceeded its size limit")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/octet-stream",
            "Content-Length": str(size),
            "X-DCP-Artifact-Name": artifact_name,
            "Authorization": "Bearer " + self.config.token,
        }
        request = Request(
            self.base_url + f"/v1/runner/{job_id}/artifacts",
            data=data, headers=headers, method="POST",
        )
        try:
            with build_opener(_NoRedirect).open(
                request, timeout=self.config.timeout_seconds
            ) as response:
                raw = response.read(32769)
                if len(raw) > 32768:
                    raise RunnerGatewayError("Gateway response exceeded the 32 KiB limit")
        except HTTPError as exc:
            raise RunnerGatewayError(
                "Gateway rejected the artifact upload", status_code=exc.code
            ) from None
        except URLError:
            raise RunnerGatewayError("Gateway artifact upload failed") from None
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RunnerGatewayError("Gateway returned an invalid artifact response") from None
        if not isinstance(result, dict) or not isinstance(result.get("artifact"), dict):
            raise RunnerGatewayError("Gateway returned an invalid artifact response")
        return result["artifact"]

    def finish(
        self, job_id: str, outcome: str, result: dict | None = None,
        error_code: str | None = None,
    ) -> dict:
        self._validate_job_id(job_id)
        if outcome not in ("succeeded", "failed", "cancelled"):
            raise ValueError("invalid terminal outcome")
        if result is not None and not isinstance(result, dict):
            raise ValueError("result must be an object")
        if error_code is not None and (
            not isinstance(error_code, str) or not _ERROR_CODE.fullmatch(error_code)
        ):
            raise ValueError("invalid error_code")
        payload = {"outcome": outcome}
        if result is not None:
            payload["result"] = result
        if error_code is not None:
            payload["error_code"] = error_code
        return self._request("POST", f"/v1/runner/{job_id}/finish", payload)

    @staticmethod
    def _validate_lease(lease_seconds: int):
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, int)
            or not 5 <= lease_seconds <= 300
        ):
            raise ValueError("lease_seconds must be an integer between 5 and 300")

    @staticmethod
    def _validate_job_id(job_id: str):
        if not isinstance(job_id, str) or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            job_id,
        ):
            raise ValueError("invalid job UUID")
