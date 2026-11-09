"""Opt-in, read-only smoke test for a deployed DCP Gateway.

This probe performs only GET requests. It never creates, lists, or terminates
runner resources and requires the live gateway to report provisioning disabled.
"""
from __future__ import annotations

import json
import os
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class RejectRedirects(HTTPRedirectHandler):
    """Do not follow redirects with an API bearer credential."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_gateway_origin(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("DCP_LIVE_GATEWAY_URL is required")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Live Gateway URL must be an HTTPS origin without credentials or path")
    return urlunsplit(("https", parsed.netloc, "", "", ""))


def run_readonly_preflight(base_url: str, bearer_token: str, opener=None) -> dict:
    """Verify HTTPS health and bearer authentication without mutating state."""
    origin = validate_gateway_origin(base_url)
    if not isinstance(bearer_token, str) or not bearer_token.strip():
        raise ValueError("DCP_LIVE_GATEWAY_API_TOKEN is required")
    open_request = opener or build_opener(RejectRedirects()).open

    health = Request(
        origin + "/healthz",
        headers={"Accept": "application/json", "User-Agent": "DCP-Live-ReadOnly-Smoke/1.0"},
        method="GET",
    )
    try:
        with open_request(health, timeout=10) as response:
            if response.status != 200:
                raise RuntimeError("Gateway health endpoint returned an unexpected status")
            raw = response.read(4097)
    except HTTPError as exc:
        try:
            raise RuntimeError("Gateway health request failed: " + type(exc).__name__) from exc
        finally:
            exc.close()
    except (URLError, TimeoutError) as exc:
        raise RuntimeError("Gateway health request failed: " + type(exc).__name__) from exc
    if len(raw) > 4096:
        raise RuntimeError("Gateway health response exceeded the size limit")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Gateway health response is not valid JSON") from exc
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        raise RuntimeError("Gateway health response did not confirm status=ok")
    if payload.get("provisioning_enabled") is not False:
        raise RuntimeError("Live provisioning must remain disabled during read-only smoke tests")

    # A unique, deliberately nonexistent ID exercises bearer authentication.
    # GET on an absent row returns 404 without invoking any provider adapter.
    sentinel = "dcp-live-preflight-" + uuid.uuid4().hex
    lookup = Request(
        origin + "/v1/runners/" + sentinel,
        headers={
            "Accept": "application/json",
            "Authorization": "Bearer " + bearer_token,
            "User-Agent": "DCP-Live-Read-Only-Smoke/1.0",
        },
        method="GET",
    )
    try:
        with open_request(lookup, timeout=10) as response:
            raise RuntimeError(
                "Authenticated sentinel lookup unexpectedly returned HTTP "
                + str(response.status)
            )
    except HTTPError as exc:
        try:
            if exc.code != 404:
                raise RuntimeError(
                    "Gateway bearer-authenticated sentinel lookup failed with HTTP "
                    + str(exc.code)
                ) from exc
        finally:
            exc.close()
    except (URLError, TimeoutError) as exc:
        raise RuntimeError("Gateway authenticated lookup failed: " + type(exc).__name__) from exc

    return {
        "health": "PASS",
        "bearer_auth": "PASS",
        "provisioning_enabled": False,
        "operations": ["GET /healthz", "GET /v1/runners/{random-nonexistent-id}"],
        "provider_live_checks": "SKIPPED",
    }


def main() -> int:
    base_url = os.environ.get("DCP_LIVE_GATEWAY_URL", "")
    bearer_token = os.environ.get("DCP_LIVE_GATEWAY_API_TOKEN", "")
    try:
        result = run_readonly_preflight(base_url, bearer_token)
    except Exception as exc:
        # Exception messages are intentionally sanitized; never print the URL
        # or bearer token.
        print("FAIL: " + str(exc))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
