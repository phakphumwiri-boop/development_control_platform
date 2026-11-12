"""Read-only, fixed-target GitHub data adapter for Recon Back Box.

This module deliberately exposes only public metadata from one repository. It
never accepts an arbitrary host, repository, ref, path, token, or write method.
"""
from __future__ import annotations

import base64
import json
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPOSITORY = "phakphum12345/Drive-letter"
API_ROOT = "https://api.github.com"
CONFIG_FILES = frozenset({
    "recon-back-box.config.json",
    "artifact-intake.config.json",
    "website-learning.config.json",
    "recon-policy.config.json",
})
MAX_CONFIG_BYTES = 128 * 1024


class ReconAPIError(Exception):
    def __init__(self, status: int, public_message: str):
        super().__init__(public_message)
        self.status = status
        self.public_message = public_message


def resolve_recon_url(path: str) -> str:
    """Resolve an approved UI route to a fixed public GitHub API URL."""
    prefix = "/api/recon/"
    if not isinstance(path, str) or not path.startswith(prefix):
        raise ReconAPIError(404, "Recon resource not found")
    route = path[len(prefix):]
    root = f"{API_ROOT}/repos/{REPOSITORY}"

    if route == "repository":
        return root
    if route == "actions/runs":
        return root + "/actions/runs?per_page=20"
    if route == "pulls":
        return root + "/pulls?state=open&per_page=100"

    match = re.fullmatch(r"pulls/([1-9][0-9]{0,8})", route)
    if match:
        return root + "/pulls/" + match.group(1)

    match = re.fullmatch(r"actions/runs/([1-9][0-9]{0,18})/artifacts", route)
    if match:
        return root + "/actions/runs/" + match.group(1) + "/artifacts"

    match = re.fullmatch(r"config/([A-Za-z0-9_.-]{1,100})", route)
    if match and match.group(1) in CONFIG_FILES:
        return (root + "/contents/current/recon-back-box/config/"
                + match.group(1) + "?ref=main")

    raise ReconAPIError(404, "Recon resource not found")


def _read_upstream(url: str) -> dict:
    request = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "DCP-Recon-Back-Box",
    }, method="GET")
    try:
        with urlopen(request, timeout=8) as response:
            raw = response.read(MAX_CONFIG_BYTES + 1)
            if len(raw) > MAX_CONFIG_BYTES:
                raise ReconAPIError(502, "Recon upstream response exceeded its size limit")
    except HTTPError as exc:
        if exc.code == 404:
            raise ReconAPIError(404, "Recon source record not found") from exc
        if exc.code == 403:
            raise ReconAPIError(503, "GitHub public API rate limit or access restriction") from exc
        raise ReconAPIError(502, "Recon source service returned an error") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ReconAPIError(502, "Recon source service is temporarily unavailable") from exc

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReconAPIError(502, "Recon source returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ReconAPIError(502, "Recon source returned an unexpected response")
    return value


def fetch_recon_resource(path: str) -> dict:
    """Fetch one allowlisted public resource; configuration is decoded JSON."""
    url = resolve_recon_url(path)
    value = _read_upstream(url)
    if path.startswith("/api/recon/config/"):
        if value.get("encoding") != "base64" or not isinstance(value.get("content"), str):
            raise ReconAPIError(502, "Recon config content is unavailable")
        try:
            encoded = "".join(value["content"].split())
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) > MAX_CONFIG_BYTES:
                raise ValueError("config too large")
            config = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReconAPIError(502, "Recon config is not valid JSON") from exc
        if not isinstance(config, dict):
            raise ReconAPIError(502, "Recon config must be a JSON object")
        return config
    return value
