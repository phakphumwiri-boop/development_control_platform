"""Small bounded HTTP primitives for secret and credential transports."""
from __future__ import annotations

from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, build_opener


class NoRedirectHandler(HTTPRedirectHandler):
    """Reject redirects so credentials and secret-bearing requests stay on-origin."""

    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def open_no_redirect(request, *, timeout: int, opener=None):
    """Open one request without following redirects; opener is injectable for tests."""
    if opener is not None:
        return opener(request, timeout=timeout)
    return build_opener(NoRedirectHandler()).open(request, timeout=timeout)


def read_bounded(response, limit: int) -> bytes:
    """Read at most limit bytes and fail if the peer sends more."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("response limit must be a positive integer")
    raw = response.read(limit + 1)
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise ValueError("HTTP response exceeded its size limit")
    return raw


def require_json_content_type(response) -> None:
    """Require a JSON media type before parsing an HTTP response."""
    headers = getattr(response, "headers", None)
    content_type = headers.get("Content-Type", "") if headers is not None else ""
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type != "application/json" and not (
        media_type.startswith("application/") and media_type.endswith("+json")
    ):
        raise ValueError("HTTP response did not declare a JSON content type")
