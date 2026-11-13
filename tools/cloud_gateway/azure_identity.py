"""Minimal Azure Managed Identity token client; no client secrets are supported."""
from __future__ import annotations

import json
import os
import re
import time
from urllib.parse import urlencode, urlsplit
from urllib.request import Request

from .safe_http import open_no_redirect, read_bounded, require_json_content_type


def urlopen(request, timeout=3):
    """Compatibility seam backed by the production no-redirect transport."""
    return open_no_redirect(request, timeout=timeout)


class IdentityError(RuntimeError):
    pass


class ManagedIdentityCredential:
    MAX_RESPONSE_BYTES = 64 * 1024

    def __init__(self, env=None, timeout=3, *, opener=None, clock=time.time):
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 30:
            raise ValueError("Managed identity timeout must be 1..30 seconds")
        self.env = os.environ if env is None else env
        self.timeout = timeout
        self.opener = opener
        self.clock = clock

    @staticmethod
    def _resource(value):
        if not isinstance(value, str) or value != value.strip() or len(value) > 2048:
            raise IdentityError("Invalid managed identity resource")
        try:
            parsed = urlsplit(value)
            _ = parsed.port
        except ValueError as exc:
            raise IdentityError("Invalid managed identity resource") from exc
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment):
            raise IdentityError("Managed identity resource must be an HTTPS URI")
        return value

    def _endpoint(self):
        endpoint = self.env.get("IDENTITY_ENDPOINT")
        if endpoint:
            try:
                parsed = urlsplit(endpoint)
                _ = parsed.port
            except (TypeError, ValueError) as exc:
                raise IdentityError("Untrusted managed identity endpoint configuration") from exc
            if (parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1")
                    or parsed.username is not None or parsed.password is not None
                    or parsed.fragment or parsed.query or not parsed.path.startswith("/")
                    or not self.env.get("IDENTITY_HEADER")):
                raise IdentityError("Untrusted managed identity endpoint configuration")
            identity_header = self.env["IDENTITY_HEADER"]
            if (not isinstance(identity_header, str) or not identity_header
                    or len(identity_header) > 4096 or "\r" in identity_header or "\n" in identity_header):
                raise IdentityError("Untrusted managed identity endpoint configuration")
            return endpoint, identity_header

        if self.env.get("DCP_AZURE_USE_IMDS", "false").lower() == "true":
            return "http://169.254.169.254/metadata/identity/oauth2/token", None
        raise IdentityError("Managed identity endpoint is unavailable; refusing client-secret fallback")

    def get_token(self, resource):
        resource = self._resource(resource)
        endpoint, identity_header = self._endpoint()
        params = {"api-version": "2019-08-01" if identity_header else "2018-02-01",
                  "resource": resource}
        client_id = self.env.get("AZURE_CLIENT_ID", "")
        if client_id:
            if not isinstance(client_id, str) or len(client_id) > 256 or "\r" in client_id or "\n" in client_id:
                raise IdentityError("Invalid managed identity client ID")
            params["client_id"] = client_id
        url = endpoint + "?" + urlencode(params)
        try:
            request = Request(url, headers={"Metadata": "true"}, method="GET")
            if identity_header:
                request.add_unredirected_header("X-IDENTITY-HEADER", identity_header)
            response_context = (urlopen(request, timeout=self.timeout) if self.opener is None
                                else open_no_redirect(request, timeout=self.timeout, opener=self.opener))
            with response_context as response:
                require_json_content_type(response)
                raw = read_bounded(response, self.MAX_RESPONSE_BYTES)
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise IdentityError("Managed identity token request failed: " + type(exc).__name__) from exc
        if not isinstance(data, dict):
            raise IdentityError("Managed identity returned an invalid response")
        token = data.get("access_token")
        token_type = data.get("token_type")
        expires_on = data.get("expires_on")
        if not isinstance(token, str) or not token or len(token) > self.MAX_RESPONSE_BYTES:
            raise IdentityError("Managed identity returned no valid access token")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise IdentityError("Managed identity returned an invalid token type")
        if not (isinstance(expires_on, (str, int)) and not isinstance(expires_on, bool)
                and re.fullmatch(r"[0-9]{1,16}", str(expires_on))):
            raise IdentityError("Managed identity returned an invalid token expiry")
        if int(expires_on) <= int(self.clock()):
            raise IdentityError("Managed identity returned an expired access token")
        return token
