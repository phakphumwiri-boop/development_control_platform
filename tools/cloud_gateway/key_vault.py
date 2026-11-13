"""Read-only Azure Key Vault secret access using Managed Identity."""
from __future__ import annotations

import json
import re
from urllib.parse import quote, urlsplit
from urllib.request import Request

from .azure_identity import ManagedIdentityCredential
from .safe_http import open_no_redirect, read_bounded, require_json_content_type


def urlopen(request, timeout=5):
    """Compatibility seam backed by the production no-redirect transport."""
    return open_no_redirect(request, timeout=timeout)


class KeyVaultError(RuntimeError):
    pass


_SECRET = re.compile(r"^[A-Za-z0-9-]{1,127}$")
_VERSION = re.compile(r"^[A-Za-z0-9-]{1,128}$")


class KeyVaultSecretReader:
    MAX_RESPONSE_BYTES = 64 * 1024

    def __init__(self, vault_url, credential=None, timeout=5, *, opener=None):
        try:
            parsed = urlsplit(vault_url)
            _ = parsed.port
        except (TypeError, ValueError) as exc:
            raise ValueError("Key Vault URL must be an HTTPS Azure vault origin") from exc
        if (parsed.scheme != "https" or not parsed.hostname
                or not parsed.hostname.lower().endswith(".vault.azure.net")
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                or parsed.username or parsed.password):
            raise ValueError("Key Vault URL must be an HTTPS Azure vault origin")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 30:
            raise ValueError("Key Vault timeout must be 1..30 seconds")
        self.base = vault_url.rstrip("/")
        self.credential = credential or ManagedIdentityCredential()
        self.timeout = timeout
        self.opener = opener

    def get_secret(self, name, version=""):
        if not isinstance(name, str) or not _SECRET.fullmatch(name):
            raise ValueError("Invalid Key Vault secret name")
        if version and (not isinstance(version, str) or not _VERSION.fullmatch(version)):
            raise ValueError("Invalid Key Vault secret version")
        suffix = "/secrets/" + quote(name, safe="")
        if version:
            suffix += "/" + quote(version, safe="")
        try:
            token = self.credential.get_token("https://vault.azure.net")
            if not isinstance(token, str) or not token or len(token) > self.MAX_RESPONSE_BYTES:
                raise ValueError("Managed identity returned an invalid token")
            request = Request(
                self.base + suffix + "?api-version=7.4",
                headers={"Accept": "application/json"},
                method="GET",
            )
            request.add_unredirected_header("Authorization", "Bearer " + token)
            response_context = (urlopen(request, timeout=self.timeout) if self.opener is None
                                else open_no_redirect(request, timeout=self.timeout, opener=self.opener))
            with response_context as response:
                require_json_content_type(response)
                raw = read_bounded(response, self.MAX_RESPONSE_BYTES)
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise KeyVaultError("Key Vault read failed: " + type(exc).__name__) from exc
        value = data.get("value") if isinstance(data, dict) else None
        if not isinstance(value, str) or not value or len(value) > self.MAX_RESPONSE_BYTES:
            raise KeyVaultError("Key Vault response did not contain a valid secret value")
        return value
