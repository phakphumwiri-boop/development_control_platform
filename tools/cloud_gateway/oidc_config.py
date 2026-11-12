"""Strict, provider-neutral configuration for a future OIDC authorization-code client.

This module validates configuration only. It does not perform discovery, fetch JWKS,
validate tokens, create sessions, or establish a production trust boundary.
Those operations must be implemented by a separately tested OIDC client.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit


class OIDCConfigurationError(ValueError):
    """Raised when OIDC client configuration is incomplete or unsafe."""


@dataclass(frozen=True)
class OIDCProviderConfig:
    issuer: str
    client_id: str
    redirect_uri: str
    scopes: tuple[str, ...] = ("openid", "profile", "email")

    @property
    def discovery_url(self) -> str:
        return self.issuer.rstrip("/") + "/.well-known/openid-configuration"


def _https_url(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise OIDCConfigurationError(f"{field} must be a non-empty URL")
    try:
        parsed = urlsplit(value)
        # Accessing .port also validates malformed port syntax.
        _ = parsed.port
    except ValueError as exc:
        raise OIDCConfigurationError(f"{field} is malformed") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise OIDCConfigurationError(
            f"{field} must use HTTPS and must not contain credentials, query, or fragment"
        )
    return value.rstrip("/") if field == "issuer" else value


def validate_oidc_config(config: OIDCProviderConfig) -> OIDCProviderConfig:
    """Validate issuer/client/redirect/scopes without contacting an identity provider."""
    if not isinstance(config, OIDCProviderConfig):
        raise OIDCConfigurationError("OIDC configuration object is required")
    issuer = _https_url(config.issuer, "issuer")
    redirect_uri = _https_url(config.redirect_uri, "redirect_uri")
    if not isinstance(config.client_id, str) or not config.client_id:
        raise OIDCConfigurationError("client_id must be a non-empty string")
    if config.client_id != config.client_id.strip() or len(config.client_id) > 512:
        raise OIDCConfigurationError("client_id is malformed")
    if not isinstance(config.scopes, (tuple, list)) or not config.scopes:
        raise OIDCConfigurationError("scopes must be a non-empty sequence")
    scopes = tuple(config.scopes)
    if (
        any(not isinstance(scope, str) or not re.fullmatch(r"[A-Za-z0-9:_-]{1,64}", scope)
            for scope in scopes)
        or len(set(scopes)) != len(scopes)
        or "openid" not in scopes
    ):
        raise OIDCConfigurationError("scopes must be unique valid values and include openid")
    return OIDCProviderConfig(
        issuer=issuer,
        client_id=config.client_id,
        redirect_uri=redirect_uri,
        scopes=scopes,
    )


def oidc_config_from_env(env) -> OIDCProviderConfig:
    """Load non-secret OIDC client settings; never reads or returns a client secret."""
    if not hasattr(env, "get"):
        raise OIDCConfigurationError("environment mapping is required")
    config = OIDCProviderConfig(
        issuer=env.get("DCP_OIDC_ISSUER", ""),
        client_id=env.get("DCP_OIDC_CLIENT_ID", ""),
        redirect_uri=env.get("DCP_OIDC_REDIRECT_URI", ""),
        scopes=tuple(env.get("DCP_OIDC_SCOPES", "openid profile email").split()),
    )
    return validate_oidc_config(config)
