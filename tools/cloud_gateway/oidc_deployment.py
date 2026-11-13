"""Fail-closed composition factory for mounting the OIDC WSGI app in a host.

Network transports and confidential-client authentication are deliberately injected
by the deployment. This module never creates an HTTP client or reads a client secret.
"""
from __future__ import annotations

from .oidc_auth_service import OIDCAuthService
from .oidc_client import OIDCProvider
from .oidc_config import OIDCConfigurationError, oidc_config_from_env
from .oidc_session_store import OIDCSessionStore
from .oidc_wsgi import create_oidc_wsgi_app


def _required(env, name: str) -> str:
    value = env.get(name, "")
    if not isinstance(value, str) or not value or value != value.strip():
        raise OIDCConfigurationError(f"{name} must be configured")
    return value


def _group_ids(env, name: str) -> tuple[str, ...]:
    raw = _required(env, name)
    values = tuple(part.strip() for part in raw.split(","))
    if (not values or any(not value or len(value) > 256 for value in values)
            or len(set(values)) != len(values)):
        raise OIDCConfigurationError(f"{name} must contain unique comma-separated group IDs")
    return values


def create_oidc_wsgi_app_from_env(env, *, fetch_json, post_form):
    """Build the production OIDC WSGI application from explicit deployment inputs.

    fetch_json(url) and post_form(url, form) must be supplied by the host and use
    TLS certificate validation, strict timeouts, bounded response sizes, and
    provider-specific confidential-client authentication where required.
    No default transport is provided, so this factory cannot silently make
    unaudited outbound requests or guess client authentication behavior.
    """
    if not hasattr(env, "get"):
        raise OIDCConfigurationError("environment mapping is required")
    if not callable(fetch_json) or not callable(post_form):
        raise OIDCConfigurationError("TLS-verified discovery and token transports are required")

    config = oidc_config_from_env(env)
    public_origin = _required(env, "DCP_PUBLIC_ORIGIN")
    database = _required(env, "DCP_OIDC_SESSION_DB_PATH")
    if database == ":memory:":
        raise OIDCConfigurationError("DCP_OIDC_SESSION_DB_PATH must be durable")
    owner_groups = _group_ids(env, "DCP_OIDC_OWNER_GROUPS")
    operator_groups = _group_ids(env, "DCP_OIDC_OPERATOR_GROUPS")
    if set(owner_groups) & set(operator_groups):
        raise OIDCConfigurationError("Owner and operator group IDs must not overlap")

    session_ttl_raw = env.get("DCP_OIDC_SESSION_TTL_SECONDS", "43200")
    try:
        if not isinstance(session_ttl_raw, str) or not session_ttl_raw.isdigit():
            raise ValueError
        session_ttl = int(session_ttl_raw)
    except ValueError as exc:
        raise OIDCConfigurationError("DCP_OIDC_SESSION_TTL_SECONDS must be an integer") from exc
    if not 300 <= session_ttl <= 86400:
        raise OIDCConfigurationError("DCP_OIDC_SESSION_TTL_SECONDS must be 300..86400")

    provider = OIDCProvider(config.issuer, fetch_json)
    sessions = OIDCSessionStore(database, session_ttl=session_ttl)
    auth = OIDCAuthService(
        config, provider, sessions, post_form, owner_groups, operator_groups
    )
    return create_oidc_wsgi_app(
        auth, public_origin,
        post_login_path=env.get("DCP_OIDC_POST_LOGIN_PATH", "/"),
    )
