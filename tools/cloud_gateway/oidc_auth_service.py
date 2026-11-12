"""OIDC authorization-code callback orchestration over durable server-side state."""
from __future__ import annotations

import hmac
import time
from urllib.parse import parse_qs, urlsplit

from .oidc_assertion import map_oidc_groups
from .oidc_client import (
    OIDCError, OIDCProvider, authorization_url, exchange_authorization_code,
    new_pkce_transaction, verify_id_token,
)
from .oidc_config import OIDCProviderConfig, validate_oidc_config
from .oidc_session_store import OIDCSessionStore


class OIDCAuthService:
    """Provider-neutral login service; caller owns secure cookie and HTTP transport."""

    def __init__(self, config: OIDCProviderConfig, provider: OIDCProvider,
                 sessions: OIDCSessionStore, post_form, owner_groups, operator_groups):
        self.config = validate_oidc_config(config)
        if provider.issuer != self.config.issuer:
            raise OIDCError("OIDC provider and client configuration issuer differ")
        if not owner_groups or not operator_groups or set(owner_groups) & set(operator_groups):
            raise OIDCError("Distinct owner and operator group mappings are required")
        self.provider = provider
        self.sessions = sessions
        self.post_form = post_form
        self.owner_groups = tuple(owner_groups)
        self.operator_groups = tuple(operator_groups)

    def begin_login(self, browser_binding: str, now: int | None = None) -> str:
        metadata = self.provider.discover()
        transaction = new_pkce_transaction(now)
        self.sessions.save_transaction(transaction.state, transaction.nonce,
                                        transaction.code_verifier, browser_binding, now)
        return authorization_url(metadata, self.config.client_id, self.config.redirect_uri,
                                 transaction, self.config.scopes)

    def complete_callback(self, query_string: str, browser_binding: str,
                          now: int | None = None) -> tuple[str, dict]:
        params = parse_qs(query_string, keep_blank_values=True, strict_parsing=False)
        states, codes, errors = params.get("state", []), params.get("code", []), params.get("error", [])
        if len(states) != 1 or not states[0]:
            raise OIDCError("OIDC callback must contain exactly one state")
        # Consume before checking provider error/code, so callback attempts cannot be replayed.
        try:
            transaction = self.sessions.consume_transaction(states[0], browser_binding, now)
        except Exception as exc:
            raise OIDCError("OIDC callback state validation failed") from exc
        if errors:
            raise OIDCError("Identity provider rejected the authorization request")
        if len(codes) != 1 or not codes[0]:
            raise OIDCError("OIDC callback must contain exactly one authorization code")
        metadata = self.provider.discover()
        from .oidc_client import PKCETransaction
        tx = PKCETransaction(states[0], transaction["nonce"], transaction["code_verifier"],
                             int(time.time()) if now is None else int(now))
        tokens = exchange_authorization_code(metadata, self.config.client_id,
                                             self.config.redirect_uri, codes[0], tx,
                                             self.post_form)
        claims = verify_id_token(tokens["id_token"], self.provider, self.config.client_id,
                                 transaction["nonce"], now)
        role = map_oidc_groups(claims.get("groups"), self.owner_groups, self.operator_groups)
        session_id, session = self.sessions.create_session(claims["sub"], role, now)
        # Return only a server-side session handle and non-secret identity metadata.
        return session_id, {"subject": session["subject"], "role": session["role"],
                            "csrf_token": session["csrf_token"], "expires_at": session["expires_at"]}

    def logout(self, session_id: str) -> bool:
        return self.sessions.revoke_session(session_id)
