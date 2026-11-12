"""Provider-neutral OpenID Connect discovery, PKCE and ID-token verification.

The module is deliberately transport-injected: callers must provide a TLS-verified
HTTP client with bounded timeouts/response sizes. It never trusts browser-supplied
claims and never exposes tokens or client credentials to browser code.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlencode, urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


class OIDCError(ValueError):
    """Raised for invalid provider metadata, authorization responses or tokens."""


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or any(c not in
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in value):
        raise OIDCError("Invalid base64url value")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise OIDCError("Invalid base64url value") from exc


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _https_endpoint(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise OIDCError(f"Provider metadata is missing {name}")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise OIDCError(f"Provider metadata has invalid {name}") from exc
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise OIDCError(f"Provider metadata {name} must be an HTTPS URL without credentials or fragment")
    return value


@dataclass(frozen=True)
class OIDCMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


class OIDCProvider:
    """Discovery/JWKS client using an injected bounded, TLS-validating JSON fetcher."""

    def __init__(self, issuer: str, fetch_json: Callable[[str], dict]):
        self.issuer = issuer
        self.fetch_json = fetch_json
        self._metadata: OIDCMetadata | None = None
        self._jwks: dict | None = None
        self._jwks_fetched_at = 0.0

    def discover(self) -> OIDCMetadata:
        if self._metadata is not None:
            return self._metadata
        issuer = _https_endpoint(self.issuer, "issuer").rstrip("/")
        document = self.fetch_json(issuer + "/.well-known/openid-configuration")
        if not isinstance(document, dict) or document.get("issuer") != self.issuer:
            raise OIDCError("Discovery issuer does not exactly match configured issuer")
        if "code" not in document.get("response_types_supported", ["code"]):
            raise OIDCError("Provider does not support authorization code flow")
        if "S256" not in document.get("code_challenge_methods_supported", []):
            raise OIDCError("Provider does not advertise PKCE S256 support")
        metadata = OIDCMetadata(
            issuer=self.issuer,
            authorization_endpoint=_https_endpoint(document.get("authorization_endpoint"), "authorization_endpoint"),
            token_endpoint=_https_endpoint(document.get("token_endpoint"), "token_endpoint"),
            jwks_uri=_https_endpoint(document.get("jwks_uri"), "jwks_uri"),
        )
        self._metadata = metadata
        return metadata

    def jwks(self, force_refresh: bool = False) -> dict:
        if self._jwks is None or force_refresh or time.time() - self._jwks_fetched_at > 300:
            document = self.fetch_json(self.discover().jwks_uri)
            if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
                raise OIDCError("JWKS document is invalid")
            if len(document["keys"]) > 100:
                raise OIDCError("JWKS contains too many keys")
            self._jwks = document
            self._jwks_fetched_at = time.time()
        return self._jwks


@dataclass(frozen=True)
class PKCETransaction:
    state: str
    nonce: str
    code_verifier: str
    created_at: int

    @property
    def code_challenge(self) -> str:
        return _b64url_encode(hashlib.sha256(self.code_verifier.encode("ascii")).digest())


def new_pkce_transaction(now: int | None = None) -> PKCETransaction:
    verifier = _b64url_encode(secrets.token_bytes(32))
    return PKCETransaction(
        state=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        code_verifier=verifier,
        created_at=int(time.time()) if now is None else int(now),
    )


def authorization_url(metadata: OIDCMetadata, client_id: str, redirect_uri: str,
                      transaction: PKCETransaction, scopes=("openid", "profile", "email")) -> str:
    if not client_id or not isinstance(client_id, str):
        raise OIDCError("OIDC client ID is required")
    redirect_uri = _https_endpoint(redirect_uri, "redirect_uri")
    if "openid" not in scopes:
        raise OIDCError("openid scope is required")
    query = urlencode({
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": " ".join(scopes),
        "state": transaction.state,
        "nonce": transaction.nonce,
        "code_challenge": transaction.code_challenge,
        "code_challenge_method": "S256",
    })
    separator = "&" if "?" in metadata.authorization_endpoint else "?"
    return metadata.authorization_endpoint + separator + query


def _json_segment(segment: str) -> dict:
    try:
        value = json.loads(_b64url_decode(segment).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OIDCError("JWT segment is not valid JSON") from exc
    if not isinstance(value, dict):
        raise OIDCError("JWT segment must be a JSON object")
    return value


def _jwk_public_key(jwk: dict, algorithm: str):
    if not isinstance(jwk, dict) or jwk.get("use", "sig") != "sig":
        raise OIDCError("JWKS key is not a signing key")
    if jwk.get("alg") not in (None, algorithm):
        raise OIDCError("JWKS key algorithm does not match token")
    if "key_ops" in jwk and "verify" not in jwk["key_ops"]:
        raise OIDCError("JWKS key is not permitted for verification")
    if algorithm == "RS256" and jwk.get("kty") == "RSA":
        n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
        if n.bit_length() < 2048 or e < 3 or e % 2 == 0:
            raise OIDCError("RSA signing key is too weak")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if algorithm == "ES256" and jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    raise OIDCError("Unsupported or mismatched JWKS key type")


def verify_id_token(token: str, provider: OIDCProvider, client_id: str,
                    expected_nonce: str, now: int | None = None, leeway: int = 60) -> dict:
    """Verify RS256/ES256 signature and required OIDC claims; reject algorithm confusion."""
    if not isinstance(token, str) or len(token) > 65536:
        raise OIDCError("ID token is missing or too large")
    parts = token.split(".")
    if len(parts) != 3:
        raise OIDCError("ID token must be a compact JWS")
    header = _json_segment(parts[0])
    claims = _json_segment(parts[1])
    algorithm = header.get("alg")
    kid = header.get("kid")
    if algorithm not in ("RS256", "ES256") or not isinstance(kid, str) or not kid:
        raise OIDCError("ID token uses an unsupported algorithm or has no key ID")
    if header.get("crit") or header.get("b64") is False:
        raise OIDCError("Critical or unencoded JWT headers are not supported")
    keys = provider.jwks().get("keys", [])
    matches = [key for key in keys if isinstance(key, dict) and key.get("kid") == kid]
    if len(matches) != 1:
        keys = provider.jwks(force_refresh=True).get("keys", [])
        matches = [key for key in keys if isinstance(key, dict) and key.get("kid") == kid]
    if len(matches) != 1:
        raise OIDCError("ID token signing key was not found uniquely")
    public_key = _jwk_public_key(matches[0], algorithm)
    signed = (parts[0] + "." + parts[1]).encode("ascii")
    signature = _b64url_decode(parts[2])
    try:
        if algorithm == "RS256":
            public_key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            if len(signature) != 64:
                raise OIDCError("ES256 signature has an invalid length")
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            public_key.verify(encode_dss_signature(r, s), signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise OIDCError("ID token signature is invalid") from exc
    current = int(time.time()) if now is None else int(now)
    if claims.get("iss") != provider.issuer:
        raise OIDCError("ID token issuer mismatch")
    aud = claims.get("aud")
    audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
    if not audiences or client_id not in audiences or any(not isinstance(v, str) for v in audiences):
        raise OIDCError("ID token audience mismatch")
    azp = claims.get("azp")
    if (len(audiences) > 1 and azp != client_id) or (azp is not None and azp != client_id):
        raise OIDCError("ID token authorized party mismatch")
    exp, iat = claims.get("exp"), claims.get("iat")
    nbf = claims.get("nbf", 0)
    numeric = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)
    if (not numeric(exp) or not numeric(iat) or not numeric(nbf)
            or exp <= current - leeway or iat > current + leeway
            or current - iat > 86400 or nbf > current + leeway):
        raise OIDCError("ID token is expired or outside its accepted time window")
    if not isinstance(expected_nonce, str) or not expected_nonce or claims.get("nonce") != expected_nonce:
        raise OIDCError("ID token nonce mismatch")
    if not isinstance(claims.get("sub"), str) or not claims["sub"] or len(claims["sub"]) > 255:
        raise OIDCError("ID token subject is invalid")
    return claims


def exchange_authorization_code(metadata: OIDCMetadata, client_id: str, redirect_uri: str,
                                code: str, transaction: PKCETransaction,
                                post_form: Callable[[str, dict], dict]) -> dict:
    """Exchange an authorization code using PKCE; transport and client auth are injected."""
    if not isinstance(code, str) or not code or len(code) > 4096:
        raise OIDCError("Authorization code is missing or invalid")
    redirect_uri = _https_endpoint(redirect_uri, "redirect_uri")
    response = post_form(metadata.token_endpoint, {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": transaction.code_verifier,
    })
    if not isinstance(response, dict) or not isinstance(response.get("id_token"), str):
        raise OIDCError("Token endpoint did not return an ID token")
    return response
