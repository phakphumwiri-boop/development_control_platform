# OIDC Discovery, JWKS, PKCE and ID-token verification

This module is a provider-neutral server-side building block. It uses the
repository's pinned cryptography dependency and injected HTTP transports.

## Flow contract

1. Validate the configured HTTPS issuer/client/callback with
   `validate_oidc_config`.
2. Fetch `{issuer}/.well-known/openid-configuration` over a TLS-validating
   transport. Require exact issuer equality, Authorization Code support and
   PKCE S256 support; accept only HTTPS authorization, token and JWKS endpoints.
3. Generate unpredictable state, nonce and PKCE verifier. Store the entire
   transaction server-side, bound to the initiating browser session, with a
   short expiry and one-time consumption.
4. Redirect to the discovered authorization endpoint with
   `response_type=code`, `state`, `nonce`, `code_challenge` and
   `code_challenge_method=S256`.
5. On callback, compare state in constant time and consume it exactly once
   before exchanging the code. Send the original exact redirect URI and PKCE
   verifier to the token endpoint.
6. Verify the ID-token JWS signature against the discovered JWKS. Only RS256
   and ES256 are supported; `none`, algorithm confusion, missing/ambiguous
   key IDs, weak RSA keys, and critical/unencoded headers are rejected.
7. Validate exact issuer, audience, authorized party, expiry, issue time,
   not-before, nonce and subject before creating an authenticated server-side
   session. Never pass unverified claims to the Gateway assertion signer.

## Transport requirements

The injected JSON/form transports must use certificate verification, bounded
timeouts, redirects disabled (or constrained to the same trusted origin),
strict response-size limits and JSON content-type checks. The module does not
perform network I/O itself and therefore cannot silently follow an attacker
redirect. Never use an untrusted URL supplied by a browser as an endpoint.

## Not a production login switch

This library does not by itself provide a public callback server, durable
transaction store, browser cookie, account lifecycle, or deployed reverse
proxy. The production deployment must persist and consume state/nonce
transactions atomically, rotate and revoke sessions, issue Secure/HttpOnly
cookies on a same-origin HTTPS host, and strip all external `X-DCP-*`
headers before signing a fresh internal assertion. GitHub Pages alone cannot
host that server-side flow. No provider tenant, client credentials, callback
registration or production integration is assumed by this change.
