# OIDC ingress and trusted identity assertions

## Deployment shape

```text
Browser
  -> HTTPS reverse proxy / OIDC middleware
       -> Authorization Code + PKCE, state, nonce, exact callback URI
       -> server-managed Secure + HttpOnly session cookie
       -> verified OIDC claims (sub + groups)
       -> DCP assertion signer (private network only)
            -> per-request HMAC identity headers
            -> DCP Gateway (same public HTTPS origin)
                 -> CSRF + Origin + role + replay checks
```

GitHub Pages is static hosting and cannot issue server-side session cookies or
run an OIDC callback. Serve the dashboard and `/api/*` behind one HTTPS origin
using a reverse proxy, or use a host that serves both. Do not configure the
browser to send credentials to a different API origin and assume cookies are
same-origin.

## OIDC middleware contract

The upstream OIDC middleware is responsible for validating the provider's JWT
signature against its JWKS, exact issuer, audience, expiry, issue time, state,
nonce, and exact redirect URI. Use Authorization Code flow with PKCE. The
middleware must create and rotate a random server-side session ID, and set a
`Secure; HttpOnly; SameSite=Lax` (or stricter compatible) cookie. Do not return
ID tokens, access tokens, refresh tokens, client secrets, or the HMAC secret to
browser JavaScript.

Pass only the already-verified claims to
`sign_verified_oidc_assertion`. The helper re-checks issuer, audience, exp,
iat, subject format and group-to-role mapping, then signs a request-bound
assertion. **It does not verify the OIDC JWT signature itself.** It must never
be called with claims supplied directly by the browser or an untrusted header.

Use the stable OIDC `sub` claim as `X-DCP-User`; do not use email as a durable
account identifier. Map explicit verified groups:
- `DCP_OIDC_OWNER_GROUPS` -> `owner`
- `DCP_OIDC_OPERATOR_GROUPS` -> `operator`
- No matching group -> deny
- Owner wins if a user belongs to both groups

The proxy signer generates a fresh nonce for every request and binds the HTTP
method, URL path, subject, role, session ID, timestamp and nonce using
HMAC-SHA256. It emits only these internal headers:
- `X-DCP-User`
- `X-DCP-Role`
- `X-DCP-Session`
- `X-DCP-Auth-Timestamp`
- `X-DCP-Auth-Nonce`
- `X-DCP-Auth-Signature`

The reverse proxy must **strip every inbound `X-DCP-*` header** from the
browser request before it invokes the signer, and must forward only the
freshly generated assertion headers. The signer must be reachable only over a
private local channel (loopback or Unix socket), never directly from the
Internet. The Gateway's internal bearer token is separate and must not be
forwarded to the browser.

## Replay, CSRF and origin controls

`ProxyIdentityVerifier` validates the HMAC, timestamp window, role and nonce.
When created by `make_handler`, it uses the Gateway SQLite store for durable
nonce consumption. Replays across verifier instances are rejected; if the
nonce database is unavailable, authentication fails closed. The current
deployment is a single Gateway using one SQLite database. A horizontally
scaled deployment needs one shared transactional nonce store before it is
supported.

The Gateway separately requires:
- exact configured `Origin` on state-changing operations;
- a session-bound CSRF token in `X-CSRF-Token`;
- server-side owner/operator authorization on every protected endpoint;
- `Cache-Control: no-store` on API responses;
- no wildcard credentialed CORS;
- no logging of cookies, tokens, identity headers, or request bodies.

OIDC logout must revoke the server session and clear the cookie. Password reset,
account recovery, session revocation, user lifecycle and audit retention remain
identity-provider/application deployment responsibilities.

## Required server-side configuration

- `DCP_PUBLIC_ORIGIN`: exact HTTPS origin serving both UI and API.
- `DCP_TRUSTED_PROXY_HMAC_SECRET`: random secret of at least 32 characters,
  stored server-side only (e.g. Key Vault).
- OIDC issuer URL and API audience for the selected identity provider.
- Separate owner and operator group IDs.
- OIDC client ID and client secret stored server-side.
- Exact callback and post-logout redirect URIs registered with the provider.

Never place any of these values in dashboard HTML, JavaScript, query strings,
Git history, browser storage, screenshots, or support logs.

## Current status and acceptance gate

This PR adds the assertion-signing helper, role mapping, durable SQLite replay
protection, and mock tests. It does not register an OIDC client, deploy a
reverse proxy, configure a tenant/domain, or enable live sign-in. The repository
has no configured identity-provider tenant or production `/api/auth/*`
deployment. GitHub Pages alone is insufficient.

Before enabling OIDC in production, supply the real issuer, audience, owner and
operator group IDs, public HTTPS origin, callback URL and secret-store
references. Then run browser acceptance for login, logout, invalid issuer,
invalid audience, expiry, nonce/state mismatch, CSRF, role denial, direct API
header spoofing, replay across process restarts, and iPhone Safari. Do not
enable provider provisioning as part of OIDC setup.


## Repository implementation status (provider-neutral)

The repository now includes the following reusable server-side building blocks:

- `oidc_config.py`: HTTPS issuer/client/callback and scope validation.
- `oidc_client.py`: Discovery metadata checks, JWKS retrieval through an
  injected transport, PKCE S256, authorization-code exchange, and RS256/ES256
  ID-token signature and claim verification.
- `oidc_session_store.py`: durable one-time state transactions bound to a
  browser binding, SQLite-backed session lookup, CSRF token validation,
  session rotation and revocation.
- `oidc_auth_service.py`: begin-login and callback orchestration, verified
  group-to-role mapping, server-only session handles, session rotation, logout,
  and Secure/HttpOnly cookie builders.
- `oidc_wsgi.py`: HTTPS-only login redirect, exact-host callback, session
  introspection, CSRF-protected rotation/logout, and secure cookie handling.
- Offline regression tests cover invalid signatures, issuer/audience/nonce,
  expired tokens, algorithm rejection, key ambiguity, PKCE, state replay,
  browser binding, session rotation and logout.

The WSGI adapter provides deployable route handling but is not mounted by
the current local password proxy or a production web host. A production HTTPS
host must instantiate the service and adapter, provide TLS-verified bounded
transports, and mount the adapter behind a trusted proxy that supplies the
validated HTTPS scheme and Host. The adapter binds the browser transaction to
a Secure/HttpOnly pre-auth cookie, enforces the exact callback host/path,
issues a Secure/HttpOnly/SameSite session cookie, and protects rotation/logout
with same-origin and CSRF checks. It must not be mounted on the current
loopback HTTP-only development listener.

The local proxy creates a fresh signed Gateway assertion from its authenticated
server-side session and does not forward arbitrary browser headers. An
end-to-end regression test now supplies forged `X-DCP-*` values and confirms
they do not replace the proxy-generated identity. Any separately deployed
reverse proxy must still strip all incoming `X-DCP-*` headers before calling
the trusted signer.

## Required live deployment configuration

Live sign-in remains disabled until an operator supplies and verifies the
selected provider's exact issuer, client ID, audience/authorized-party
requirements, callback URI, owner and operator group identifiers, public HTTPS
origin, and secret-store references. Provider secrets must be injected into
the server environment or secret manager, never committed or sent to browser
code. No provider tenant or cloud resource is created by CI.
