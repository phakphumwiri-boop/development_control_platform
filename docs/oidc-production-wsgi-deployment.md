# Production OIDC WSGI application composition

The provider-neutral OIDC modules now include
`tools.cloud_gateway.oidc_deployment.create_oidc_wsgi_app_from_env`, a
fail-closed composition factory for a production WSGI host.

This is an application factory, **not a deployed service**. It does not bind a
port, terminate TLS, create a reverse proxy, register an identity-provider
client, or enable sign-in in the existing local HTTP listener.

## Required non-secret configuration

- `DCP_OIDC_ISSUER`: exact HTTPS issuer identifier.
- `DCP_OIDC_CLIENT_ID`: registered client ID.
- `DCP_OIDC_REDIRECT_URI`: exact HTTPS callback URI registered at the IdP.
- `DCP_PUBLIC_ORIGIN`: exact HTTPS origin serving the UI and auth routes.
- `DCP_TRUSTED_PROXY_CIDRS`: comma-separated canonical IP CIDRs for the
  immediate TLS-terminating proxy peers that connect directly to the WSGI
  listener. Empty, malformed, or duplicate entries are rejected.
- `DCP_OIDC_SESSION_DB_PATH`: durable SQLite file path on protected persistent
  storage; `:memory:` is rejected.
- `DCP_OIDC_OWNER_GROUPS`: comma-separated, explicit owner group identifiers.
- `DCP_OIDC_OPERATOR_GROUPS`: comma-separated, explicit operator group
  identifiers, disjoint from owner groups.
- `DCP_OIDC_SCOPES`: optional scopes; defaults to `openid profile email`.
- `DCP_OIDC_SESSION_TTL_SECONDS`: optional integer from 300 to 86400;
  defaults to 43200.
- `DCP_OIDC_POST_LOGIN_PATH`: optional safe same-origin path; defaults to `/`.

The factory does not read or return a client secret. It requires injected
`fetch_json(url)` and `post_form(url, form)` callables. The deployment must
supply transports that validate TLS certificates, enforce strict connection
and read timeouts, bound response sizes, reject redirects to untrusted hosts,
and implement the selected provider's required confidential-client
authentication. Client credentials must come from the deployment's secret
manager and must never be placed in browser configuration or source control.

## WSGI host requirements

Example composition (the host supplies its own reviewed transport functions):

```python
from os import environ
from tools.cloud_gateway.oidc_deployment import create_oidc_wsgi_app_from_env

application = create_oidc_wsgi_app_from_env(
    environ,
    fetch_json=tls_verified_bounded_json_get,
    post_form=tls_verified_bounded_token_post,
)
```

The two transport names above are deployment-provided callables, not
repository functions. Do not copy the example as executable code until those
functions have been implemented and reviewed for the chosen IdP.

Mount the WSGI app only behind a trusted HTTPS reverse proxy. The deployment
factory wraps the OIDC application in `TrustedHTTPSProxyMiddleware`, which
requires the immediate peer address to match `DCP_TRUSTED_PROXY_CIDRS`, accepts
only a single `X-Forwarded-Proto: https` and exact `X-Forwarded-Host` matching
`DCP_PUBLIC_ORIGIN`, and strips all forwarded and `X-DCP-*` headers before the
OIDC routes run. The proxy must overwrite (not append) those forwarded headers,
strip every inbound `X-DCP-*` header, and keep the signer and Gateway on private
channels. Firewall the WSGI listener so only the configured proxy peers can
connect; the middleware is defense in depth, not a replacement for network
isolation or a reviewed proxy configuration. The proxy must also enforce host
validation and TLS policy before forwarding.

A reviewed Nginx reference template is provided at
`deploy/nginx/oidc-ingress.conf.example`. It uses a strict request-header
allowlist (`proxy_pass_request_headers off`), overwrites Host and forwarded
origin values, passes only the OIDC cookie/origin/CSRF and basic request
headers, disables upstream retries, bounds request size and proxy timeouts, and
rejects unknown HTTP/TLS hosts. It also routes the same-origin SPA from
`/srv/dcp-ui`; replace that root with the reviewed UI build location.

For the supplied same-host layout, bind the WSGI server to
`127.0.0.1:8080` only and set
`DCP_TRUSTED_PROXY_CIDRS=127.0.0.1/32`. Do not expose port 8080 on a public or
untrusted interface. Replace `dcp.example.invalid` and certificate paths
before use; configure `DCP_PUBLIC_ORIGIN=https://dcp.example.invalid` and
register the exact callback URI with the selected IdP. The template requires
Nginx 1.19.4 or later for `ssl_reject_handshake`. It is a reference
configuration, not a deployed or production-validated reverse proxy.

Use persistent, access-controlled storage with backups and single-instance
SQLite semantics. Horizontal scaling is not supported by this SQLite session
store without a shared transactional session/nonce backend.

## Explicit non-goals and acceptance gates

- The existing `Run-DCP-Gateway.ps1` and loopback password proxy remain
  unchanged; this factory is not mounted into that HTTP-only development path.
- No IdP has been selected or configured by this change.
- No client secret, tenant, DNS, certificate, cloud resource, or production
  deployment is created.
- Gateway provisioning remains disabled by default.

Before production activation, select the IdP and register exact redirect
URIs; implement and review the injected TLS transports and secret-manager
integration; configure the trusted HTTPS host/proxy and its immediate peer
CIDRs; then run browser E2E for
login, callback, session, rotation, logout, invalid issuer/audience/signature,
state/nonce replay, CSRF, role denial, spoofed headers, restart persistence,
and iPhone Safari. Do not enable provisioning as part of identity setup.
