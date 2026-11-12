# Provider-neutral OIDC configuration

The Gateway now has a small configuration-validation boundary for a future OIDC
Authorization Code + PKCE implementation.

## Environment

The validator reads only these non-secret settings:

- `DCP_OIDC_ISSUER`: HTTPS issuer URL, without query or fragment.
- `DCP_OIDC_CLIENT_ID`: registered public client identifier.
- `DCP_OIDC_REDIRECT_URI`: exact HTTPS callback URL registered with the provider.
- `DCP_OIDC_SCOPES`: optional space-separated scopes; defaults to
  `openid profile email` and must include `openid`.

The derived discovery URL is
`<issuer>/.well-known/openid-configuration`.

## Security and implementation boundary

This change validates configuration only. It does **not**:

- contact the discovery endpoint or retrieve JWKS;
- validate JWT signatures, issuer, audience, nonce, state, or PKCE;
- exchange authorization codes;
- create, rotate, or revoke sessions;
- establish a trusted reverse-proxy boundary; or
- make the Gateway production OIDC-enabled.

No client secret is loaded by this module. Do not place secrets in browser
configuration. A confidential-client secret, if required by a selected provider,
must be handled only by a future server-side secret integration.

The issuer and callback URL are HTTPS-only. Provider-specific discovery and
JWKS validation must be implemented and tested separately before enabling login.
