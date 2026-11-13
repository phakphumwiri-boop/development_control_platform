# GitHub App runner bootstrap

## Scope

`tools.cloud_gateway.github_app.GitHubAppRunnerBootstrap` is a server-side
credential broker for issuing a repository-scoped GitHub Actions runner
registration token. It does not create a VM, install a runner, or enable
provisioning by itself.

The implementation is deliberately fail-closed:
- The GitHub App ID and installation ID are validated at startup.
- Every runner operation requires current GitHub App installation-catalog membership and `private: true`. Public repositories are filtered out of the selectable catalog. The optional explicit allowlist only narrows this private catalog; it is never a fallback or proof of privacy.
- The installation access token request is scoped to that one repository.
- The installation must grant repository Administration write permission required by the registration-token endpoint.
- The registration token is returned only to the provider-side caller.
- Token fields are excluded from object representations; API errors are sanitized.
- The App private key is accepted in memory and must be read from a server-side
  secret store such as Azure Key Vault. Never commit it or pass it to browser code.

## Required GitHub App configuration

Create/configure the GitHub App outside this repository and install it only on
all intended private repositories (public repositories remain excluded from DCP even if installed). Grant Contents: read for branch/tag discovery and commit verification, plus
the minimum repository Administration permission needed to create and remove
self-hosted runner registrations (Administration: write as required by
GitHub's current App permission model).
Do not grant organization-wide installation access unless separately reviewed.

Server-side settings are expected to be supplied by the deployment environment:
- `DCP_GITHUB_APP_ID`
- `DCP_GITHUB_APP_INSTALLATION_ID`
- `DCP_GITHUB_APP_PRIVATE_KEY_SECRET_NAME` (a Key Vault secret name, not key content)
- `DCP_GATEWAY_ALLOWED_REPOSITORIES` (optional comma-separated narrowing filter applied after private installation-catalog verification; never a fallback)

The App private key must be retrieved server-side through the existing read-only
Key Vault secret reader. Never put private key material, installation tokens,
or runner registration tokens in dashboard responses, browser storage, query
strings, audit events, workflow logs, or Git history.

## Token flow

1. Discover the installation repository catalog using a short-lived installation token with Metadata: read.
2. For branch/tag listing and commit verification, revalidate private installation membership and mint a short-lived token scoped to the selected repository with Contents: read only.
3. For runner administration, revalidate private installation membership and sign a short-lived RS256 App JWT (issued-at skew, expiry under ten minutes).
4. Exchange it for an installation access token scoped to the selected repository.
5. Require the repository Administration permission appropriate to the requested runner operation.
6. Create that repository's Actions runner registration token.
7. Return a redacted credential object to the provider-side bootstrap caller; Contents tokens and registration tokens never reach the browser.

The registration token is a short-lived bootstrap credential, not a durable
runner secret. The caller must pass it only through a protected provider
bootstrap channel (for Azure, protected extension settings; for Orka, a
protected secret injection mechanism) and ensure the guest does not persist it.
The runner must be configured as ephemeral and removed after its one job.

## Validation and current limits

The API transport rejects redirects, bounds response bodies to 2 MiB, and
requires JSON content type for non-empty responses. Unit tests use generated
test RSA keys and mocked responses. They do not contact GitHub, Key Vault,
Azure Resource Manager, Orka, or create any cloud resources.
A passing unit test proves the local contract only; it is not evidence that a
GitHub App exists, is installed, or has the required permissions.

This PR does not read production secrets, configure an App, activate a provider,
enable provisioning, or deploy an OIDC ingress. Provider integration and
independent GitHub runner-online verification remain subsequent phases.
