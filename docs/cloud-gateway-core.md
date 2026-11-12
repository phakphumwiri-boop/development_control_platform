# DCP Cloud Gateway Core

This phase adds a provider-neutral authenticated API, strict platform policy, a SQLite lifecycle ledger, idempotency, audit metadata, budget ceiling checks, a circuit breaker, concurrency limits, and bounded runtime.

## Fail-closed defaults
- Live provisioning is OFF.
- Owner approval is required independently from the enable flag.
- A server-side repository allowlist and positive budget ceiling are mandatory.
- Current spend plus projected run cost must fit below the configured ceiling.
- Circuit breaker must be clear; concurrency and runtime are bounded.
- Platform image and labels are enforced server-side; workers must be ephemeral with restricted egress.
- Registration tokens are provider-side only.
- API routes require bearer authentication and request bodies are size limited.
- The SQLite ledger stores no credentials or runner registration tokens.

## API and local mode
The health endpoint is /healthz. Authenticated endpoints are POST /v1/runners, GET /v1/runners/{id}, and DELETE /v1/runners/{id}. The server binds to loopback by default and accepts a configurable port. A bearer token is required to start it.

The default provider adapter is intentionally disabled. This phase does not contact Azure, Key Vault, ARM, or Orka and cannot create billable resources.

## Evidence semantics
HTTP 202 means accepted/provisioning only. Online requires a provider status observation; terminated requires provider teardown confirmation. A provisioning response is not evidence of an online runner or passing build.

Azure Managed Identity, Key Vault, Azure Budget API integration, Azure VM provisioners, effective NIC egress verification, and GitHub runner cleanup modules are implemented with mock-backed tests. The Azure runtime factory is composed only when `DCP_AZURE_PROVIDER_ENABLED=true`; otherwise both provider slots remain `DisabledProvider`. This adapter opt-in is separate from `DCP_GATEWAY_PROVISIONING_ENABLED`, owner approval, and the provider-specific budget guard. Orka remains disabled pending verified protected User Data and an Orka-specific budget source. Budget guards are selected by the routed provider key; an Azure budget snapshot can never authorize an Orka request. The generic provider guard requires a matching provider identity in the snapshot and fails closed on missing, stale/unavailable, or denied data. Real provider validation remains SKIPPED until provider accounts, live egress/guest acceptance, and explicit budget approval are supplied.

## Browser control-plane role boundary

The authenticated browser API accepts signed proxy identities for read operations,
but runner creation and termination require the signed identity role to be exactly
`owner`. An `operator` may inspect session, status, and runner inventory but
cannot create or terminate runners, even when the deployment-wide provisioning
and owner-approval flags are enabled. The gateway enforces this check server-side
after proxy-signature, same-origin, and CSRF validation; UI visibility is not an
authorization control.

The reverse proxy must strip all client-supplied `X-DCP-*` identity headers and
inject a fresh HMAC assertion only after authenticating and authorizing the
upstream session. Keep the HMAC secret shared only between the trusted ingress
and gateway. These local contract tests prove the gateway role check with
synthetic assertions; they do not verify a deployed reverse proxy or production
identity provider.
