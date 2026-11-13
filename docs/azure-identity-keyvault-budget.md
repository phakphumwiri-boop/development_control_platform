# Azure identity, Key Vault, and budget reader

This adapter set is read-only. It obtains Microsoft Entra access tokens through a platform-provided Managed Identity endpoint, reads named Key Vault secrets, and reads an existing Azure Consumption budget. It does not create a vault, role assignment, budget, subscription, resource group, or compute resource.

## Required deployment configuration
- Configure a system- or user-assigned Managed Identity on the gateway host.
- Grant only Key Vault Secrets User on the specific vault and read-only Cost Management/Budget permissions at the narrowest applicable scope.
- Configure DCP_AZURE_USE_IMDS=true only on an Azure VM that exposes IMDS, or use the platform-provided local IDENTITY_ENDPOINT and IDENTITY_HEADER.
- Set the Key Vault origin and secret names through deployment configuration. Never put secret values in GitHub Actions variables, source files, command lines, or logs.
- Provide subscription ID and an already-existing budget name. This code intentionally contains no create/update/delete budget operation.
- Set `DCP_AZURE_PROJECTED_RUN_COST_USD` to an explicit positive per-run estimate for the configured maximum runtime; zero or missing estimates block provisioning.

## Budget semantics
A budget read must return an active time period, Cost category, amount, currentSpend, matching forecastSpend and currency. Missing or malformed budget data fails closed. The adapter only compares USD amounts; other currencies are denied until a reviewed conversion policy exists. Azure budgets are monitoring/alerting constructs, so the gateway's independent spend circuit breaker remains mandatory.

## Verification boundary
Tests use mocked HTTP responses only. No Azure endpoint was contacted, no identity token was requested from a live host, and no billable Azure resource was created. Required role assignments and live authorization are deployment-time checks and remain unverified here.


## Projection and freshness safety

The Azure budget reader now requires a valid forecast amount with the same currency
as current spend. A missing or malformed forecast is UNKNOWN and blocks
provisioning; a currency mismatch is not treated as a comparable value.
Budget snapshots reject negative, NaN, infinite, or malformed amounts.

`DCP_AZURE_PROJECTED_RUN_COST_USD` is the conservative upper-bound cost for one
eligible Azure runner at its configured maximum runtime (use the more expensive
of the enabled Azure Linux/Windows profiles). The guard evaluates
`projected_run_cost_usd * (active_runner_count + 1)`, so existing active and
cleanup-pending runners are included before authorizing another runner. Failed
records with provider resources still pending cleanup continue to count against
concurrency.

The Gateway status response includes only aggregate lifecycle counters
(`state_counts`, `cleanup_pending`, `cleanup_retries`, and
`cleanup_confirmed`); it does not disclose runner names, repository IDs, or
provider identifiers.

All Azure ARM, Key Vault, GitHub App, and Orka bearer credentials are placed in
non-redirected request headers. A redirect cannot forward these credentials to
a different host. Provider creation requires both a live budget guard and
verified cleanup wiring. The production bootstrap remains disabled until all
deployment-side controls are configured and accepted.


The Gateway serializes capacity checks and durable provisioning reservations in
one process so concurrent requests cannot all observe the same free slot. The
current SQLite deployment supports one Gateway process; multi-process or
multi-region provisioning requires a shared transactional reservation/nonce
store before scaling out.

The Azure Consumption budget is authoritative only for Azure resources. Orka
macOS remains disabled until its own provider-specific cost/budget guard is
implemented and verified; an Azure budget PASS must never be treated as proof
that MacStadium spend is within limits.


Azure's Consumption Budgets API only returns `forecastSpend` when the budget
contains a forecast alert type. Configure a forecasted notification on the
target budget; otherwise DCP treats the snapshot as UNKNOWN and denies runner
creation rather than silently falling back to current spend only.


## Reference

- Microsoft Learn: [Azure Consumption Budgets - Get (2023-05-01)](https://learn.microsoft.com/en-us/rest/api/consumption/budgets/get?view=rest-consumption-2023-05-01). The API defines the budget time period and notes that forecast spend is returned only when a forecast alert type is configured.


## Secret and token transport hardening

Managed Identity and Key Vault calls now use a bounded, no-redirect HTTP
transport. Managed Identity accepts only the platform-local App Service endpoint
with its identity header, or the explicitly enabled Azure VM IMDS endpoint.
It validates HTTPS resource identifiers, requires a Bearer token with a future
expiry, validates JSON content type, and rejects responses larger than 64 KiB.
Key Vault accepts only an HTTPS `*.vault.azure.net` origin, validates secret
names/versions, requires JSON, and applies the same 64 KiB response bound.
Redirects are rejected rather than followed.

The shared HTTP helper also provides bounded reads and redirect rejection for
the GitHub App API client. GitHub API responses are bounded to 2 MiB and
non-empty responses must declare a JSON media type. The HTTP opener is
injectable for deterministic tests; production defaults use the no-redirect
opener. Tests use mocks only and do not contact Azure or GitHub.
