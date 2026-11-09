# DCP Cloud Runner Control Plane

**Status:** provider-neutral orchestration foundation; live cloud provisioning is not enabled until a provider gateway is deployed and configured.

## Goal

Provide one reusable control plane for projects that need macOS CI without owning a Mac. The first target is `phakphum12345/generated-A4-pdf`; other repositories must be explicitly allowlisted. DCP does not silently register repositories or change their workflow files.

## Architecture

1. A trusted workflow or operator requests an ephemeral macOS runner for an exact repository, workflow run ID, and full commit SHA.
2. DCP validates the repository allowlist, SHA, approved image, and bounded runtime.
3. The provider adapter sends a request to a separately deployed HTTPS Cloud Runner Gateway.
4. The gateway is responsible for vendor-specific cloud VM creation, GitHub App authentication, short-lived runner registration, runner online confirmation, and teardown.
5. The runner is ephemeral, restricted-egress, and labelled `dcp-cloud-macos`. The requesting workflow must use a matching label and still wait for GitHub to confirm the runner is online.

DCP intentionally does not accept GitHub registration tokens, SSH private keys, or cloud credentials in request payloads. The gateway must hold these as server-side secrets and must never return or log them.

## Gateway API contract

Base URL must be HTTPS and is supplied through `DCP_RUNNER_PROVIDER_URL`. Authentication uses `DCP_RUNNER_PROVIDER_TOKEN` in the Authorization header; never commit it.

- `POST /v1/runners` — accepts `repository`, `workflow_run_id`, `commit_sha`, `image`, `labels`, `ephemeral`, `max_runtime_minutes`, `network_policy`, and `registration_token_handling`.
- `GET /v1/runners/{id}` — returns current lifecycle state.
- `DELETE /v1/runners/{id}` — requests teardown.

Responses are JSON objects with non-empty string `id` and `state`; optional `runner_name` and `detail` must be strings, and `labels` must be a list of strings. The adapter caps response bodies at 65,536 bytes, URL-escapes provider IDs in lifecycle paths, and rejects gateway URLs containing paths, query strings, fragments, credentials, or invalid ports. Transport error messages expose only the exception type so endpoint details and credentials are not copied into user-visible errors. The gateway must enforce authenticated caller identity, repository allowlisting, rate limits, idempotency, audit logging, VM TTL, cleanup on workflow completion/cancellation, and protection against arbitrary command execution. The gateway implementation is not included in this repository yet; no vendor-specific API is assumed.

## Provisioning remains disabled by default

The manual GitHub Actions workflow is fail-closed. A dispatch does not provision anything unless the operator explicitly selects `enable_cloud_runner_provisioning=true` **and** both repository Actions variables are explicitly set to the exact string `true`:

- `DCP_CLOUD_RUNNER_PROVISIONING_ENABLED`
- `DCP_CLOUD_RUNNER_OWNER_APPROVED`

The Python workflow client independently enforces both flags and defaults each to false. These flags do not replace the remote Gateway's mandatory provider-specific budget, allowlist, identity, concurrency, runtime, runner-online, and cleanup checks. Do not set either repository variable until the provider environment has passed the separately documented production acceptance and the owner has approved the exact spend ceiling and scope.

## Configuration

- `DCP_RUNNER_PROVIDER_URL`: HTTPS gateway origin.
- `DCP_RUNNER_PROVIDER_TOKEN`: gateway bearer token, stored in deployment secret storage.
- `DCP_RUNNER_ALLOWED_REPOSITORIES`: comma-separated exact owner/repository allowlist.

The first intended allowlist entry is `phakphum12345/generated-A4-pdf`. Configure it only in the backend deployment environment after review.

## Cost and safety

The approved request image is currently `macos-15-arm64`, with a 5–180 minute runtime bound and a default of 60 minutes. These are request policy defaults, not a promise that a provider offers that image or price. A provider must publish pricing, region, machine class, startup latency, retention, and cancellation behavior before production use. Provisioning must be denied when provider health, billing guardrails, or repository authorization are unknown.

## Integration status and truthful CI evidence

This commit adds only the DCP policy/orchestration layer and a provider API contract. It does not create a cloud VM, register a GitHub runner, execute a macOS build, or prove macOS CI. Until a real gateway is deployed and end-to-end tested, keep the existing GitHub-hosted macOS job as the authoritative check and report its queued/cancelled state as pending/unknown—not passed.

## Tests

Run:

```sh
python -m unittest tests.test_cloud_runner_backend -v
python -m unittest discover -s tests -v
```

Tests cover the policy manager with a fake provider and the HTTPS adapter with mocked HTTP responses. They exercise authentication and JSON serialization, URL validation and escaping, response shape and size limits, and transport-error redaction. They do not contact a real gateway or make paid cloud calls.


## Gateway GitHub App runtime configuration

The gateway can optionally compose its existing Azure Managed Identity, Key Vault,
and GitHub App adapters when all of these server-side variables are present:

- `DCP_AZURE_KEY_VAULT_URL`: HTTPS origin of the Azure Key Vault.
- `DCP_GITHUB_APP_ID`: numeric GitHub App ID.
- `DCP_GITHUB_APP_INSTALLATION_ID`: numeric installation ID.
- `DCP_GITHUB_APP_PRIVATE_KEY_SECRET_NAME`: Key Vault secret name containing the PEM private key.

The App private key is fetched at startup through Managed Identity and kept in process
memory only. The App installation must be restricted to the explicitly configured
`DCP_GATEWAY_ALLOWED_REPOSITORIES` and have the repository Administration permission
needed to create short-lived runner registration tokens and inspect/remove runners.
The gateway identity needs only the Key Vault secret-read role for that vault.
Do not put the PEM key in environment variables, workflow inputs, request bodies, or logs.

If none of these variables is configured, GitHub App integration remains disabled.
Partial configuration causes startup to fail closed. Cleanup checks the exact
allowlisted repository and runner name, refuses deregistration unless GitHub reports
the runner offline, and treats an absent runner as already cleaned up.

The GitHub App token/runner lifecycle integration and protected Azure bootstrap factory now exist, alongside mock-tested Azure VM and Orka adapters. The production server still uses `DisabledProvider`: Azure effective egress policy and guest login profile are not verified; Orka has no authoritative provider-specific budget reader or protected macOS User Data bootstrap. Provider composition and provisioning must remain disabled until those checks and live runner/job/teardown acceptance are completed and reviewed. No Azure or Orka resources are created by unit/contract tests.
