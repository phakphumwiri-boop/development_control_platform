# DCP Multi-platform Cloud Runner

## Scope and current implementation status

This repository implements the DCP client, policy profiles, workflow dispatch, provider-neutral API contract, and an Azure VM provider runtime factory behind the explicit `DCP_AZURE_PROVIDER_ENABLED` opt-in. The Azure adapter remains disabled by default; Orka remains disabled. The repository does **not** deploy Azure resources or prove a live Azure/Orka environment. No live runner or successful build is implied by accepting a provisioning request.

## Target topology

- **Azure control plane:** HTTPS gateway, queue/state store, Key Vault, managed identity, audit logs, budget/concurrency controls, and policy enforcement.
- **Linux:** disposable Azure Linux VM or VM Scale Set instance.
- **Windows:** disposable Azure Windows VM or VM Scale Set instance.
- **macOS:** Apple-hardware capacity through MacStadium Orka (or another reviewed Apple-hardware provider). A standard Azure VM is not a supported macOS host.

## Approved DCP profiles

| target_os | image | labels | provider |
| --- | --- | --- | --- |
| linux | ubuntu-24.04-x64 | self-hosted, Linux, X64, dcp-cloud-linux | Azure |
| windows | windows-2025-x64 | self-hosted, Windows, X64, dcp-cloud-windows | Azure |
| macos | macos-15-arm64 | self-hosted, macOS, ARM64, dcp-cloud-macos | MacStadium Orka |

DCP pins the image and labels. The gateway must independently enforce the same mapping and reject arbitrary caller-supplied images or labels.

## Gateway lifecycle requirements

1. Authenticate DCP (prefer workload identity/OIDC); authorize the repository against a server-side allowlist.
2. Enforce idempotency on repository + workflow run + commit + target OS.
3. Apply subscription budget, per-repository concurrency, timeout, and global kill-switch before resource creation.
4. Generate and consume GitHub runner registration tokens inside the gateway only. Never return tokens to DCP, logs, VM metadata, or workflow output.
5. Create a fresh isolated worker; restrict inbound access and permit only required outbound endpoints. Do not expose SSH/RDP publicly.
6. Register as ephemeral, verify runner online, and report lifecycle separately from build results.
7. On job completion, cancellation, failure, or TTL expiry, deregister and destroy worker, disks, and networking resources. Reconcile orphan resources.
8. Emit credential-free audit logs with provider ID, timestamps, image, repository, workflow run, commit SHA, and terminal state.

## Azure deployment requirements

- Deploy gateway as an Azure Container App or equivalent private HTTPS service with managed identity.
- Store GitHub App and Orka credentials in Azure Key Vault; grant only narrowly scoped secret-read access.
- Use ARM with managed identity and a dedicated resource group. Tag resources with managed-by=dcp-cloud-runner, runner-id, repository, and workflow-run-id.
- Use ephemeral OS disks where supported, strict NSG egress, and hard TTL.
- Configure Azure budgets/alerts plus an application-level spend circuit breaker. Budgets alert but do not automatically block every possible resource creation.
- Orka API calls originate only from the gateway. Keep the Orka credential out of repository and GitHub workflow secrets.

## Security boundary

Do not run untrusted fork pull-request code on persistent self-hosted runners. Use GitHub-hosted runners for untrusted PR validation; reserve cloud workers for explicitly allowlisted trusted dispatches. Require ephemeral workers, restricted egress, server-side token handling, bounded runtime, and a kill switch.

A 202/provisioning response is not evidence of online. Online is not evidence of a passing build. Preserve PASS / FAIL / SKIPPED / UNKNOWN with commit-SHA-bound evidence.

## Before enabling billable resources

Configure subscription/resource-group scope, region, budget ceiling, provider accounts, retention, and owner approval. DCP-to-gateway authentication, GitHub App credentials, and Orka credentials belong in Azure Key Vault or managed identity—not source control. Keep live provisioning disabled until those approvals are recorded. This PR creates no billable resources.
