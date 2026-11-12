# Azure production deployment plan

**Status:** deployment preparation only. No Azure resources have been created and live provisioning remains disabled.

This document defines the approved Azure hosting direction for the Development Control Platform (DCP). It is deliberately a gated runbook: do not deploy billable resources, publish a public endpoint, or enable runner provisioning until the required subscription, domain, identity, budget, and live acceptance evidence are supplied and reviewed.

## 1. Current implementation facts

The current Gateway has:
- a Python HTTP API with `/healthz`, `/v1/runners`, and browser-facing `/api/*` routes;
- HMAC-signed reverse-proxy identity assertions, same-origin and CSRF checks;
- a SQLite lifecycle, audit, and replay-nonce store;
- optional Azure Managed Identity access to Key Vault;
- optional GitHub App private-key retrieval from Key Vault;
- Azure VM and Orka provider modules with mock-backed tests.

The current production entry point still composes `ProviderRouter(DisabledProvider(), DisabledProvider())`. It does not compose the real Azure VM adapter. The current repo also does not include a complete deployed OIDC callback/session service or a trusted proxy that signs the DCP identity headers. Therefore the first Azure deployment must be a non-provisioning staging deployment. A green `/healthz` check is not evidence that login, runner creation, Azure VM bootstrap, or cleanup works.

## 2. Target Azure topology

Use one Azure region selected with the owner after checking service availability, data residency, and price.

- **Azure Container Apps Environment:** isolates the DCP services and provides managed HTTPS ingress for the edge service.
- **DCP Gateway Container App:** private/internal ingress only; run one replica while SQLite is used. Do not expose the Gateway listener directly to the public internet.
- **Persistent data volume:** mount an Azure Files share for the SQLite database and backups. Keep one active Gateway replica until the store and nonce replay protection are migrated to a shared transactional database with tested concurrency semantics.
- **OIDC edge/auth service:** public same-origin entry point for the dashboard and `/api/*`; performs OIDC authorization-code flow with PKCE, validates issuer/audience/signature/state/nonce/redirect URI/account status, maps users to DCP roles, strips all inbound `X-DCP-*` headers, and signs fresh per-request HMAC assertions for the Gateway. This component is a deployment prerequisite and must be implemented and security-reviewed; it is not supplied by the current repo.
- **Azure Key Vault:** stores the Gateway API bearer token, proxy HMAC key, GitHub App private key, and any OIDC client secret. Access only through managed identities and least-privilege RBAC.
- **Managed identities:** separate identities for Gateway and edge where practical. Gateway receives only Key Vault secret-read access and the minimum Azure VM/network permissions needed after the provider implementation is approved. The edge receives only the secrets it needs to validate OIDC and sign assertions.
- **Log Analytics / Azure Monitor:** central application and platform diagnostics. Configure redaction; never log bearer tokens, private keys, cookies, authorization codes, signed assertions, or raw request bodies.
- **Azure budget:** configure a real subscription budget and alerts. The application budget guard is a separate hard gate; Azure Cost Management budget alerts are not instantaneous authorization signals.

Keep the public dashboard and browser API on one HTTPS origin. Do not use GitHub Pages as the production API host.

## 3. Required owner-provided deployment inputs

Before resource deployment, collect and verify:

1. Azure subscription ID and tenant ID.
2. Target resource group (or explicit approval to create one).
3. Azure region.
4. DNS domain/subdomain controlled by the owner, plus permission to create the required DNS records.
5. OIDC identity provider tenant/issuer, client registration, exact redirect URI, and the approved owner/operator role mapping.
6. Approved monthly Azure spending ceiling and alert recipients.
7. GitHub App ID, installation ID, exact repository allowlist, and confirmation that the App has only the required runner administration permissions.
8. Approved Azure VM image/SKU/region, network egress allowlist, guest login method, and bootstrap method.
9. A decision on persistent data retention, backup, and recovery objectives.

Do not send secrets, private keys, passwords, or access tokens in chat or commit them to Git. Enter them directly into Azure Key Vault or an approved secret manager after the deployment identity is established.

## 4. Secret and configuration contract

Populate secrets in Key Vault, then grant the Gateway managed identity read access only to the named secrets:

- `DCP_GATEWAY_API_TOKEN` — private service-to-service bearer token.
- `DCP_TRUSTED_PROXY_HMAC_SECRET` — random secret of at least 32 characters, shared only with the trusted edge signer.
- GitHub App PEM private key — under the configured secret name referenced by `DCP_GITHUB_APP_PRIVATE_KEY_SECRET_NAME`.
- OIDC client secret — edge service only, if the chosen OIDC provider requires one.

Gateway configuration must be injected from the deployment secret integration, not baked into the image:

- `DCP_GATEWAY_HOST=0.0.0.0` inside its private container network.
- `DCP_GATEWAY_PORT` set to the container's internal listening port.
- `DCP_GATEWAY_API_TOKEN` from Key Vault.
- `DCP_TRUSTED_PROXY_HMAC_SECRET` from Key Vault.
- `DCP_PUBLIC_ORIGIN` set to the exact public HTTPS origin, with no path or trailing slash.
- `DCP_GATEWAY_DATABASE` set to the persistent mounted database path.
- `DCP_AZURE_KEY_VAULT_URL`, `DCP_GITHUB_APP_ID`, `DCP_GITHUB_APP_INSTALLATION_ID`, and `DCP_GITHUB_APP_PRIVATE_KEY_SECRET_NAME` after the GitHub App is configured.
- `DCP_GATEWAY_PROVISIONING_ENABLED=false` for all staging and initial production deployment.
- `DCP_GATEWAY_OWNER_APPROVED=false` until explicit owner sign-off.
- `DCP_GATEWAY_ALLOWED_REPOSITORIES` restricted to the reviewed exact allowlist.
- Budget, concurrency, runtime, and circuit-breaker values set to conservative reviewed limits.

Do not set provisioning to true simply because the service starts. The current runtime is intentionally wired to `DisabledProvider`, and the Azure provider adapter still needs verified guest login, effective egress controls, lifecycle checks, and real acceptance tests.

## 5. Deployment sequence and release gates

### Gate A — account and cost preflight
- Verify subscription/tenant ownership and deployment permissions.
- Check regional availability and estimate Container Apps, storage, Key Vault, monitoring, networking, DNS, and VM costs.
- Create the resource group only after owner approval of the exact subscription, region, names, and budget.
- Configure budget alerts before any runner VM is enabled.

### Gate B — private staging foundation
- Deploy Container Apps Environment, private Gateway app, persistent storage, Key Vault, managed identities, and monitoring.
- Keep public ingress disabled for the Gateway.
- Keep provisioning and owner approval false.
- Verify managed-identity access using non-secret success/failure signals.
- Verify database persistence across a controlled restart and restore from backup.

### Gate C — OIDC edge and same-origin dashboard
- Implement and independently review the OIDC edge service.
- Validate PKCE, state, nonce, issuer, audience, signature, redirect URI, account status, role mapping, logout, session expiry, cookie Secure/HttpOnly/SameSite settings, CSRF, and rate limits.
- Prove the edge strips user-supplied `X-DCP-*` headers and injects valid per-request HMAC assertions.
- Verify replayed assertions are rejected and the durable nonce store is shared/atomic if more than one Gateway replica is ever used.
- Serve the dashboard and API from one HTTPS origin and verify browser flows end-to-end.

### Gate D — Azure runner adapter acceptance
- Implement explicit runtime composition for the real Azure adapter; do not remove `DisabledProvider` as a blanket shortcut.
- Create the private NIC first, then call the ARM-backed effective-network verifier before issuing the VM create request. A failed, missing, malformed, stale/unknown, or timed-out result must delete/reconcile the NIC and must never fall through to VM creation.
- The verifier must call the NIC `effectiveNetworkSecurityGroups` and `effectiveRouteTable` actions directly against Azure Resource Manager (Network API `2025-05-01`). It must bind the result to the exact NIC, configured subnet, and expected NSG resource ID.
- Configure an owner-reviewed, non-empty outbound flow allowlist (protocol, destination port, destination CIDR) and the exact approved Azure Firewall/NVA next-hop IP. Every required flow must match an explicit effective outbound Allow rule in every applied NSG; default rules (priority 65000 or greater) do not count as authorization.
- Require an active effective `0.0.0.0/0` route whose next-hop type is `VirtualAppliance` and whose next-hop IP equals the approved firewall/NVA address. Missing, inactive, Internet, VirtualNetworkGateway, unknown, or mismatched next hops fail closed.
- Treat HTTP `202 Accepted` only as an asynchronous operation start. Require a trusted HTTPS `management.azure.com` Location, poll until a complete HTTP `200` result, and fail closed on missing Location, untrusted host, non-success response, or timeout. Do not cache effective-network results; verify immediately after NIC creation and before every VM create.
- The verifier's managed identity needs only the required read/action permissions for the target NIC effective-network operations and the existing scoped NIC/VM lifecycle permissions. Do not grant NSG or route-table write permissions to the verifier.
- Verify managed identity, resource-group scoping, VM SKU/image, guest login, ephemeral disk/data handling, outbound network policy, and deletion.
- Verify GitHub App token creation, runner registration, online confirmation, one controlled test job, runner-offline confirmation, GitHub deregistration, VM deletion, and cleanup after cancellation/timeout.
- Test failure injection at each lifecycle stage and prove that orphaned resources are reconciled.
- Verify provider-specific live budget reads and hard denial when the budget source is unavailable or stale.


#### Effective egress Live Acceptance (Azure subscription required)
Mock tests prove parser and fail-closed behavior only. They do not prove Azure has applied the intended policy. Before enabling any real runner:
1. In the approved subscription/resource group, create or select the owner-approved private subnet, NSG, route table, and Azure Firewall/NVA. Record their full resource IDs and the firewall private IP.
2. Record the exact outbound destinations as CIDRs and ports. Confirm the list is sufficient for the approved GitHub runner registration, job checkout/artifact, and monitoring endpoints. Resolve and maintain changing service IP ranges through an owner-approved process; do not replace them with `Internet`, `*`, or unrestricted outbound access.
3. Run the NIC effective NSG and effective route table ARM actions against a disposable private NIC with the same subnet and NSG association that production runners will use. Capture timestamps, request IDs, NIC/subnet/NSG IDs, effective rule names/priorities, route prefix/state/next-hop type/IP, and sanitized operation status.
4. Prove each approved flow is explicitly allowed and that an unapproved destination/port is denied by the effective policy. Prove the default route uses the exact approved firewall/NVA next hop and that the firewall policy itself permits only the approved destinations.
5. Repeat after changing NSG, subnet association, route table, firewall policy, or service endpoint ranges. Preserve the evidence with the release record.
6. Run one controlled end-to-end connectivity test from the guest to approved destinations and a negative test to an unapproved destination. A successful ARM policy read alone does not prove firewall forwarding or guest-level reachability.
7. Verify that a simulated or observed ARM `202 Accepted` is polled to completion and that missing/unknown/timed-out operations block VM creation. Confirm in Activity Log that the verifier made no NSG/route-table writes.
8. Obtain owner sign-off for the exact allowlist, firewall IP, region, resource group, budget, and test evidence before any real VM provisioning.

Required evidence: sanitized ARM responses for both effective operations, timestamps/request IDs, effective rules and routes, firewall policy export, guest connectivity test results, negative test result, CI report, and owner approval. Do not include access tokens, guest credentials, bootstrap payloads, or secrets.

### Gate E — controlled production enablement
- Review test reports, cost estimates, threat model, backup/restore evidence, and rollback plan.
- Obtain explicit owner approval for the exact repository allowlist, budget, concurrency, runtime, region, and VM SKU.
- Enable provisioning only after all prior gates pass and a separate reviewed change updates the runtime composition.
- Start with one allowlisted repository and one concurrent runner. Monitor actual costs and cleanup before increasing limits.

## 6. Acceptance checklist

- [ ] Azure subscription, tenant, region, resource group, and DNS are verified.
- [ ] Cost estimate and monthly ceiling are approved; Azure budget alerts are active.
- [ ] Gateway is private; only the edge has public HTTPS ingress.
- [ ] OIDC login, role mapping, logout, CSRF, session expiry, and replay protection pass tests.
- [ ] Dashboard and API share one HTTPS origin.
- [ ] Secrets are in Key Vault; managed identity permissions are least-privilege.
- [ ] SQLite persistence and backup/restore are proven, or the store is migrated to a shared transactional database before scaling.
- [ ] Real Azure provider composition is implemented and reviewed; no `DisabledProvider` remains in the production path.
- [ ] Guest login, egress restrictions, runner online/job/teardown, GitHub deregistration, and orphan cleanup pass live tests.
- [ ] Live provider budget gate fails closed on missing, stale, or unavailable budget data.
- [ ] Production owner approval and rollback procedure are recorded.

## 7. Rollback

- Immediately set `DCP_GATEWAY_PROVISIONING_ENABLED=false` and `DCP_GATEWAY_OWNER_APPROVED=false`.
- Disable the edge route to mutating API endpoints while preserving the health/diagnostic path.
- Stop new runner requests; reconcile and terminate all active or expired VMs and deregister only runners confirmed offline.
- Preserve the audit database and diagnostic evidence for incident review.
- Rotate affected Key Vault secrets if exposure is suspected.
- Do not delete the persistent database, audit ledger, or Key Vault until cleanup and retention obligations are satisfied.

## 8. Current deployment boundary

This plan is documentation and deployment preparation only. It does not deploy Azure resources, configure DNS/OIDC, create secrets, enable cloud provisioning, or claim production readiness. Those actions require the owner inputs in section 3 and verified live acceptance evidence.
