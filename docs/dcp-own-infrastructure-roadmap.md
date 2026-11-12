# DCP Own Infrastructure — Execution Roadmap

## Current baseline

- Canonical repository: `phakphumwiri-boop/development_control_platform`
- Default branch: `main`
- Baseline commit when this roadmap was reconciled: `66acbf0352f99d67898600494dc537e19f306fd9`
- Live Cloud Provisioning remains disabled. The production Gateway is still composed with `DisabledProvider` adapters.
- The `protect-main` repository ruleset is active. It requires four named GitHub Actions checks and enforces an up-to-date branch before merge. Do not bypass it or force-push to satisfy it.

## Three connected systems

| System | Implemented capability | Current boundary |
| --- | --- | --- |
| Gateway / Auth Proxy | Same-origin API, trusted-proxy HMAC assertions, role checks, CSRF/origin checks, durable replay protection, job and cloud-runner lifecycle APIs, budgets and audit records | Production OIDC callback/session middleware and deployed reverse-proxy signer are not present. Current HMAC assertions are a contract, not proof of live OIDC login. |
| Local Windows Runner / Agent | Authenticated registration, capability preflight, claim/heartbeat/log/finish, workspace isolation, immutable commit checkout, fixed Flutter command allowlist, bounded process execution, cancellation, artifact upload | Windows CI uses real `cmd.exe` and local-stack E2E, but self-hosted/physical-host acceptance remains opt-in and has not been run on the target workstation. Repository build code is not an OS sandbox. |
| Cloud / Ephemeral Runner lifecycle | Azure VM and NIC lifecycle modules, guest-profile validation, effective NSG/route verifier, GitHub App runner registration/online checks, retryable cleanup and deregistration | Runtime provider composition is still disabled. No Azure VM, Key Vault secret, GitHub App registration token, Orka VM, or billable resource was created by CI. |

The Infrastructure Manager is a separate provider-neutral inventory API. It is currently wired to `FakeInfrastructureProvider` only and has `provisioning_enabled=False`; it is not an Azure/Orka resource manager yet.

## Delivery status

| Phase | Work package | Status | Exit evidence / remaining work |
| --- | --- | --- | --- |
| 0 | Baseline, branch safety, and CI | Implemented | Node.js 24 migration merged in PR #40. Main ruleset requires `validate`, Windows dynamic-port, Windows Auth Proxy/Gateway E2E, and Linux Minimal Emulator checks. |
| 1 | Repository Manager hardening | Implemented | GitHub App installation catalog, repository membership checks, ref discovery, immutable commit resolution, and project inspection are in the mainline. |
| 2 | DCP Core and Job Control Plane | Implemented for local-first operation | Durable SQLite queue, idempotency, state transitions, cancellation, leases, audit events, Runner Registry, and Scheduler. Production identity ingress and multi-instance shared nonce storage remain separate work. |
| 3 | Local Runner Engine | Implemented in code and CI | Windows launcher, real `cmd.exe` integration, host preflight, authenticated Agent, per-job workspace, safe checkout, fixed Flutter commands, process bounds, and artifact handoff. Physical-host acceptance remains pending. |
| 4 | Cloud Provisioning Engine | Partial / disabled | Azure guest login profile validation (PR #43), effective NIC egress verification (PR #44), Azure configuration preflight (PR #45), and confirmed GitHub runner deregistration (PR #46) are merged. The Gateway still uses `ProviderRouter(DisabledProvider(), DisabledProvider())`. Azure runtime composition and live acceptance are not complete. Orka remains `ready=false`. |
| 5 | Artifact Center | Implemented in local-first flow | Bounded upload, job/worker ownership, SHA-256 integrity metadata, authenticated download, and artifact indexing are implemented. Retention and production storage deployment need release review. |
| 6 | Dashboard | Partial | The same-origin HTML dashboard and Gateway APIs are integrated. Production OIDC ingress and static-host/API deployment parity are not proven. Flutter-native screen parity is a separate UI workstream. |
| 7 | Live provider acceptance | Disabled / approval required | No live Azure or Orka provisioning. Requires explicit owner approval, isolated subscription/cluster, cost ceiling, network allowlist, guest access proof, runner online evidence, and teardown proof. |

## Recent merged work

| PR | Change | Result |
| --- | --- | --- |
| #40 | Migrate GitHub Actions workflows to Node.js 24 | Merged |
| #43 | Validate Azure Linux/Windows guest login profiles before bootstrap | Merged |
| #44 | Verify Azure effective NIC NSG rules and firewall default route using the documented ARM response schema | Merged |
| #45 | Validate Azure firewall/egress configuration and Guest profile Key Vault references in read-only preflight | Merged |
| #46 | Wire the Gateway to verified GitHub runner cleanup and confirm runner absence after deregistration | Merged |

CI validation on these PR heads passed. The Windows Runner Acceptance job remained skipped according to its existing explicit opt-in gate. Post-merge push workflows also passed on main commit `66acbf0352f99d67898600494dc537e19f306fd9`: Validate Control Plane run `43266934859` and Local-first Minimal Emulator run `43266934906`.

## Readiness gates that must remain separate

### Gateway identity

- `oidc_assertion.py` validates and signs already-verified claims; it does not validate an OIDC JWT signature or perform Authorization Code + PKCE.
- A production OIDC middleware/reverse proxy must validate issuer, audience, signature/JWKS, state, nonce, expiry, exact callback URI, session rotation, and logout.
- The proxy must strip inbound `X-DCP-*` headers and inject fresh request-bound HMAC assertions over a private channel.
- The current durable replay store is SQLite for a single Gateway. Horizontal scaling requires a shared transactional nonce store.
- Do not enable browser-facing production provisioning until the real identity provider, HTTPS origin, callback, owner/operator groups, and session revocation path are accepted.

### Local Runner

- CI success proves the tested GitHub-hosted Windows environment and mocked control-plane contracts, not the user's physical Windows host.
- Keep `DCP_RUNNER_EXECUTION_ENABLED=0` by default. Any real build execution requires a disposable/isolated host and an exact trusted-repository allowlist.
- Never treat Runner registration or online state as proof that a build succeeded.
- Run the opt-in self-hosted acceptance only on a deliberately enrolled, owner-approved host; do not broaden it to ordinary PRs.

### Azure

- PR #43 validates guest-profile structure; PR #44 verifies effective NSG/route data; PR #45 validates configuration syntax. None of these proves that Key Vault contains the intended values or that Azure has applied the policy.
- Azure effective-route verification must fail closed if the active IPv4 default route does not point to exactly one approved firewall next hop.
- The provider must remain disabled until the runtime factory, managed identity, Key Vault secret references, pinned image versions, budget guard, exact egress allowlist, guest login, GitHub runner online check, and cleanup reconciliation are composed and tested.
- Live acceptance must use an isolated resource group/subscription and record create, online, terminate, VM absence, NIC absence, GitHub runner absence, and cost evidence.

### Orka / macOS

- macOS catalog entries are metadata, not proof of Apple hardware capacity.
- The current Orka adapter has not verified the exact Orka 4.0 User Data schema against the target cluster's `/api/v1/swagger` or OpenAPI document.
- Never place a GitHub registration token in `customMetadata`.
- Orka requires its own provider budget source, protected bootstrap path, runner-online check, and verified VM teardown before `ready=true`.

### Infrastructure Manager

- The authenticated API and SQLite inventory currently use only `FakeInfrastructureProvider`.
- Do not confuse a fake resource lifecycle with an Azure VM, Orka VM, Hyper-V guest, or real host.
- A real provider requires a separately reviewed adapter, provider-scoped budget, readiness gate, owner approval, and cleanup evidence.

## Next execution order

1. **Finish post-merge CI verification for PR #46** on the current `main` commit; preserve all four required checks.
2. **Production OIDC ingress** — select the identity provider and deploy the HTTPS callback/session/reverse-proxy signer; test login, logout, role denial, CSRF, spoofed headers, nonce replay, and iPhone Safari.
3. **Azure runtime composition** — add a disabled-by-default, testable provider factory; bind managed identity, Key Vault guest profiles, pinned images, budget guard, effective egress verifier, and GitHub App lifecycle. Keep provisioning and owner approval false.
4. **Azure live acceptance** — only after an explicit owner-approved isolated subscription/resource group and budget, run one disposable Linux and Windows acceptance, then prove VM, NIC, and GitHub runner removal.
5. **Orka acceptance** — obtain the target cluster API schema/version, implement protected User Data bootstrap, add Orka-specific budget, then test one disposable macOS worker and teardown.
6. **Local Windows host acceptance** — run the opt-in acceptance on the intended physical/disposable Windows host, verify detected capabilities, dynamic-port lifecycle, token isolation, and artifact pipeline.
7. **Release audit** — reconcile API/OpenAPI/docs, dashboard behavior, installer/bootstrap scripts, log redaction, branch ruleset, and all required checks before a release.

## Safety and merge gates

- Keep `DCP_GATEWAY_PROVISIONING_ENABLED=false` and owner approval false until the live gates above are complete.
- Do not read or print Secrets or Environment Values during repository audits.
- Do not create billable Azure/Orka resources from CI or a normal PR.
- Do not use fake-provider or mock-test results as live provider evidence.
- Do not weaken repository allowlists, ephemeral-runner policy, credential isolation, or the opt-in self-hosted acceptance gate.
- Follow: READ → ANALYZE → MODIFY → TEST → AUDIT → MERGE → VERIFY → FOLLOW-UP.
- Merge only when the exact current PR head is based on the latest `main`, all four required checks pass, and the repository ruleset permits the merge. Never force-push to bypass the ruleset.
