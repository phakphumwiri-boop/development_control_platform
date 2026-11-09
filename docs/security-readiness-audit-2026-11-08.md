# DCP Security & Readiness Audit

**Review date:** 2026-11-08  
**Repository:** `phakphumwiri-boop/development_control_platform`  
**Audited base:** `main` at `36a6c5b1f9becb948acaf59f27f10765fc7edbde`  
**Review type:** source/documentation review plus owner-reported local test result  
**Overall decision:** **LOCAL DEVELOPMENT READY; CLOUD PROVISIONING NOT READY**

## Executive summary

The reviewed `main` revision preserves the intended fail-closed design. The Local Auth Proxy is source-configured for loopback, the local launcher injects loopback Gateway configuration and explicitly sets both provisioning and owner approval to false, and the Gateway policy requires multiple independent gates before provisioning. The documented production Gateway composition remains `DisabledProvider`, so cloud runner provisioning is intentionally unavailable.

The owner reported that the full local test suite on this `main` revision completed with **236 tests, 0 failures, in 19.549 seconds**, and exit code **0**. This is local test evidence, not a GitHub Actions result or live cloud acceptance evidence.

This review does **not** establish the live state of processes, listening sockets, environment variables, provider budgets, cloud accounts, or deployed infrastructure. Those runtime facts remain **UNKNOWN** until checked on the target machine or deployment environment.

## Findings

| Area | Status | Evidence and interpretation |
|---|---|---|
| Main revision and test suite | **PASS (reported)** | Owner-reported local run on `main` / `36a6c5b`: 236 tests passed; exit code 0. Not represented as CI or production evidence. |
| Local Auth Proxy bind | **PASS (source)** | `tools/local_auth_proxy.py` defines `HOST = "127.0.0.1"`; the local stack is documented as loopback-only. Actual running socket was not inspected. |
| Local Gateway bind | **PASS (configured by launcher) / UNKNOWN (live)** | The local launcher injects `DCP_GATEWAY_HOST=127.0.0.1`. Actual process arguments, environment, and listening sockets were not inspected during this review. |
| Local provisioning defaults | **PASS (source)** | The Local Auth Proxy launcher explicitly injects `DCP_GATEWAY_PROVISIONING_ENABLED=false` and `DCP_GATEWAY_OWNER_APPROVED=false`. The local setup guide documents the same defaults. |
| Gateway policy defaults | **PASS (source)** | `GatewaySettings` defaults both flags to false. `authorize_provisioning` also requires owner approval, a non-empty repository allowlist, a non-tripped circuit breaker, a positive budget ceiling, projected spend within budget, and available concurrency. |
| Browser/API provisioning gates | **PASS (source)** | The browser-facing POST path requires an authenticated owner identity, same-origin and CSRF validation, provisioning enabled, owner approval, selected provider budget gate exactly `PASS`, provider readiness, and a non-tripped circuit breaker. |
| Provider-specific budget state | **UNKNOWN (live)** | The Gateway reports a provider budget as `UNKNOWN` when its provider-specific guard is absent or cannot be read. No live budget snapshot was obtained in this review. |
| Provider runtime composition | **BLOCKED by design** | The documented production entry point composes `DisabledProvider` adapters. Azure guest login/effective egress, Orka protected bootstrap and provider-specific budget evidence, and live runner/job/teardown acceptance remain prerequisites. |
| Cloud deployment readiness | **BLOCKED** | The Azure deployment plan is preparation-only. It requires subscription, domain, identity, cost, private ingress, OIDC edge, persistence, provider acceptance, and explicit owner approval before deployment or enablement. |
| Live endpoints and infrastructure | **UNKNOWN** | No live network probe, process inspection, cloud-account query, or provider API call was performed. |

## Repository governance (live GitHub configuration)

The GitHub repository configuration was checked on 2026-11-09 through the repository and branch APIs:

- Repository: `phakphumwiri-boop/development_control_platform` (public fork of `phakphum12345/development_control_platform`).
- Default branch: `main`.
- GitHub reports `main` as **not protected** (`protected: false`).
- The repository rulesets endpoint returned an empty list.
- Therefore, the repository currently has no GitHub-enforced required pull-request reviews or required status checks on `main`. The YAML registry policy in this repository is an application-level policy record; it does not itself enforce GitHub branch protection.

This is a governance gap, not evidence of a code vulnerability. Before treating this fork as a controlled release repository, an administrator should configure a branch ruleset for `main` that requires pull requests, requires the applicable CI checks, blocks force-push and deletion, and requires review/approval appropriate to the repository's ownership model. The exact required check names should be taken from stable completed GitHub Actions runs, not guessed. No branch protection or ruleset settings were changed as part of this audit.

## Verified source controls

### Local-only service boundary

- `tools/local_auth_proxy.py` sets the Local Auth Proxy host to `127.0.0.1`.
- The local launcher passes `DCP_GATEWAY_HOST=127.0.0.1` to its Gateway child process.
- `docs/windows-11-one-click.md` documents the Dashboard/Auth Proxy and Gateway as loopback-only and prohibits binding to `0.0.0.0` or exposing the ports to a LAN or the internet.
- The local Auth Proxy keeps Gateway bearer and HMAC signing secrets server-side; its browser-facing session uses HttpOnly/SameSite cookies and CSRF checks.

### Fail-closed cloud controls

- Local startup explicitly sets provisioning and owner approval to false.
- Gateway settings default both controls to false when not enabled by configuration.
- Provisioning requires explicit owner approval and several independent policy gates.
- Provider-specific budget gates must be `PASS`; missing or failed budget reads remain blocked.
- The documented production runtime continues to use `DisabledProvider`, rather than composing a live cloud provider.
- The Azure deployment runbook states that no Azure resources have been created and live provisioning remains disabled.

### Test evidence and its limits

The owner-reported full suite result is:

```text
Ran 236 tests in 19.549s

OK
FullTest ExitCode: 0
```

This validates the test suite at the reported local revision. Unit and mock-backed adapter tests do not prove cloud VM creation, runner registration, effective egress restrictions, a real workflow job, or remote teardown.

## Required follow-up before any cloud enablement

All items below remain release gates; this audit does not authorize them.

1. **Local runtime verification:** inspect the actual Local Auth Proxy and Gateway process bindings and confirm both listeners are on loopback only. Do not stop or restart unrelated services to perform this check.
2. **Runtime configuration verification:** inspect only safe boolean/status outputs for provisioning and owner approval. Do not print or share tokens, passwords, cookies, HMAC secrets, private keys, or other credential values.
3. **Budget verification:** obtain current, provider-specific budget guard results for Azure Linux, Azure Windows, and Orka macOS. Any missing, stale, or failed result must remain blocked.
4. **Bootstrap and network verification:** complete and review Azure guest login and effective egress controls, plus Orka protected macOS bootstrap and provider-specific budget integration.
5. **Live lifecycle acceptance:** in a separately approved, cost-bounded environment, prove runner registration, online confirmation, a controlled job, cancellation/timeout behavior, deregistration, provider teardown, and orphan cleanup.
6. **Production identity and ingress:** implement and independently review the OIDC edge/session service, same-origin HTTPS boundary, role mapping, CSRF, replay protection, and private Gateway ingress described in the deployment runbook.
7. **Owner release approval:** obtain explicit approval for the exact subscription, region, repository allowlist, spending ceiling, concurrency, runtime, and provider configuration. Only then consider a separate reviewed change to runtime composition and provisioning flags.

## Safety statement

This audit added documentation only. It did not enable provisioning, change runtime configuration, create cloud resources, expose a public endpoint, access secret values, or claim live provider acceptance. Cloud provisioning must remain disabled and owner approval false until every required gate is independently verified and explicitly approved.

## Source references

- `README.md` — local-first operation, cloud runner boundary, and security limitations.
- `docs/local-first-mode.md` — no-cost defaults, read-only doctor, and evidence limits.
- `docs/windows-11-one-click.md` — local loopback topology and safe startup defaults.
- `docs/cloud-runner-control-plane.md` — provider contract and live acceptance limitations.
- `docs/azure-production-deployment.md` — staged deployment gates and owner approval requirements.
- `tools/local_auth_proxy.py` — loopback host, local authentication, and launcher environment.
- `tools/cloud_gateway/policy.py` — fail-closed provisioning and budget policy.
- `tools/cloud_gateway/server.py` — browser-facing owner, CSRF, provider-budget, readiness, and circuit-breaker gates.
- `tests/test_local_auth_proxy.py` and `tests/test_cloud_runner_backend.py` — local authentication and mock-backed provider contract coverage.
