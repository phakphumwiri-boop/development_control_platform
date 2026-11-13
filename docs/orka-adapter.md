# Orka macOS runner adapter

The Orka adapter uses the documented Orka API Server VM endpoints and BearerTokenAuth. The VM configuration is supplied by trusted deployment configuration, not by the caller. It adds DCP ownership metadata and accepts only the approved macOS 15 ARM64 profile.

## Lifecycle evidence
- A successful VM create response means provisioning was accepted, not that the runner is online.
- An Orka VM in Running state remains provisioning until an injected GitHub runner-online checker independently confirms registration.
- A successful DELETE response means terminating, not terminated. A subsequent status lookup returning 404 confirms the VM is gone.
- VM identifiers are constrained to the DCP-generated name format before status or delete requests.

## Secret handling
The Orka bearer token is read through an injected Key Vault secret reader at request time. It is never included in VM metadata, request payloads, provider errors, or audit data. Do not put Orka credentials in GitHub Actions secrets or repository files. GitHub runner registration credentials must also remain out of VM custom metadata and ordinary API settings.

## Not enabled by this adapter
This adapter does not create an Orka namespace, VM config, image, node, or cluster. The approved VM config must already exist and be reviewed to map to macOS 15 ARM64. Runner registration/bootstrap, GitHub App credentials, network egress policy, and live Orka account validation remain separate acceptance gates.

The public [Orka API Server reference](https://macstadium.github.io/orka-api-docs/)
says it covers Orka 4.0 and later. Its currently published Deploy a VM request
schema does not list a `userdata` field, and its VM response schema does not
list `userdataPhase`. The reference directs operators to the target cluster's
own `/api/v1/swagger` for the cluster-version contract.

The DCP adapter contains an experimental `runner_userdata_factory` path that
adds a `userdata` field, but this field is **not verified against the currently
published public schema**. Treat the path as disabled/unaccepted: Gateway
readiness remains false, and live provisioning must not be attempted until
MacStadium and the target cluster's own OpenAPI schema confirm the field,
first-boot execution semantics, and whether request bodies can appear in API,
proxy, audit, or support logs. Do not assume that a write-only response means
the request body is never logged. Never put GitHub registration tokens in
`customMetadata`.

The Gateway selects budget guards by provider. Orka requests require a separate guard keyed to `orka`; an Azure Consumption budget is never accepted as evidence for Orka spend. A generic provider-budget guard contract is available, but no Orka billing reader or provider budget source is configured or verified. Therefore Orka readiness remains false until an authoritative Orka/MacStadium cost source, forecast semantics, currency, and freshness policy are implemented and tested. No Orka capacity was allocated by tests.
