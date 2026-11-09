# DCP Infrastructure Manager — Phase 1

## Scope

This increment introduces a DCP-owned, provider-neutral infrastructure inventory and lifecycle contract. It is deliberately local-first. The initial `FakeInfrastructureProvider` is a deterministic simulation and does not create VMs, containers, cloud resources, or paid capacity.

## Components

- `InfrastructureManager`: validates image/template compatibility, provider readiness, idempotency, and lifecycle operations.
- `InfrastructureStore`: durable SQLite inventory and credential-free lifecycle audit events.
- `InfrastructureProvider`: provider-neutral readiness/create/inspect/start/stop/delete contract.
- `FakeInfrastructureProvider`: simulation implementation for development and tests.
- Image catalog: pinned logical DCP image identifiers for Linux, Windows, and macOS.
- Template catalog: bounded CPU, memory, disk metadata for each target OS.

## Lifecycle

`provisioned -> running -> stopped -> running -> deleted`

Invalid transitions fail with a lifecycle conflict. Delete is idempotent. Resource creation is idempotent by caller-supplied key; reusing a key for a different OS/image/template is rejected.

## Safety

- External providers are disabled unless `provisioning_enabled=True` is explicitly supplied by a future composition layer.
- Fake provider is the only default provider and performs no external I/O.
- No Azure, Orka, Hyper-V, Apple host, network, or cloud SDK is called.
- No provider credentials or secrets are stored in the inventory.
- macOS image metadata is catalog metadata only; it is not evidence of macOS host availability or build readiness.
- This phase does not expose unauthenticated HTTP lifecycle endpoints or enable the existing Gateway provisioning route.

## Validation

Run:

```sh
python -m unittest tests.test_cloud_gateway_infrastructure -v
```

The tests use temporary SQLite databases and the fake provider only. Live infrastructure acceptance remains a separate, explicitly approved phase.
