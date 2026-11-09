# Local Job Control Plane — milestones 1–2

The local-first job API adds a durable SQLite queue, authenticated HTTP lifecycle endpoints, and per-job workspace isolation. It does not execute repository code, launch build commands, create VMs, or enable cloud provisioning.

## Dashboard API

Dashboard routes use the existing trusted-proxy HMAC session. Reads require an owner/operator session. Mutations require same-origin plus CSRF validation. Job cancellation is owner-only.

- `POST /api/jobs` — create with `Idempotency-Key`; payload allows only `repository`, immutable lowercase `commit_sha`, and `target` in `test|build|package`.
- `GET /api/jobs?limit=50` — list recent jobs.
- `GET /api/jobs/{id}` — inspect a job.
- `GET /api/jobs/{id}/events` — lifecycle events.
- `GET /api/jobs/{id}/logs?after_id=0&limit=500` — paginated logs.
- `POST /api/jobs/{id}/cancel` — owner-only cancellation.

## Runner API

Runner routes use credentials separate from the gateway's internal API token and browser session. Configure `DCP_RUNNER_TOKENS` as a JSON object mapping worker IDs to unique tokens of at least 32 characters. Do not commit tokens or put them in dashboard configuration.

- `POST /v1/runner/claim` — optional `lease_seconds` (5–300); worker identity comes from its credential, never the request body.
- `POST /v1/runner/{id}/heartbeat` — renew the authenticated worker's active lease.
- `POST /v1/runner/{id}/logs` — append a bounded stdout/stderr/system log message.
- `POST /v1/runner/{id}/finish` — report `succeeded|failed|cancelled`; only the current lease owner can finish.

The jobs database defaults to `DCP_GATEWAY_DATABASE + ".jobs"`; override with `DCP_GATEWAY_JOBS_DATABASE`.

## Safety boundary

Expired leases are recovered before a claim. Old workers are fenced by the lease checks in the store. The API accepts no shell command, arbitrary environment, filesystem path, or provider selection. Workspace allocation is local to the Runner host and does not imply repository checkout or build execution. Command policy, process-tree termination, resource limits, build execution, artifacts, VM creation, and Cloud Provisioning remain disabled.


## M3 — Local Runner Agent bootstrap

The first Agent increment is a control-plane-only client. It can validate configuration, read Gateway health, and call the authenticated claim/heartbeat/log/finish contracts. It does not poll continuously, clone repositories, create workspaces, spawn subprocesses, or execute build commands.

Required environment:
- `DCP_GATEWAY_URL` — HTTPS Gateway origin; HTTP is accepted only for loopback development.
- `DCP_RUNNER_WORKER_ID` — worker identity registered by the Gateway credential map.
- `DCP_RUNNER_TOKEN` — dedicated worker token (32+ characters); never pass it as a command-line argument or print it.
- `DCP_RUNNER_TIMEOUT_SECONDS` — optional request timeout (1–60; default 20).

Safe connectivity check:

```powershell
$env:DCP_GATEWAY_URL = "http://127.0.0.1:8789"
$env:DCP_RUNNER_WORKER_ID = "local-worker-01"
$env:DCP_RUNNER_TOKEN = "<dedicated-worker-token>"
python -m tools.local_runner_agent --check
```

The check reads only `/healthz`; it does not claim a job. The client uses Python's standard HTTPS certificate validation for remote Gateway origins. Job execution remains disabled until workspace isolation, command policy, cancellation, and resource limits are implemented and tested.


## M5 — Per-job Workspace Isolation

`tools/local_runner_agent/workspace.py` provides a local `WorkspaceManager` for Runner hosts.

- Every workspace is created beneath one configured absolute root, using the canonical Job UUID as its directory name.
- Workspace directories are mode `0700`; the ownership marker is mode `0600` and binds the directory to the exact Job UUID and authenticated worker ID.
- Duplicate allocation, cross-job/cross-worker access, symlink roots, symlink workspace entries, and path escapes fail closed.
- Active workspace count is bounded (default 8); regular-file bytes are measured against a per-workspace quota (default 2 GiB).
- Cleanup requires a valid ownership marker and removes only the matching Job workspace.
- The workspace manager does not clone a repository, extract an archive, spawn a process, or execute a build.

Example (local Runner process only):

```python
from tools.local_runner_agent.workspace import WorkspaceManager

manager = WorkspaceManager("/var/lib/dcp/workspaces")
workspace = manager.create(job_id, authenticated_worker_id)
# Future checkout/build stages may use this directory after their own policy gates.
manager.check_quota(job_id, authenticated_worker_id)
manager.cleanup(job_id, authenticated_worker_id)
```

The workspace E2E acceptance test creates a Job in the SQLite queue, claims it as a Runner, allocates an isolated workspace, verifies ownership and quota, cleans it, and records a terminal cancellation. It deliberately does not check out or execute untrusted repository content.
