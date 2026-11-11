# Local Job Control Plane — milestones 1–2

The local-first job API adds a durable SQLite queue, authenticated HTTP lifecycle endpoints, and per-job workspace isolation. It does not execute repository code, launch build commands, create VMs, or enable cloud provisioning.

## Dashboard API

Dashboard routes use the existing trusted-proxy HMAC session. Reads require an owner/operator session. Mutations require same-origin plus CSRF validation. Job cancellation is owner-only.

- `POST /api/jobs` — create with `Idempotency-Key`; payload allows only `repository`, immutable lowercase `commit_sha`, and `target` in `test|build|package|build_android|build_web|build_windows|build_linux|build_macos|build_ios`.
- `GET /api/jobs?limit=50` — list recent jobs.
- `GET /api/jobs/{id}` — inspect a job.
- `GET /api/jobs/{id}/events` — lifecycle events.
- `GET /api/jobs/{id}/logs?after_id=0&limit=500` — paginated logs.
- `POST /api/jobs/{id}/cancel` — owner-only cancellation.

## Runner API

Runner routes use credentials separate from the gateway's internal API token and browser session. Configure `DCP_RUNNER_TOKENS` as a JSON object mapping worker IDs to unique tokens of at least 32 characters. Do not commit tokens or put them in dashboard configuration.

- `POST /v1/runner/register` — register host OS and allowlisted build capabilities; worker identity comes from its credential, never the request body.
- `POST /v1/runner/ping` — refresh fleet liveness.
- `POST /v1/runner/claim` — optional `lease_seconds` (5–300); only jobs supported by the registered Runner capabilities are claimable.
- `POST /v1/runner/{id}/heartbeat` — renew the authenticated worker's active lease.
- `POST /v1/runner/{id}/logs` — append a bounded stdout/stderr/system log message.
- `POST /v1/runner/{id}/finish` — report `succeeded|failed|cancelled`; only the current lease owner can finish.
- `POST /v1/runner/{id}/artifacts` — upload one bounded `application/octet-stream` artifact while the authenticated worker owns the active lease.
- `GET /api/artifacts/{artifact_id}/download` — authenticated Dashboard download with SHA-256 integrity verification.

The jobs database defaults to `DCP_GATEWAY_DATABASE + ".jobs"`; override with `DCP_GATEWAY_JOBS_DATABASE`.

## Safety boundary

Expired leases are recovered before a claim. Old workers are fenced by the lease checks in the store. The API accepts no shell command, arbitrary environment, filesystem path, or provider selection. Workspace allocation is local to the Runner host and does not imply repository checkout or build execution. Artifact upload/storage, VM creation, and Cloud Provisioning remain disabled. Flutter build execution is opt-in and restricted to an explicit trusted-repository allowlist. It runs on the Runner host; it is not an OS sandbox, so only repositories approved by the operator may be executed, and production runners should be disposable/isolated hosts.


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


## M6 — Flutter Build Execution

The Runner Agent now has a one-job execution pipeline:

`Gateway claim → per-job workspace → immutable GitHub commit archive → Flutter command allowlist → bounded process → Gateway logs/status → workspace cleanup`.

- `GitHubCommitCheckout` downloads only `https://api.github.com/repos/{owner}/{repo}/zipball/{commit_sha}`; redirects are HTTPS-only and restricted to GitHub archive hosts.
- Archive download and expanded size, entry count, paths, and file types are bounded. Path traversal, symlinks, special files, and non-Flutter commits are rejected. No Git hooks, submodules, or repository scripts run during checkout.
- Before each target command, the Runner executes the fixed `flutter pub get --enforce-lockfile` step against the committed `pubspec.lock`; missing or symlink lockfiles are rejected. Flutter commands are fixed by target; arbitrary shell commands, command arguments, and environment variables are not accepted. The Runner performs a read-only host preflight before execution and rejects configured capabilities that were not detected locally.
- Supported targets: `test`, `build` (Android APK), `package` (Android App Bundle), `build_android`, `build_web`, `build_windows`, `build_linux`, `build_macos`, and `build_ios`.
- macOS/iOS targets require a macOS host; Windows and Linux targets require their corresponding host OS.
- Dependency resolution and target execution share a bounded job deadline and combined output limit, process-tree termination, and periodic Runner lease heartbeat/cancellation checks. Pub, Gradle, temporary, and home caches are isolated beneath the per-job workspace; only required OS/toolchain variables (including the detected Android SDK location on Windows) are passed through.
- Execution is disabled by default. `--check` remains health-only. `--once` processes at most one job and requires `DCP_RUNNER_EXECUTION_ENABLED=1`, an absolute `DCP_RUNNER_WORKSPACE_ROOT`, a non-empty JSON array in `DCP_RUNNER_TRUSTED_REPOSITORIES`, and a successful local Git/Flutter preflight. `DCP_RUNNER_CAPABILITIES`, when supplied, must be a unique subset of preflight-detected capabilities.
- Set `DCP_GITHUB_TOKEN` only as a host environment secret when private-repository read access is required. It is not stored in a job, logged, or passed in a URL.
- Build outputs are packaged by `FlutterArtifactPackager`, uploaded through the authenticated Runner endpoint, indexed with SHA-256 metadata, and downloadable through the authenticated Dashboard Artifact Center.

Example PowerShell configuration (use a dedicated, disposable Runner host and an operator-approved repository):

```powershell
$env:DCP_GATEWAY_URL = "https://<your-gateway-origin>"
$env:DCP_RUNNER_WORKER_ID = "local-worker-01"
$env:DCP_RUNNER_TOKEN = "<dedicated-runner-token>"
$env:DCP_RUNNER_EXECUTION_ENABLED = "1"
$env:DCP_RUNNER_WORKSPACE_ROOT = "D:\\DCP\\workspaces"
$env:DCP_RUNNER_TRUSTED_REPOSITORIES = '["owner/repository"]'
$env:DCP_RUNNER_CAPABILITIES = '["flutter","android","web"]' # Add windows only when Visual Studio C++ toolchain preflight passes
python -m tools.local_runner_agent --once
```

The command processes no more than one queued job. The host must have the Flutter SDK installed and on PATH. The Flutter process runs on the Runner host rather than inside an OS sandbox; do not add repositories to the trusted list unless their build/test code is approved for execution on that host.


## M7 — Artifact Center

- Flutter build output is collected from target-specific output paths. Single-file outputs (APK/AAB) are stored directly; directory outputs (Web, Windows, Linux, macOS, iOS) are packaged into a bounded ZIP.
- Runner uploads use a dedicated bearer-authenticated endpoint and a sanitized filename header; browser credentials are never used for Runner upload.
- Gateway storage uses a private absolute directory (default: `<DCP_GATEWAY_DATABASE>.artifacts`) configurable with `DCP_GATEWAY_ARTIFACTS_ROOT`.
- `DCP_GATEWAY_MAX_ARTIFACT_BYTES` controls the per-artifact upload limit (default 100 MiB; maximum 1 GiB).
- Each artifact receives a UUID, job/worker ownership record, size, creation timestamp, and SHA-256 digest. Upload requires a current Job lease and verifies it again after writing.
- Files are written to private temporary files and atomically moved into storage. Download verifies the stored SHA-256 before streaming the file.
- Dashboard APIs expose metadata only; the download route requires an authenticated owner/operator session and sets private/no-store and nosniff headers.
- The Dashboard Build Jobs panel displays successful Job artifacts with authenticated download links. Artifacts are not exposed for failed or cancelled Jobs.
- Retention pruning is available through `ArtifactStore.prune(retention_days=30)`; scheduling retention is an operator responsibility and is not enabled automatically in this increment.


## M8 — Local Runner Fleet Registry

- The Gateway keeps a persistent inventory of local Runner workers, host OS, declared capabilities, registration time, last-seen time, and state (`online`, `draining`, `offline`). Configure its database with `DCP_GATEWAY_RUNNERS_DATABASE` (default `<DCP_GATEWAY_DATABASE>.runners`) and stale timeout with `DCP_GATEWAY_RUNNER_STALE_SECONDS`.
- Worker identity is derived from its dedicated Runner token; the client never supplies its own worker ID in registration or heartbeat payloads.
- A Runner must register before claiming work. Job claims are filtered by the Runner's registered capabilities: Flutter test, Android, Web, Windows, Linux, macOS, and iOS.
- Unsupported platform jobs remain queued for a compatible worker instead of being claimed and failing on the wrong OS.
- Runner liveness is refreshed during active builds. Workers older than `DCP_GATEWAY_RUNNER_STALE_SECONDS` (default 60 seconds; allowed 15–3600) are reported offline.
- Dashboard operators can Drain a worker to stop new claims while allowing its active Job to finish, then Enable it again. A stale worker becomes online again only after it checks in.
- `host_os` is recorded separately from build capabilities. Configure `DCP_RUNNER_CAPABILITIES` as a JSON array containing only targets actually detected by local preflight (for example `flutter`, `android`, `web`, `windows`, `linux`, `macos`, `ios`). A Windows host without Visual Studio may still register for Android/Web work but will not advertise Windows desktop builds. The default uses the full preflight-detected capability set; cross-platform targets are never assumed.
- The CLI remains one-shot (`--once`); continuous polling/daemon supervision is a separate deployment decision.
