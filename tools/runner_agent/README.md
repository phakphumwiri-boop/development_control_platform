# DCP Local Runner Agent

The Runner Agent connects an explicitly configured local host to the DCP Gateway.
It registers host capabilities, renews runner/job liveness, claims compatible
jobs, checks out the exact requested Git commit, runs an allowlisted Flutter
command, uploads a build archive, and reports the terminal result.

## Security boundary

**Execution is disabled unless `DCP_RUNNER_EXECUTION_ENABLED=true`.** Enabling
it means the runner host will execute Flutter project build scripts and other
code from the selected repository commit. Use a dedicated, disposable VM or
host account with no personal files, cloud credentials, or broad network access.
Do not run this agent on a workstation containing sensitive credentials.

- The Gateway URL must use HTTPS; plain HTTP is accepted only for loopback.
- Runner tokens are unique per worker and are configured at the Gateway through
  `DCP_RUNNER_TOKENS`, a JSON object mapping worker IDs to 32+ character secrets.
- Keep tokens in a secret manager/environment injection, never in source control.
- Private GitHub repositories require a preconfigured Git credential helper on
  the runner. The agent does not copy GitHub App or dashboard credentials.
- Git checkout is detached at the immutable commit SHA returned by the Gateway.
  The agent verifies `git rev-parse HEAD` before running Flutter.
- Commands use a fixed target allowlist with `shell=False`; Windows Flutter
  batch shims are launched through an explicit `cmd.exe` command line.
- Execution requires an exact `DCP_RUNNER_TRUSTED_REPOSITORIES` JSON allowlist.
  Jobs for other repositories are rejected before checkout.
- Build subprocesses receive only an allowlist of OS/toolchain variables.
  Runner tokens, GitHub tokens, and other arbitrary parent-process variables
  are never forwarded to project build code.
- HOME, APPDATA, LOCALAPPDATA, temporary files, and package caches are isolated
  to the job workspace; Android SDK and Visual Studio paths are preserved
  explicitly when required.
- OS-specific jobs are rejected locally if the host OS does not match.
- Build logs are streamed to the job; the job lease is renewed while commands run.
- APK/AAB outputs are uploaded as their original files; directory outputs are
  packaged as bounded ZIP files. The Gateway validates the lease and computes SHA-256.
- This MVP does not provide OS-level sandboxing. Network isolation, ephemeral
  host reset, and least-privilege runner credentials remain deployment duties.

## Supported targets

| Target | Flutter command | Artifact |
| --- | --- | --- |
| `test` | `flutter test` | None |
| `build`, `build_android` | `flutter build apk --release` | APK |\n| `package` | `flutter build appbundle --release` | AAB |
| `build_web` | `flutter build web --release` | ZIP of web output |
| `build_linux` | `flutter build linux --release` | ZIP of Linux bundle |
| `build_windows` | `flutter build windows --release` | ZIP of Windows bundle |
| `build_macos` | `flutter build macos --release` | ZIP of macOS bundle |
| `build_ios` | `flutter build ios --release --no-codesign` | ZIP of iOS app bundle |

A macOS/iOS build requires an actual macOS host with Flutter/Xcode installed and
registered with the matching capabilities. A catalog image or fake VM is not
a macOS build host.

## Configure the Gateway

Example (use a secret manager in production):

```powershell
$env:DCP_RUNNER_TOKENS = '{"win-runner-01":"<unique-32+-character-secret>"}'
```

Restart the Gateway after configuring the token map. Ensure the Runner Registry
database and job/artifact stores are persistent.

## Safe Runner Enrollment (no build execution)

After the read-only preflight passes, configure the Gateway URL, worker ID,
and the unique runner token already provisioned for that worker:

```powershell
$env:DCP_GATEWAY_URL = "https://dcp.example.internal"
$env:DCP_RUNNER_ID = "win-runner-01"
$env:DCP_RUNNER_TOKEN = "<same-secret-configured-on-gateway>"
# Optional: restrict the detected capabilities; this cannot add capabilities.
$env:DCP_RUNNER_CAPABILITIES = "flutter,windows,android,web"
python -m tools.runner_agent.agent --enroll-only
```

Enrollment uses the authenticated `POST /v1/runner/enroll` endpoint. The
Gateway records the host as **offline** so it is visible in the Runner inventory
but cannot claim jobs. The command exits immediately after registration; it
does not ping, claim, clone, checkout, or execute a repository. It never needs
`DCP_RUNNER_EXECUTION_ENABLED`. The optional capability list must be a
non-empty subset of the local preflight results. If omitted, all locally
detected capabilities are registered.

## Start a Runner (separate explicit opt-in)

Only on a dedicated, disposable host after enrollment and operator review:

```powershell
$env:DCP_RUNNER_TRUSTED_REPOSITORIES = '["owner/mobile-app"]'
$env:DCP_RUNNER_EXECUTION_ENABLED = "true"
python -m tools.runner_agent.agent --once
```

The trusted repository JSON array is mandatory before execution can start.
Use exact `owner/repository` entries; do not add repositories merely to make
a job pass. The Runner rejects non-allowlisted jobs before any checkout.

For a long-running service, omit `--once` and supervise the process with the
host's service manager. Execution remains disabled unless explicitly enabled.
The running agent registers as online and sends liveness pings. Linux/macOS use
the same environment variables in their service manager; advertise only
capabilities detected by preflight. Add `ios` only to a macOS runner with a
working Xcode toolchain.

## Validation

```sh
python -m unittest tests.test_runner_agent -v
python -m unittest discover -s tests -v
```

Tests do not contact the Gateway, clone repositories, or run Flutter builds.
Security regression tests also verify strict Gateway origin validation,
trusted-repository enforcement, child-process secret isolation, and bounded
artifact handling.
A real host acceptance test is still required for each supported operating
system. In particular, macOS readiness is not claimed until a real Mac Runner
has registered and completed a build.

## Read-only host preflight (first step before enrollment)

Run this on the candidate Windows, Linux, or macOS host:

```sh
python -m tools.runner_agent.preflight
python -m tools.runner_agent.preflight --json
```

Preflight checks installed toolchain commands and reports conservative platform
capabilities. It does not contact the Gateway, read or print runner tokens,
install software, clone repositories, or enable execution. The
`minimum_agent_prerequisites_met` field means only that Git and Flutter are
present; it does **not** mean the host is enrolled or ready to execute jobs.
Platform capabilities are reported only when their platform toolchain is found.
Android additionally requires Java and an Android SDK/ADB. Windows requires
Visual Studio, Linux requires Clang/CMake/Ninja, and macOS/iOS requires Xcode.
A separate real-host acceptance build is still required before declaring a
platform production-ready.

Version probes decode subprocess output as UTF-8 with replacement handling so
Windows console code pages cannot crash the preflight reader thread.
