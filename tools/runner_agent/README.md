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
- Commands use argument arrays with `shell=False`; arbitrary job-supplied shell
  commands are not accepted.
- OS-specific jobs are rejected locally if the host OS does not match.
- Build logs are streamed to the job; the job lease is renewed while commands run.
- Artifact uploads use the existing lease-checked Gateway endpoint and bounded
  Artifact Store. The Gateway validates the lease and computes SHA-256.
- This MVP does not provide OS-level sandboxing. Network isolation, ephemeral
  host reset, and least-privilege runner credentials remain deployment duties.

## Supported targets

| Target | Flutter command | Artifact |
| --- | --- | --- |
| `test` | `flutter test` | None |
| `build`, `package`, `build_android` | `flutter build apk --release` | APK |
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

## Configure a Windows Runner

Install Git, Flutter, and the required platform toolchain, then set:

```powershell
$env:DCP_GATEWAY_URL = "https://dcp.example.internal"
$env:DCP_RUNNER_ID = "win-runner-01"
$env:DCP_RUNNER_TOKEN = "<same-secret-configured-on-gateway>"
$env:DCP_RUNNER_CAPABILITIES = "flutter,windows,android,web"
$env:DCP_RUNNER_EXECUTION_ENABLED = "true"
python -m tools.runner_agent.agent --once
```

For a long-running service, omit `--once` and supervise the process with the
host's service manager. Use a different worker ID and unique token for each
runner. Linux/macOS use the same environment variables in their service
manager; advertise only capabilities actually installed and tested on that
host. Add `ios` only to a macOS runner with a working Xcode toolchain.

## Validation

```sh
python -m unittest tests.test_runner_agent -v
python -m unittest discover -s tests -v
```

Tests do not contact the Gateway, clone repositories, or run Flutter builds.
A real host acceptance test is still required for each supported operating
system. In particular, macOS readiness is not claimed until a real Mac Runner
has registered and completed a build.
