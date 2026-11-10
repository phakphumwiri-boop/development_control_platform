# DCP Runner Scheduler

## Purpose

The Runner Scheduler connects the durable job queue to the authenticated local
Runner Registry. A job is leased only to a registered, online, non-draining
runner whose advertised capabilities and host OS match the requested target.

## Target matching

| Job target | Required host | Additional capability |
| --- | --- | --- |
| `test`, `build`, `package` | Linux, Windows, or macOS | `flutter` |
| `build_android` | Registered host OS | `android` |
| `build_web` | Registered host OS | `web` |
| `build_linux` | Linux | `linux` |
| `build_windows` | Windows | `windows` |
| `build_macos` | macOS | `macos` |
| `build_ios` | macOS | `macos` and `ios` |

The registry validates that a runner cannot advertise another host operating
system. The scheduler independently enforces host matching for OS-specific
build targets before calling the durable queue claim operation.

## Infrastructure boundary

- The scheduler claims work only for an authenticated Runner Registry identity.
- The Infrastructure Manager catalog is descriptive; catalog images/templates
  are not execution hosts.
- Fake Provider resources are simulations and are never eligible runners.
- No automatic VM provisioning or scale-out occurs when no runner is eligible.
- External provisioning remains disabled.
- A macOS build can be claimed only by an online registered macOS runner with
  the required capability. A macOS catalog entry or fake VM is not sufficient.
- iOS additionally requires the explicit `ios` capability on that macOS runner.

## API behavior

The existing runner endpoint `POST /v1/runner/claim` now delegates to
`RunnerScheduler`. If the Runner Registry is unavailable, the Gateway fails
closed instead of falling back to an unfiltered queue claim. The response
continues to return either the leased job or `null`.

## Validation

Run:

```sh
python -m unittest tests.test_cloud_gateway_scheduler_integration -v
python -m unittest tests.test_cloud_gateway_runner_registry -v
python -m unittest discover -s tests -v
```

Tests use temporary SQLite stores and fake infrastructure metadata only. They
do not create VMs, execute repository code, or contact external providers.
