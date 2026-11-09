# Windows 11 self-hosted deployment (local resources)

**Status:** local development and owner-authenticated Dashboard/Gateway stack. Cloud runner provisioning and remote production deployment remain disabled.

This deployment runs on the Windows 11 PC's own CPU, memory, and disk. It does not require Azure, Orka, Docker, a paid cloud subscription, a public IP, or an inbound firewall rule.

## 1. Recommended: integrated local stack

Use this path for normal local operation. It starts the Dashboard, password-authenticated Local Auth Proxy, and Gateway together.

### Requirements

- Windows 11 x64
- Python 3.10+ and the Python Launcher (`py.exe`)
- Git is optional for running the stack
- Node.js/Playwright are optional and needed only for browser smoke tests

The default stack uses Python's standard library. No pip installation is required for the local Dashboard/Auth Proxy/Gateway path.

### First startup

1. Download or clone this repository to a folder you control.
2. Double-click `Setup-DCP-Local.cmd` once for the read-only preflight.
3. Double-click `Start-DCP-Local.cmd`.
4. In the separate PowerShell window, create an owner username and password when prompted. The password must be at least 14 characters and is entered twice.
5. Open `http://127.0.0.1:8789/` and sign in.

The owner credential record is stored at `%LOCALAPPDATA%\DCP\owner-auth.json` as a salted PBKDF2-HMAC-SHA256 hash (600,000 rounds), not plaintext. The file is restricted to the current Windows account. The Gateway database is `%LOCALAPPDATA%\DCP\gateway.sqlite3`.

### Service and security boundaries

| Component | Address / storage | Behavior |
| --- | --- | --- |
| Dashboard + Local Auth Proxy | `127.0.0.1:8789` | Serves the Dashboard, verifies owner password, manages HttpOnly/SameSite session and CSRF |
| Gateway | `127.0.0.1:8790` | Independently verifies signed proxy identity assertions and replay nonces |
| Owner credential hash | `%LOCALAPPDATA%\DCP\owner-auth.json` | Salted PBKDF2 hash; no plaintext password |
| Gateway database | `%LOCALAPPDATA%\DCP\gateway.sqlite3` | Local lifecycle and audit data |

The Gateway bearer token and trusted-proxy HMAC secret are generated in memory at startup and are not sent to browser JavaScript or persisted. Sessions are held in memory and are revoked when the process restarts. The integrated stack binds only to loopback and uses HTTP because it is local-only; it is not a remote or multi-user internet login service.

Do not change either service bind address to `0.0.0.0`, expose the ports to a LAN or the internet, add router port forwarding, or disable Windows Defender Firewall.

### Stop and port conflicts

Keep the stack PowerShell window open. Press Ctrl+C in that window to stop the Auth Proxy and its Gateway child process.

If port 8789 or 8790 is already occupied, startup stops and reports the conflict. It does not terminate the existing listener. Inspect the process owner before taking any action; do not stop an unverified process.

## 2. Optional: standalone static Dashboard

`Start-DCP-Dashboard.ps1 -OpenBrowser` starts the static Dashboard only, usually on an automatically selected local port. It does not start the Gateway and is not the authenticated integrated stack. Use `Start-DCP-Local.cmd` for the complete owner-authenticated experience.

## 3. Local validation

From the repository root:

```powershell
py -3 -m tools.cloud_gateway.local_mode
py -3 -m unittest discover -s tests -v
```

For browser smoke tests, install the optional Node.js/Playwright dependencies as described in the repository validation instructions. GitHub Actions additionally runs the Windows launcher/Auth Proxy/Gateway integration and Linux Gateway tests. CI uses hosted runners; it is not a substitute for a final run on your own PC.

## 4. Optional: GitHub Actions self-hosted runner

A GitHub Actions self-hosted runner is a separate GitHub worker process. It is not the DCP Gateway and does not enable DCP-managed ephemeral runner provisioning.

1. In the repository, open **Settings → Actions → Runners → New self-hosted runner**.
2. Select Windows and x64.
3. Follow the exact, short-lived registration commands shown by GitHub in a local PowerShell window. Never paste the registration token into ChatGPT, a commit, an issue, or a log.
4. Start interactively first. Configure a Windows service only after reviewing workflow permissions and deciding that the machine may execute jobs unattended.
5. Prefer a dedicated Windows account and a workspace with no personal secrets. Do not run untrusted pull-request code on a self-hosted runner that can access private files or credentials.

## 5. What is not enabled

- `DCP_GATEWAY_PROVISIONING_ENABLED=false`
- `DCP_GATEWAY_OWNER_APPROVED=false`
- The runtime provider remains `DisabledProvider`; DCP cannot create or terminate Azure/Orka/local ephemeral runners.
- Provider adapters, mock tests, or a successful CI run do not prove a real VM or GitHub runner is online.
- Remote access, multi-user authorization, TLS termination, production identity federation, and production security review are not supplied by this local-only setup.

Keep the deployment private and local until those separate production gates are implemented and independently accepted.
