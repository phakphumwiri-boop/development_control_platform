# Windows 11 one-click local startup

This starts the Dashboard, Local Auth Proxy, and Gateway on your own Windows 11 PC. The services use local CPU, memory, and disk only; no Azure, Orka, Docker, paid cloud account, public IP, or inbound firewall rule is required.

## Requirements

- Windows 11 x64
- Python 3.10+ and the Python Launcher (`py.exe`)
- Git is optional

The default local stack uses Python's standard library and does not require a pip install. Optional GitHub App/cloud integrations have separate dependencies and are not enabled by this local setup.

## First run

1. Download or clone this repository to a folder you control.
2. Double-click `Setup-DCP-Local.cmd` to run the read-only environment doctor.
3. Double-click `Start-DCP-Local.cmd`.
4. In the separate PowerShell window, choose an owner username (1–64 ASCII letters, digits, dot, underscore, @, or hyphen) and a password of at least 14 characters, then confirm the password. This happens only on first launch.
5. Open the Dashboard at `http://127.0.0.1:8789/` and sign in with that username and password.

The owner password is stored as a salted PBKDF2-HMAC-SHA256 hash in `%LOCALAPPDATA%\DCP\owner-auth.json`, never as plaintext. The local Auth Proxy issues an HttpOnly, SameSite=Strict session cookie. Session state, the Gateway bearer token, and the trusted-proxy HMAC secret remain in process memory. The browser never receives Gateway credentials.

## Local service layout

- Dashboard + Auth Proxy: `127.0.0.1:8789`
- Gateway: `127.0.0.1:18790`
- SQLite data: `%LOCALAPPDATA%\DCP\gateway.sqlite3`
- Owner credential hash: `%LOCALAPPDATA%\DCP\owner-auth.json`

The Auth Proxy serves the Dashboard, validates the owner password, manages sessions and CSRF, then signs short-lived HMAC identity assertions when forwarding allowlisted API requests to the Gateway. The Gateway independently verifies the signature and replay nonce. The API token and HMAC secret are never exposed to browser JavaScript.

This is an HTTP service bound exclusively to loopback. Do not change the bind address to `0.0.0.0`, expose the ports to the LAN/internet, or use it as a remote multi-user login service. The cookie is HttpOnly and SameSite=Strict; loopback HTTP is used because this stack is local-only and does not configure a local TLS certificate.

## Recon Back Box integration

The Recon Back Box is served at `/recon-back-box/` from the same local Dashboard origin.
Its read-only source data is the public `phakphum12345/Drive-letter` repository. The browser
calls only the authenticated same-origin `/api/recon/*` endpoints; the Local Auth Proxy
forwards those requests to the local Gateway, which fetches a fixed allowlist of public
GitHub metadata and the four versioned JSON configs from `main`. No GitHub token is
stored in the browser or local stack.

The local integration requires an authenticated DCP Owner session. Recon source access is
read-only: exported config edits are review material and are not pushed to GitHub. The
Drive-letter connection must not be treated as a durable write path unless a separately
approved GitHub App integration with repository write permission is configured.

## Stop

Press `Ctrl+C` in the PowerShell window running the integrated stack. It stops both the Auth Proxy and its Gateway child process.

## Safety and capability boundary

- `DCP_GATEWAY_PROVISIONING_ENABLED=false`
- `DCP_GATEWAY_OWNER_APPROVED=false`
- Cloud provisioning remains disabled. No runner is created or deleted by this local integration.
- The Gateway still uses fail-closed disabled provider adapters; this does not create local VMs, containers, or ephemeral DCP-managed runners.
- The optional manually registered GitHub Actions self-hosted runner is a separate GitHub feature.

The automated Linux and Windows emulator workflows exercise login, session issuance, signed Gateway API access, CSRF/origin enforcement, logout/revocation, and safe provisioning defaults. They do not replace a final test on your own Windows 11 computer.

For broader deployment limitations, see [Windows 11 self-hosted deployment](windows-11-self-hosted.md).
