# Reset the local DCP Owner password

Use this procedure only on the Windows computer that hosts the DCP local stack.

1. Stop DCP first: switch to the PowerShell window running the integrated stack and press **Ctrl+C**. Do not stop unrelated services.
2. In the repository folder, double-click `Reset-DCP-Owner-Password.cmd`.
3. The tool displays the existing Owner username, prompts for a new password without echoing it, and requires at least **14 characters**.
4. After the tool confirms success, double-click `Start-DCP-Local.cmd`.
5. Sign in at `http://127.0.0.1:8789/` using the unchanged username and new password.

The reset tool operates only on `%LOCALAPPDATA%\DCP\owner-auth.json` (or the path configured by `DCP_LOCAL_AUTH_CREDENTIAL_FILE`). It validates the existing credential record, creates a timestamped backup beside it, restricts the backup and replacement file to the current Windows account, and atomically replaces the password hash. It does not delete or modify `gateway.sqlite3`, runner records, project files, or cloud resources.

If the credential file is missing or invalid, the tool stops without creating a new Owner account. Preserve the DCP data directory and investigate rather than deleting it.

Passwords of fourteen characters are accepted as requested, but a longer unique passphrase is strongly recommended. The local service remains bound to loopback; do not expose its ports to a network.
