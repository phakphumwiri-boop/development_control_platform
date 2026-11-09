"""Safely reset the local DCP Owner password without changing the Owner account."""
from __future__ import annotations

import getpass
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Make imports work when launched as: py -3 tools\\reset_owner_password.py
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.local_auth_proxy import (  # noqa: E402
    CREDENTIALS,
    MIN_PASSWORD_LENGTH,
    PORT,
    password_record,
)


def _validate_record(record: object) -> dict:
    if not isinstance(record, dict):
        raise ValueError("Owner credential file is not a JSON object.")
    try:
        valid = (
            isinstance(record.get("username"), str)
            and bool(record["username"])
            and record.get("algorithm") == "pbkdf2_sha256"
            and len(bytes.fromhex(record["salt"])) == 32
            and len(bytes.fromhex(record["password_hash"])) == 32
            and int(record["rounds"]) >= 300_000
        )
    except (KeyError, TypeError, ValueError):
        valid = False
    if not valid:
        raise ValueError("Owner credential file is invalid; no changes were made.")
    return record


def _restrict_file(path: Path) -> None:
    if os.name == "nt":
        who = subprocess.run(
            ["whoami.exe"], check=True, capture_output=True, text=True
        ).stdout.strip()
        if not who:
            raise RuntimeError("Could not identify the current Windows account for file permissions.")
        subprocess.run(
            ["icacls.exe", str(path), "/inheritance:r", "/grant:r", f"{who}:(F)"],
            check=True, capture_output=True, text=True,
        )
    else:
        path.chmod(0o600)


def reset_owner_password(path: Path, password: str, confirmation: str) -> Path:
    """Write a new salted hash and return the protected backup path."""
    path = Path(path)
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must contain at least {MIN_PASSWORD_LENGTH} characters.")
    if password != confirmation:
        raise ValueError("Passwords do not match.")
    if not path.is_file():
        raise FileNotFoundError(f"Owner credential file was not found: {path}")

    current = _validate_record(json.loads(path.read_text(encoding="utf-8")))
    new_record = password_record(current["username"], password)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup = path.with_name(path.name + ".backup-" + stamp)
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    shutil.copy2(path, backup)
    try:
        _restrict_file(backup)
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(new_record, handle, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        _restrict_file(temporary)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return backup


def _proxy_is_running() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=0.5):
            return True
    except OSError:
        return False


def main() -> int:
    print("DCP local Owner password reset")
    print("This tool changes only the local owner-auth.json file.")
    if _proxy_is_running():
        print(f"STOP: Local Auth Proxy is still running on 127.0.0.1:{PORT}.")
        print("Stop the DCP stack first (Ctrl+C in its PowerShell window), then run this tool again.")
        return 2
    try:
        current = _validate_record(json.loads(CREDENTIALS.read_text(encoding="utf-8")))
        print(f"Owner username (unchanged): {current['username']}")
        password = getpass.getpass("New Owner password (minimum 14 characters): ")
        confirmation = getpass.getpass("Confirm new password: ")
        backup = reset_owner_password(CREDENTIALS, password, confirmation)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"RESET FAILED: {exc}")
        return 1

    print("Owner password reset successfully.")
    print(f"Protected backup created: {backup}")
    print("Start DCP again with Start-DCP-Local.cmd and sign in with the new password.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
