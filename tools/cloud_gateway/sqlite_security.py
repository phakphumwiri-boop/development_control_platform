"""Private-permission preparation for local SQLite database files."""
from __future__ import annotations

import os
import stat
from pathlib import Path


def prepare_private_sqlite_file(path: str | os.PathLike) -> None:
    """Create a SQLite file with owner-only POSIX permissions.

    Windows relies on the ACL inherited from the user-controlled parent directory
    (normally %LOCALAPPDATA%\\DCP); POSIX hosts get an explicit 0600 file mode.
    Symlink and non-regular database paths are rejected on every platform.
    """
    if str(path) == ":memory:":
        return
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(target), flags, 0o600)
    except FileExistsError:
        descriptor = None
    except OSError as exc:
        raise ValueError("SQLite database path cannot be created safely") from exc
    if descriptor is not None:
        os.close(descriptor)
    try:
        info = target.lstat()
    except OSError as exc:
        raise ValueError("SQLite database path is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError("SQLite database path must be a regular file, not a symlink")
    if os.name == "posix":
        try:
            os.chmod(target, 0o600, follow_symlinks=False)
        except OSError as exc:
            raise ValueError("SQLite database permissions could not be restricted") from exc
