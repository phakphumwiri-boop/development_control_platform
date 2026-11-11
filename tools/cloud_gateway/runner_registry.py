"""Local Runner inventory, capability registry, drain controls, and liveness."""
from __future__ import annotations

import json
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .sqlite_security import prepare_private_sqlite_file


_WORKER = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")
_OS = {"linux", "windows", "macos"}
_CAPABILITIES = {"flutter", "android", "web", "linux", "windows", "macos", "ios"}


class WorkerNotFound(KeyError):
    pass


class WorkerConflict(RuntimeError):
    pass


def _now():
    return datetime.now(timezone.utc)


class RunnerRegistry:
    """SQLite registry; worker identity is always supplied by the credential verifier."""

    def __init__(self, path="dcp-runners.sqlite3", stale_after_seconds: int = 60):
        if isinstance(stale_after_seconds, bool) or not isinstance(stale_after_seconds, int) or not 15 <= stale_after_seconds <= 3600:
            raise ValueError("stale_after_seconds must be between 15 and 3600")
        self.path = str(path)
        prepare_private_sqlite_file(self.path)
        self.stale_after_seconds = stale_after_seconds
        self.lock = threading.RLock()
        with self.db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS local_runners (
                    worker_id TEXT PRIMARY KEY,
                    host_os TEXT NOT NULL,
                    capabilities TEXT NOT NULL,
                    state TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS local_runners_seen_idx ON local_runners(last_seen)")

    @contextmanager
    def db(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _validate(worker_id: str, host_os: str, capabilities):
        if not isinstance(worker_id, str) or not _WORKER.fullmatch(worker_id):
            raise ValueError("invalid worker ID")
        if not isinstance(host_os, str) or host_os not in _OS:
            raise ValueError("host_os must be linux, windows, or macos")
        if not isinstance(capabilities, list) or not 1 <= len(capabilities) <= 7:
            raise ValueError("capabilities must be a non-empty array")
        if any(not isinstance(item, str) or item not in _CAPABILITIES for item in capabilities):
            raise ValueError("unsupported Runner capability")
        if len(set(capabilities)) != len(capabilities) or "flutter" not in capabilities:
            raise ValueError("capabilities must be unique and include flutter")
        if host_os not in capabilities:
            raise ValueError("capabilities must include the Runner host OS")
        if any(item in capabilities and item != host_os for item in _OS):
            raise ValueError("Runner cannot claim another host operating system capability")

    def _decode(self, row):
        if row is None:
            return None
        item = dict(row)
        item["capabilities"] = json.loads(item["capabilities"])
        last_seen = datetime.fromisoformat(item["last_seen"])
        if item["state"] != "draining" and last_seen < _now() - timedelta(seconds=self.stale_after_seconds):
            item["state"] = "offline"
        return item

    def register(
        self, worker_id: str, host_os: str, capabilities: list[str], *, online: bool = True
    ) -> dict:
        if not isinstance(online, bool):
            raise ValueError("online must be a boolean")
        self._validate(worker_id, host_os, capabilities)
        now = _now().isoformat()
        with self.lock, self.db() as conn:
            old = conn.execute(
                "SELECT state,registered_at FROM local_runners WHERE worker_id=?", (worker_id,)
            ).fetchone()
            # Enrollment records an installed host without claiming it is live.
            # A currently draining runner remains draining until an owner enables it.
            state = "draining" if old and old["state"] == "draining" else ("online" if online else "offline")
            registered_at = old["registered_at"] if old else now
            conn.execute("""
                INSERT INTO local_runners(worker_id,host_os,capabilities,state,registered_at,last_seen)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(worker_id) DO UPDATE SET
                    host_os=excluded.host_os, capabilities=excluded.capabilities,
                    state=excluded.state, last_seen=excluded.last_seen
            """, (worker_id, host_os, json.dumps(sorted(capabilities)), state, registered_at, now))
        return self.get(worker_id)

    def heartbeat(self, worker_id: str) -> dict:
        now = _now().isoformat()
        with self.lock, self.db() as conn:
            row = conn.execute(
                "SELECT state FROM local_runners WHERE worker_id=?", (worker_id,)
            ).fetchone()
            if row is None:
                raise WorkerNotFound(worker_id)
            state = "draining" if row["state"] == "draining" else "online"
            conn.execute(
                "UPDATE local_runners SET state=?,last_seen=? WHERE worker_id=?",
                (state, now, worker_id),
            )
        return self.get(worker_id)

    def get(self, worker_id: str) -> dict | None:
        with self.lock, self.db() as conn:
            row = conn.execute(
                "SELECT * FROM local_runners WHERE worker_id=?", (worker_id,)
            ).fetchone()
        return self._decode(row)

    def list_workers(self) -> list[dict]:
        with self.lock, self.db() as conn:
            rows = conn.execute(
                "SELECT * FROM local_runners ORDER BY worker_id"
            ).fetchall()
        return [self._decode(row) for row in rows]

    def allowed_targets(self, worker_id: str) -> list[str]:
        worker = self.get(worker_id)
        if not worker or worker["state"] != "online":
            return []
        caps = set(worker["capabilities"])
        targets = []
        if "flutter" in caps:
            targets.extend(("test", "build", "package"))
        if "android" in caps:
            targets.extend(("build", "build_android", "package"))
        if "web" in caps:
            targets.append("build_web")
        if "windows" in caps:
            targets.append("build_windows")
        if "linux" in caps:
            targets.append("build_linux")
        if "macos" in caps:
            targets.append("build_macos")
        if "macos" in caps and "ios" in caps:
            targets.append("build_ios")
        return sorted(set(targets))

    def drain(self, worker_id: str) -> dict:
        with self.lock, self.db() as conn:
            changed = conn.execute(
                "UPDATE local_runners SET state='draining' WHERE worker_id=?", (worker_id,)
            ).rowcount
            if not changed:
                raise WorkerNotFound(worker_id)
        return self.get(worker_id)

    def enable(self, worker_id: str) -> dict:
        with self.lock, self.db() as conn:
            changed = conn.execute(
                "UPDATE local_runners SET state='online' WHERE worker_id=?", (worker_id,)
            ).rowcount
            if not changed:
                raise WorkerNotFound(worker_id)
        return self.get(worker_id)
