"""Local artifact storage with lease checks, SHA-256 metadata, and safe file access."""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
import threading
from contextlib import contextmanager
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_WORKER = re.compile(r"^[A-Za-z0-9_.:-]{1,100}$")


class ArtifactError(RuntimeError):
    """Artifact upload, lookup, or retention failure."""


class ArtifactStore:
    """Store immutable artifact blobs beneath a private root and index their hashes."""

    def __init__(self, root: str | os.PathLike, max_artifact_bytes: int = 100 * 1024 * 1024):
        raw = Path(root).expanduser()
        if not raw.is_absolute():
            raise ValueError("artifact root must be an absolute path")
        if isinstance(max_artifact_bytes, bool) or not isinstance(max_artifact_bytes, int) or not 1024 <= max_artifact_bytes <= 1024 * 1024 * 1024:
            raise ValueError("max_artifact_bytes must be between 1 KiB and 1 GiB")
        if raw.exists() and raw.is_symlink():
            raise ArtifactError("artifact root must not be a symlink")
        raw.mkdir(parents=True, exist_ok=True, mode=0o700)
        if raw.is_symlink() or not raw.is_dir():
            raise ArtifactError("artifact root is not a safe directory")
        self.root = raw.resolve(strict=True)
        if self.root in (Path("/"), Path.home().resolve()):
            raise ArtifactError("artifact root cannot be a filesystem or home root")
        os.chmod(self.root, 0o700)
        self.max_artifact_bytes = max_artifact_bytes
        self.database = self.root / "metadata.sqlite3"
        self.lock = threading.RLock()
        with self._db() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS artifacts (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    storage_key TEXT NOT NULL UNIQUE,
                    size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS artifacts_job_idx ON artifacts(job_id, created_at)")
        try:
            os.chmod(self.database, 0o600)
        except OSError:
            pass

    @contextmanager
    def _db(self):
        conn = sqlite3.connect(self.database, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def _validate_identity(job_id: str, worker_id: str, name: str, size: int):
        try:
            if str(uuid.UUID(job_id)) != job_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ArtifactError("invalid job ID") from None
        if not isinstance(worker_id, str) or not _WORKER.fullmatch(worker_id):
            raise ArtifactError("invalid worker identity")
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in (".", ".."):
            raise ArtifactError("invalid artifact filename")
        if isinstance(size, bool) or not isinstance(size, int) or size < 1:
            raise ArtifactError("artifact size must be positive")

    @staticmethod
    def _assert_lease(job_store, job_id: str, worker_id: str):
        row = job_store.get(job_id)
        if not row or row.get("state") not in ("running", "cancel_requested") or row.get("worker") != worker_id:
            raise ArtifactError("Runner does not own an active Job")
        try:
            expiry = datetime.fromisoformat(row["lease_until"])
        except (TypeError, ValueError, KeyError):
            raise ArtifactError("Job lease is invalid") from None
        if expiry <= datetime.now(timezone.utc):
            raise ArtifactError("Job lease has expired")
        return row

    def store(self, job_store, job_id: str, worker_id: str, name: str, source, size: int) -> dict:
        self._validate_identity(job_id, worker_id, name, size)
        if size > self.max_artifact_bytes:
            raise ArtifactError("artifact exceeds configured size limit")
        self._assert_lease(job_store, job_id, worker_id)
        job_dir = self.root / job_id
        if job_dir.exists() and job_dir.is_symlink():
            raise ArtifactError("artifact job directory must not be a symlink")
        job_dir.mkdir(mode=0o700, exist_ok=True)
        if job_dir.resolve(strict=True).parent != self.root:
            raise ArtifactError("artifact path escaped configured root")
        artifact_id = str(uuid.uuid4())
        storage_key = artifact_id + ".blob"
        final_path = job_dir / storage_key
        temp_path = job_dir / (artifact_id + ".tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        digest = hashlib.sha256()
        remaining = size
        try:
            fd = os.open(temp_path, flags, 0o600)
            with os.fdopen(fd, "wb") as output:
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ArtifactError("artifact upload ended before Content-Length")
                    if not isinstance(chunk, bytes) or len(chunk) > remaining:
                        raise ArtifactError("artifact upload stream returned invalid data")
                    output.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
                output.flush()
                os.fsync(output.fileno())
            self._assert_lease(job_store, job_id, worker_id)
            os.replace(temp_path, final_path)
            metadata = {
                "id": artifact_id, "job_id": job_id, "worker_id": worker_id,
                "name": name, "size": size, "sha256": digest.hexdigest(),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            with self.lock, self._db() as db:
                db.execute(
                    "INSERT INTO artifacts(id,job_id,worker_id,name,storage_key,size,sha256,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (artifact_id, job_id, worker_id, name, storage_key, size,
                     metadata["sha256"], metadata["created_at"]),
                )
            return {key: value for key, value in metadata.items() if key != "worker_id"}
        except Exception:
            for path in (temp_path, final_path):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            raise

    def list_for_job(self, job_id: str) -> list[dict]:
        try:
            if str(uuid.UUID(job_id)) != job_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ArtifactError("invalid job ID") from None
        with self.lock, self._db() as db:
            rows = db.execute(
                "SELECT id,job_id,name,size,sha256,created_at FROM artifacts WHERE job_id=? ORDER BY created_at,id",
                (job_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get(self, artifact_id: str) -> tuple[dict, Path]:
        try:
            if str(uuid.UUID(artifact_id)) != artifact_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ArtifactError("invalid artifact ID") from None
        with self.lock, self._db() as db:
            row = db.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
        if row is None:
            raise ArtifactError("artifact not found")
        job_dir = self.root / row["job_id"]
        path = job_dir / row["storage_key"]
        if job_dir.is_symlink() or path.is_symlink() or not path.is_file():
            raise ArtifactError("artifact storage entry is missing or unsafe")
        if path.resolve(strict=True).parent != job_dir.resolve(strict=True):
            raise ArtifactError("artifact path escaped storage root")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size != row["size"]:
            raise ArtifactError("artifact storage integrity check failed")
        metadata = {
            "id": row["id"], "job_id": row["job_id"], "name": row["name"],
            "size": row["size"], "sha256": row["sha256"],
            "created_at": row["created_at"],
        }
        return metadata, path

    def open(self, artifact_id: str):
        metadata, path = self.get(artifact_id)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        return metadata, os.fdopen(fd, "rb")

    def prune(self, retention_days: int = 30) -> int:
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or not 1 <= retention_days <= 3650:
            raise ValueError("retention_days must be between 1 and 3650")
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        removed = 0
        with self.lock, self._db() as db:
            rows = db.execute(
                "SELECT id,job_id,storage_key FROM artifacts WHERE created_at<?", (cutoff,)
            ).fetchall()
            for row in rows:
                path = self.root / row["job_id"] / row["storage_key"]
                try:
                    if not path.is_symlink():
                        path.unlink(missing_ok=True)
                finally:
                    db.execute("DELETE FROM artifacts WHERE id=?", (row["id"],))
                    removed += 1
        return removed
