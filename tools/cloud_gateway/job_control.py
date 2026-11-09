"""Local-first durable job queue. This module never executes repository code."""
import json
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

class JobConflict(RuntimeError):
    pass

class JobNotFound(KeyError):
    pass

def utcnow():
    return datetime.now(timezone.utc)

class JobStore:
    """SQLite job lifecycle: queued, running, cancel_requested, and terminal states."""
    def __init__(self, path="dcp-jobs.sqlite3"):
        self.path = str(path)
        self.lock = threading.RLock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, idem TEXT UNIQUE NOT NULL, fingerprint TEXT NOT NULL,
                    repository TEXT NOT NULL, commit_sha TEXT NOT NULL, target TEXT NOT NULL,
                    state TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL, worker TEXT, lease_until TEXT,
                    cancel_at TEXT, result TEXT, error_code TEXT
                );
                CREATE INDEX IF NOT EXISTS jobs_queue_idx ON jobs(state, created_at);
                CREATE TABLE IF NOT EXISTS job_events (
                    id INTEGER PRIMARY KEY, job_id TEXT NOT NULL, event TEXT NOT NULL,
                    detail TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS job_logs (
                    id INTEGER PRIMARY KEY, job_id TEXT NOT NULL, stream TEXT NOT NULL,
                    message TEXT NOT NULL, created_at TEXT NOT NULL
                );
            """)

    @contextmanager
    def db(self):
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def _decode(row):
        if row is None:
            return None
        item = dict(row)
        for key in ("payload", "result"):
            item[key] = json.loads(item[key]) if item[key] else None
        return item

    @staticmethod
    def _event(db, job_id, event, detail=None):
        db.execute(
            "INSERT INTO job_events(job_id,event,detail,created_at) VALUES(?,?,?,?)",
            (job_id, event, json.dumps(detail or {}, sort_keys=True), utcnow().isoformat()),
        )

    def create(self, payload, idempotency_key):
        if not isinstance(idempotency_key, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{8,200}", idempotency_key):
            raise ValueError("Invalid Idempotency-Key")
        if not isinstance(payload, dict):
            raise ValueError("Job payload must be an object")
        if not set(payload).issubset({"repository", "commit_sha", "target"}):
            raise ValueError("Unsupported job payload fields")
        repository, sha = payload.get("repository"), payload.get("commit_sha")
        target = payload.get("target", "test")
        if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository):
            raise ValueError("Invalid repository")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("Invalid commit SHA")
        if target not in ("test", "build", "package", "build_android", "build_web", "build_windows", "build_linux", "build_macos", "build_ios"):
            raise ValueError("Unsupported target")
        normalized = {"repository": repository, "commit_sha": sha, "target": target}
        fingerprint = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        job_id, timestamp = str(uuid.uuid4()), utcnow().isoformat()
        with self.lock, self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT * FROM jobs WHERE idem=?", (idempotency_key,)).fetchone()
            if old:
                if old["fingerprint"] != fingerprint:
                    raise JobConflict("Idempotency key conflict")
                db.execute("COMMIT")
                return self._decode(old), False
            db.execute(
                "INSERT INTO jobs(id,idem,fingerprint,repository,commit_sha,target,state,payload,created_at,updated_at) VALUES(?,?,?,?,?,?,'queued',?,?,?)",
                (job_id, idempotency_key, fingerprint, repository, sha, target,
                 json.dumps(normalized), timestamp, timestamp),
            )
            self._event(db, job_id, "queued")
            db.execute("COMMIT")
        return self.get(job_id), True

    def get(self, job_id):
        with self.lock, self.db() as db:
            return self._decode(db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())

    def list_recent(self, limit=50):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("Invalid limit")
        with self.lock, self.db() as db:
            rows = db.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,))
            return [self._decode(row) for row in rows]

    def recover_expired_leases(self):
        """Requeue abandoned work, or finalize abandoned cancellation requests."""
        current = utcnow().isoformat()
        recovered = []
        with self.lock, self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT id,state FROM jobs WHERE state IN ('running','cancel_requested') "
                "AND lease_until IS NOT NULL AND lease_until<=? ORDER BY lease_until,id",
                (current,),
            ).fetchall()
            for row in rows:
                if row["state"] == "cancel_requested":
                    state, event = "cancelled", "cancelled_after_lease_expiry"
                else:
                    state, event = "queued", "lease_expired_requeued"
                db.execute(
                    "UPDATE jobs SET state=?,worker=NULL,lease_until=NULL,updated_at=? WHERE id=?",
                    (state, current, row["id"]),
                )
                self._event(db, row["id"], event)
                recovered.append({"id": row["id"], "state": state})
            db.execute("COMMIT")
        return recovered

    def claim(self, worker, lease_seconds=30, allowed_targets=None):
        if not isinstance(worker, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", worker):
            raise ValueError("Invalid worker")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 5 <= lease_seconds <= 300:
            raise ValueError("Invalid lease")
        if allowed_targets is not None:
            supported = {"test", "build", "package", "build_android", "build_web",
                         "build_windows", "build_linux", "build_macos", "build_ios"}
            if (not isinstance(allowed_targets, (list, tuple, set, frozenset))
                    or any(not isinstance(item, str) or item not in supported for item in allowed_targets)):
                raise ValueError("Invalid allowed target list")
            allowed_targets = sorted(set(allowed_targets))
            if not allowed_targets:
                return None
        current = utcnow()
        expiry = (current + timedelta(seconds=lease_seconds)).isoformat()
        with self.lock, self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if allowed_targets is None:
                row = db.execute("SELECT * FROM jobs WHERE state='queued' ORDER BY created_at,id LIMIT 1").fetchone()
            else:
                placeholders = ",".join("?" for _ in allowed_targets)
                row = db.execute(
                    f"SELECT * FROM jobs WHERE state='queued' AND target IN ({placeholders}) ORDER BY created_at,id LIMIT 1",
                    tuple(allowed_targets),
                ).fetchone()
            if row is None:
                db.execute("COMMIT")
                return None
            changed = db.execute(
                "UPDATE jobs SET state='running',worker=?,lease_until=?,updated_at=? WHERE id=? AND state='queued'",
                (worker, expiry, current.isoformat(), row["id"]),
            ).rowcount
            if changed != 1:
                db.execute("ROLLBACK")
                return None
            self._event(db, row["id"], "running", {"worker": worker})
            db.execute("COMMIT")
        return self.get(row["id"])

    def heartbeat(self, job_id, worker, lease_seconds=30):
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 5 <= lease_seconds <= 300:
            raise ValueError("Invalid lease")
        current = utcnow()
        expiry = (current + timedelta(seconds=lease_seconds)).isoformat()
        with self.lock, self.db() as db:
            changed = db.execute(
                "UPDATE jobs SET lease_until=?,updated_at=? WHERE id=? AND state IN ('running','cancel_requested') AND worker=? AND lease_until>?",
                (expiry, current.isoformat(), job_id, worker, current.isoformat()),
            ).rowcount
            if not changed:
                raise JobConflict("Worker does not own active job lease")
        return self.get(job_id)

    def cancel(self, job_id):
        with self.lock, self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise JobNotFound(job_id)
            if row["state"] == "queued":
                db.execute("UPDATE jobs SET state='cancelled',updated_at=? WHERE id=?", (utcnow().isoformat(), job_id))
                self._event(db, job_id, "cancelled")
            elif row["state"] == "running":
                timestamp = utcnow().isoformat()
                db.execute("UPDATE jobs SET state='cancel_requested',cancel_at=?,updated_at=? WHERE id=?", (timestamp, timestamp, job_id))
                self._event(db, job_id, "cancel_requested")
            db.execute("COMMIT")
        return self.get(job_id)

    def finish(self, job_id, worker, outcome, result=None, error_code=None):
        if outcome not in ("succeeded", "failed", "cancelled"):
            raise ValueError("Invalid terminal outcome")
        if result is not None and not isinstance(result, dict):
            raise ValueError("result must be an object")
        if error_code is not None and (not isinstance(error_code, str) or not re.fullmatch(r"[A-Z0-9_]{1,64}", error_code)):
            raise ValueError("Invalid error code")
        with self.lock, self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise JobNotFound(job_id)
            if (row["state"] not in ("running", "cancel_requested") or row["worker"] != worker
                    or not row["lease_until"] or row["lease_until"] <= utcnow().isoformat()):
                raise JobConflict("Worker does not own an active job lease")
            if row["state"] == "cancel_requested" and outcome == "succeeded":
                raise JobConflict("Cancellation must be acknowledged")
            db.execute(
                "UPDATE jobs SET state=?,updated_at=?,worker=NULL,lease_until=NULL,result=?,error_code=? WHERE id=?",
                (outcome, utcnow().isoformat(), json.dumps(result) if result is not None else None, error_code, job_id),
            )
            self._event(db, job_id, outcome, {"error_code": error_code} if error_code else {})
            db.execute("COMMIT")
        return self.get(job_id)

    def append_log(self, job_id, worker, message, stream="stdout"):
        if stream not in ("stdout", "stderr", "system"):
            raise ValueError("Invalid stream")
        if not isinstance(message, str) or not message or len(message.encode("utf-8")) > 8192:
            raise ValueError("Log message must be 1..8192 bytes")
        with self.lock, self.db() as db:
            row = db.execute("SELECT state,worker,lease_until FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise JobNotFound(job_id)
            if (row["state"] not in ("running", "cancel_requested") or row["worker"] != worker
                    or not row["lease_until"] or row["lease_until"] <= utcnow().isoformat()):
                raise JobConflict("Worker does not own an active job lease")
            db.execute("INSERT INTO job_logs(job_id,stream,message,created_at) VALUES(?,?,?,?)",
                       (job_id, stream, message, utcnow().isoformat()))

    def events(self, job_id):
        with self.lock, self.db() as db:
            if not db.execute("SELECT 1 FROM jobs WHERE id=?", (job_id,)).fetchone():
                raise JobNotFound(job_id)
            return [{"id": r["id"], "event": r["event"], "detail": json.loads(r["detail"]),
                     "created_at": r["created_at"]}
                    for r in db.execute("SELECT * FROM job_events WHERE job_id=? ORDER BY id", (job_id,))]

    def logs(self, job_id, after_id=0, limit=500):
        if isinstance(after_id, bool) or not isinstance(after_id, int) or after_id < 0:
            raise ValueError("Invalid after_id")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("Invalid limit")
        with self.lock, self.db() as db:
            if not db.execute("SELECT 1 FROM jobs WHERE id=?", (job_id,)).fetchone():
                raise JobNotFound(job_id)
            return [dict(row) for row in db.execute(
                "SELECT * FROM job_logs WHERE job_id=? AND id>? ORDER BY id LIMIT ?",
                (job_id, after_id, limit),
            )]
