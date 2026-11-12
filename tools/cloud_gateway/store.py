"""Durable SQLite lifecycle and credential-free audit ledger."""
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .sqlite_security import prepare_private_sqlite_file

ACTIVE = ("provisioning", "online", "terminating")
CLEANUP_EVENTS = {"runner_cleanup_confirmed", "provider_cleanup_confirmed", "cleanup_retry"}
TRANSITIONS = {
    "provisioning": {"provisioning", "online", "terminating", "terminated", "failed"},
    "online": {"terminating", "terminated", "failed"},
    "terminating": {"terminated", "failed"},
    "failed": {"terminating", "terminated"},
    "terminated": set(),
}


def now():
    return datetime.now(timezone.utc).isoformat()


class LifecycleConflict(RuntimeError):
    pass


class RunnerStore:
    def __init__(self, path="dcp-gateway.sqlite3"):
        self.path = str(path)
        self.lock = threading.RLock()
        prepare_private_sqlite_file(self.path)
        with self.db() as c:
            c.executescript("""CREATE TABLE IF NOT EXISTS runners(
                id TEXT PRIMARY KEY,idempotency_key TEXT UNIQUE NOT NULL,
                fingerprint TEXT NOT NULL,repository TEXT NOT NULL,
                workflow_run_id INTEGER NOT NULL,commit_sha TEXT NOT NULL,
                target_os TEXT NOT NULL,provider_id TEXT,state TEXT NOT NULL,
                request_json TEXT NOT NULL,created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,expires_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_state ON runners(state);
            CREATE INDEX IF NOT EXISTS idx_expiry ON runners(state,expires_at);
            CREATE TABLE IF NOT EXISTS audit(
                id INTEGER PRIMARY KEY,runner_id TEXT,event TEXT,
                detail_json TEXT,created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS auth_nonces(
                nonce TEXT PRIMARY KEY,expires_at REAL NOT NULL
            );""")

    @contextmanager
    def db(self):
        """Open a SQLite connection and always close it after use."""
        c = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        c.row_factory = sqlite3.Row
        try:
            with c:
                yield c
        finally:
            c.close()

    def active_count(self):
        with self.lock, self.db() as c:
            return c.execute(
                "SELECT count(*) FROM runners WHERE state IN (?,?,?) "
                "OR (state='failed' AND provider_id IS NOT NULL AND NOT EXISTS "
                "(SELECT 1 FROM audit WHERE audit.runner_id=runners.id "
                "AND audit.event IN ('runner_cleanup_confirmed','provider_cleanup_confirmed')))",
                ACTIVE,
            ).fetchone()[0]

    def expired_active(self, now_iso):
        """Return active rows whose persisted UTC expiry has passed."""
        try:
            parsed = datetime.fromisoformat(now_iso)
        except (TypeError, ValueError) as exc:
            raise ValueError("Expiry comparison requires an ISO timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("Expiry comparison requires a timezone-aware timestamp")
        with self.lock, self.db() as c:
            rows = c.execute(
                "SELECT * FROM runners WHERE "
                "(state IN (?,?,?) OR (state='failed' AND provider_id IS NOT NULL AND NOT EXISTS "
                "(SELECT 1 FROM audit WHERE audit.runner_id=runners.id "
                "AND audit.event IN ('runner_cleanup_confirmed','provider_cleanup_confirmed')))) "
                "AND expires_at<=? ORDER BY expires_at",
                (*ACTIVE, now_iso),
            ).fetchall()
            return [dict(row) for row in rows]

    def list_recent(self, limit=50):
        """Return newest runner records without request payloads or credentials."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("Runner list limit must be 1..200")
        with self.lock, self.db() as c:
            rows = c.execute(
                "SELECT id,state,target_os,created_at,updated_at,expires_at FROM runners "
                "ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(row) for row in rows]

    def get(self, rid):
        with self.lock, self.db() as c:
            r = c.execute("SELECT * FROM runners WHERE id=?", (rid,)).fetchone()
            return dict(r) if r else None

    def get_by_key(self, key):
        with self.lock, self.db() as c:
            r = c.execute(
                "SELECT * FROM runners WHERE idempotency_key=?", (key,)
            ).fetchone()
            return dict(r) if r else None

    def create(self, rid, key, fingerprint, payload, expires):
        with self.lock, self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            old = c.execute(
                "SELECT * FROM runners WHERE idempotency_key=?", (key,)
            ).fetchone()
            if old:
                if old["fingerprint"] != fingerprint:
                    raise LifecycleConflict("Idempotency key conflicts with an existing request")
                c.execute("COMMIT")
                return dict(old), False
            t = now()
            c.execute(
                "INSERT INTO runners VALUES(?,?,?,?,?,?,?,NULL,'provisioning',?,?,?,?)",
                (rid, key, fingerprint, payload["repository"], payload["workflow_run_id"],
                 payload["commit_sha"], payload["target_os"],
                 json.dumps(payload, sort_keys=True), t, t, expires),
            )
            c.execute(
                "INSERT INTO audit(runner_id,event,detail_json,created_at) VALUES(?,?,?,?)",
                (rid, "provisioning_requested", "{}", t),
            )
            c.execute("COMMIT")
            return self.get(rid), True

    def transition(self, rid, state, provider_id=None, detail=None):
        with self.lock, self.db() as c:
            c.execute("BEGIN IMMEDIATE")
            r = c.execute("SELECT * FROM runners WHERE id=?", (rid,)).fetchone()
            if not r:
                raise KeyError(rid)
            if state not in TRANSITIONS.get(r["state"], set()):
                raise LifecycleConflict("Invalid transition " + r["state"] + " -> " + state)
            t = now()
            c.execute(
                "UPDATE runners SET state=?,provider_id=COALESCE(?,provider_id),updated_at=? WHERE id=?",
                (state, provider_id, t, rid),
            )
            safe = {"detail": detail[:100]} if isinstance(detail, str) and detail in {
                "TimeoutError", "ConnectionError", "ProviderUnavailable"
            } else {}
            c.execute(
                "INSERT INTO audit(runner_id,event,detail_json,created_at) VALUES(?,?,?,?)",
                (rid, state, json.dumps(safe), t),
            )
            c.execute("COMMIT")
            return self.get(rid)

    def lifecycle_summary(self):
        """Return aggregate lifecycle/cleanup counts without runner identifiers."""
        with self.lock, self.db() as c:
            state_rows = c.execute(
                "SELECT state,count(*) FROM runners GROUP BY state"
            ).fetchall()
            cleanup_pending = c.execute(
                "SELECT count(*) FROM runners WHERE state='terminating' "
                "OR (state='failed' AND provider_id IS NOT NULL AND NOT EXISTS "
                "(SELECT 1 FROM audit WHERE audit.runner_id=runners.id "
                "AND audit.event IN ('runner_cleanup_confirmed','provider_cleanup_confirmed')))"
            ).fetchone()[0]
            cleanup_retries = c.execute(
                "SELECT count(*) FROM audit WHERE event='cleanup_retry'"
            ).fetchone()[0]
            cleanup_confirmed = c.execute(
                "SELECT count(*) FROM audit WHERE event IN "
                "('runner_cleanup_confirmed','provider_cleanup_confirmed')"
            ).fetchone()[0]
        return {
            "state_counts": {state: count for state, count in state_rows},
            "cleanup_pending": cleanup_pending,
            "cleanup_retries": cleanup_retries,
            "cleanup_confirmed": cleanup_confirmed,
        }

    def consume_auth_nonce(self, nonce, now_epoch, expires_at_epoch):
        if not isinstance(nonce, str) or not 16 <= len(nonce) <= 128:
            raise ValueError("Invalid authentication nonce")
        if (isinstance(now_epoch, bool) or not isinstance(now_epoch, (int, float))
                or isinstance(expires_at_epoch, bool) or not isinstance(expires_at_epoch, (int, float))
                or expires_at_epoch <= now_epoch):
            raise ValueError("Invalid authentication nonce expiry")
        with self.lock, self.db() as c:
            c.execute("DELETE FROM auth_nonces WHERE expires_at<=?", (now_epoch,))
            if c.execute("SELECT count(*) FROM auth_nonces").fetchone()[0] >= 100000:
                return False
            try:
                c.execute(
                    "INSERT INTO auth_nonces(nonce,expires_at) VALUES(?,?)",
                    (nonce, expires_at_epoch),
                )
            except sqlite3.IntegrityError:
                return False
            return True

    def mark_cleanup_due(self, rid):
        timestamp = now()
        with self.lock, self.db() as c:
            changed = c.execute(
                "UPDATE runners SET expires_at=?,updated_at=? "
                "WHERE id=? AND state IN (?,?,?)",
                (timestamp, timestamp, rid, "provisioning", "online", "terminating"),
            ).rowcount
            if not changed:
                raise LifecycleConflict("Runner is not in a retryable cleanup state")

    def record_event(self, rid, event, result=None):
        if event not in CLEANUP_EVENTS:
            raise ValueError("Audit event is not allowlisted")
        safe = {}
        if result in ("removed", "already_absent", "provider_only", "pending"):
            safe["result"] = result
        with self.lock, self.db() as c:
            exists = c.execute("SELECT 1 FROM runners WHERE id=?", (rid,)).fetchone()
            if not exists:
                raise KeyError(rid)
            c.execute(
                "INSERT INTO audit(runner_id,event,detail_json,created_at) VALUES(?,?,?,?)",
                (rid, event, json.dumps(safe), now()),
            )

    def audit_events(self, rid):
        with self.lock, self.db() as c:
            return [
                {"event": r["event"], "detail": json.loads(r["detail_json"]),
                 "created_at": r["created_at"]}
                for r in c.execute("SELECT * FROM audit WHERE runner_id=? ORDER BY id", (rid,))
            ]
