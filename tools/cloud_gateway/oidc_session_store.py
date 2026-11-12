"""Durable, one-time OIDC transactions and revocable server-side sessions."""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import closing
import time
from pathlib import Path

from .sqlite_security import prepare_private_sqlite_file


class OIDCSessionError(ValueError):
    pass


class OIDCSessionStore:
    def __init__(self, database: str, session_ttl: int = 43200, transaction_ttl: int = 600):
        if not isinstance(session_ttl, int) or not 300 <= session_ttl <= 86400:
            raise ValueError("OIDC session TTL must be 300..86400 seconds")
        if not isinstance(transaction_ttl, int) or not 60 <= transaction_ttl <= 900:
            raise ValueError("OIDC transaction TTL must be 60..900 seconds")
        self.database = database
        self.session_ttl = session_ttl
        self.transaction_ttl = transaction_ttl
        if database != ":memory:":
            prepare_private_sqlite_file(database)
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS oidc_transactions (
                    state_hash TEXT PRIMARY KEY,
                    nonce TEXT NOT NULL,
                    code_verifier TEXT NOT NULL,
                    browser_binding_hash TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS oidc_sessions (
                    session_hash TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('owner','operator')),
                    csrf_secret TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS oidc_sessions_expiry ON oidc_sessions(expires_at);
            """)

    def _connect(self):
        db = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        return db

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def save_transaction(self, state: str, nonce: str, code_verifier: str,
                         browser_binding: str, now: int | None = None) -> None:
        if any(not isinstance(v, str) or not v or len(v) > 512
               for v in (state, nonce, code_verifier, browser_binding)):
            raise OIDCSessionError("Invalid OIDC transaction values")
        current = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            db.execute("DELETE FROM oidc_transactions WHERE expires_at <= ?", (current,))
            try:
                db.execute(
                    "INSERT INTO oidc_transactions VALUES(?,?,?,?,?)",
                    (self._digest(state), nonce, code_verifier,
                     self._digest(browser_binding), current + self.transaction_ttl),
                )
            except sqlite3.IntegrityError as exc:
                raise OIDCSessionError("OIDC state collision") from exc

    def consume_transaction(self, state: str, browser_binding: str,
                            now: int | None = None) -> dict:
        if not isinstance(state, str) or not state or not isinstance(browser_binding, str) or not browser_binding:
            raise OIDCSessionError("OIDC state and browser binding are required")
        current = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM oidc_transactions WHERE state_hash=?",
                (self._digest(state),),
            ).fetchone()
            # Consume whether valid or not: a state value cannot be retried.
            db.execute("DELETE FROM oidc_transactions WHERE state_hash=?", (self._digest(state),))
            db.commit()
        if (row is None or row["expires_at"] <= current
                or row["browser_binding_hash"] != self._digest(browser_binding)):
            raise OIDCSessionError("OIDC state is invalid, expired, replayed, or browser binding mismatched")
        return {"nonce": row["nonce"], "code_verifier": row["code_verifier"]}

    def create_session(self, subject: str, role: str, now: int | None = None) -> tuple[str, dict]:
        if not isinstance(subject, str) or not subject or len(subject) > 255 or role not in ("owner", "operator"):
            raise OIDCSessionError("Verified subject and authorized role are required")
        current = int(time.time()) if now is None else int(now)
        session_id = secrets.token_urlsafe(32)
        csrf_secret = secrets.token_urlsafe(32)
        with self._connect() as db:
            db.execute(
                "INSERT INTO oidc_sessions VALUES(?,?,?,?,?,?,NULL)",
                (self._digest(session_id), subject, role, csrf_secret, current, current + self.session_ttl),
            )
        return session_id, {"subject": subject, "role": role, "csrf_token": csrf_secret,
                             "expires_at": current + self.session_ttl}

    def get_session(self, session_id: str, now: int | None = None) -> dict | None:
        if not isinstance(session_id, str) or not session_id:
            return None
        current = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            row = db.execute(
                "SELECT subject,role,csrf_secret,created_at,expires_at FROM oidc_sessions "
                "WHERE session_hash=? AND revoked_at IS NULL AND expires_at>?",
                (self._digest(session_id), current),
            ).fetchone()
        if row is None:
            return None
        return {"subject": row["subject"], "role": row["role"],
                "csrf_token": row["csrf_secret"], "created_at": row["created_at"],
                "expires_at": row["expires_at"]}

    def rotate_session(self, old_session_id: str, now: int | None = None) -> tuple[str, dict]:
        current = int(time.time()) if now is None else int(now)
        old = self.get_session(old_session_id, current)
        if old is None:
            raise OIDCSessionError("Session is invalid or expired")
        new_id, session = self.create_session(old["subject"], old["role"], current)
        if not self.revoke_session(old_session_id, current):
            self.revoke_session(new_id, current)
            raise OIDCSessionError("Session rotation lost a concurrent revocation race")
        return new_id, session

    def revoke_session(self, session_id: str, now: int | None = None) -> bool:
        if not isinstance(session_id, str) or not session_id:
            return False
        current = int(time.time()) if now is None else int(now)
        with self._connect() as db:
            result = db.execute(
                "UPDATE oidc_sessions SET revoked_at=? WHERE session_hash=? AND revoked_at IS NULL",
                (current, self._digest(session_id)),
            )
        return result.rowcount == 1

    def csrf_valid(self, session_id: str, supplied: str, now: int | None = None) -> bool:
        session = self.get_session(session_id, now)
        if session is None or not isinstance(supplied, str) or not supplied:
            return False
        import hmac
        return hmac.compare_digest(session["csrf_token"], supplied)
