"""DCP-owned infrastructure inventory and lifecycle control.

The initial provider is deliberately in-memory and non-provisioning: it models
VM lifecycle for contract tests and local development without creating hosts,
containers, cloud resources, or billable capacity.
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

_STATES = {"provisioned", "running", "stopped", "deleted"}
_OS = {"linux", "windows", "macos"}
_ID = re.compile(r"^[a-z][a-z0-9-]{1,62}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class InfrastructureError(RuntimeError):
    """Base error for infrastructure manager operations."""


class ResourceNotFound(InfrastructureError):
    pass


class LifecycleConflict(InfrastructureError):
    pass


class ProviderUnavailable(InfrastructureError):
    pass


class InfrastructureProvider(Protocol):
    provider_id: str

    def readiness(self, image: dict, template: dict) -> dict: ...
    def create(self, resource: dict) -> dict: ...
    def inspect(self, provider_resource_id: str) -> dict: ...
    def start(self, provider_resource_id: str) -> dict: ...
    def stop(self, provider_resource_id: str) -> dict: ...
    def delete(self, provider_resource_id: str) -> dict: ...


class FakeInfrastructureProvider:
    """Deterministic simulation provider; never invokes an external system."""

    provider_id = "fake"

    def __init__(self):
        self.resources: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.lock = threading.RLock()

    def readiness(self, image: dict, template: dict) -> dict:
        return {"ready": True, "provider": self.provider_id, "mode": "simulation",
                "creates_real_resources": False}

    def create(self, resource: dict) -> dict:
        with self.lock:
            rid = "fake-" + uuid.uuid4().hex[:16]
            row = {"provider_resource_id": rid, "state": "provisioned",
                   "target_os": resource["target_os"], "image_id": resource["image_id"],
                   "template_id": resource["template_id"]}
            self.resources[rid] = row
            self.calls.append(("create", rid))
            return dict(row)

    def inspect(self, provider_resource_id: str) -> dict:
        with self.lock:
            row = self.resources.get(provider_resource_id)
            if row is None:
                raise ResourceNotFound(provider_resource_id)
            self.calls.append(("inspect", provider_resource_id))
            return dict(row)

    def _change(self, action: str, provider_resource_id: str, state: str) -> dict:
        with self.lock:
            row = self.resources.get(provider_resource_id)
            if row is None:
                raise ResourceNotFound(provider_resource_id)
            row["state"] = state
            self.calls.append((action, provider_resource_id))
            return dict(row)

    def start(self, provider_resource_id: str) -> dict:
        return self._change("start", provider_resource_id, "running")

    def stop(self, provider_resource_id: str) -> dict:
        return self._change("stop", provider_resource_id, "stopped")

    def delete(self, provider_resource_id: str) -> dict:
        return self._change("delete", provider_resource_id, "deleted")


class InfrastructureStore:
    """SQLite resource inventory, idempotency ledger, and credential-free audit."""

    def __init__(self, path="dcp-infrastructure.sqlite3"):
        self.path = str(path)
        self.lock = threading.RLock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.db() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS infrastructure_resources (
                    id TEXT PRIMARY KEY,
                    idempotency_key TEXT UNIQUE NOT NULL,
                    provider_id TEXT NOT NULL,
                    provider_resource_id TEXT NOT NULL,
                    target_os TEXT NOT NULL,
                    image_id TEXT NOT NULL,
                    template_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS infra_state_idx
                    ON infrastructure_resources(state);
                CREATE TABLE IF NOT EXISTS infrastructure_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    resource_id TEXT NOT NULL,
                    event TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)

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

    def get(self, resource_id: str):
        with self.lock, self.db() as conn:
            row = conn.execute(
                "SELECT * FROM infrastructure_resources WHERE id=?", (resource_id,)
            ).fetchone()
        return self._decode(row)

    def by_key(self, key: str):
        with self.lock, self.db() as conn:
            row = conn.execute(
                "SELECT * FROM infrastructure_resources WHERE idempotency_key=?", (key,)
            ).fetchone()
        return self._decode(row)

    @staticmethod
    def _decode(row):
        if row is None:
            return None
        result = dict(row)
        result["metadata"] = json.loads(result.pop("metadata_json"))
        return result

    def create(self, row: dict):
        now = _now()
        with self.lock, self.db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            old = conn.execute(
                "SELECT * FROM infrastructure_resources WHERE idempotency_key=?",
                (row["idempotency_key"],),
            ).fetchone()
            if old:
                return self._decode(old), False
            conn.execute("""
                INSERT INTO infrastructure_resources
                (id,idempotency_key,provider_id,provider_resource_id,target_os,
                 image_id,template_id,state,metadata_json,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """, (row["id"], row["idempotency_key"], row["provider_id"],
                  row["provider_resource_id"], row["target_os"], row["image_id"],
                  row["template_id"], row["state"], json.dumps(row.get("metadata", {})),
                  now, now))
            conn.execute("""
                INSERT INTO infrastructure_audit(resource_id,event,detail_json,created_at)
                VALUES(?,?,?,?)
            """, (row["id"], "resource_created", "{}", now))
            conn.commit()
        return self.get(row["id"]), True

    def transition(self, resource_id: str, state: str, metadata: dict | None = None):
        allowed = {
            "provisioned": {"running", "deleted"},
            "running": {"stopped", "deleted"},
            "stopped": {"running", "deleted"},
            "deleted": set(),
        }
        with self.lock, self.db() as conn:
            row = conn.execute(
                "SELECT state,metadata_json FROM infrastructure_resources WHERE id=?",
                (resource_id,),
            ).fetchone()
            if row is None:
                raise ResourceNotFound(resource_id)
            if state == row["state"]:
                return self.get(resource_id)
            if state not in allowed.get(row["state"], set()):
                raise LifecycleConflict("Invalid infrastructure transition")
            merged = json.loads(row["metadata_json"])
            if metadata:
                merged.update(metadata)
            now = _now()
            conn.execute("""
                UPDATE infrastructure_resources SET state=?,metadata_json=?,updated_at=?
                WHERE id=?
            """, (state, json.dumps(merged), now, resource_id))
            conn.execute("""
                INSERT INTO infrastructure_audit(resource_id,event,detail_json,created_at)
                VALUES(?,?,?,?)
            """, (resource_id, state, "{}", now))
        return self.get(resource_id)

    def list_resources(self):
        with self.lock, self.db() as conn:
            rows = conn.execute(
                "SELECT * FROM infrastructure_resources ORDER BY created_at DESC"
            ).fetchall()
        return [self._decode(row) for row in rows]

    def events(self, resource_id: str):
        with self.lock, self.db() as conn:
            rows = conn.execute("""
                SELECT event,detail_json,created_at FROM infrastructure_audit
                WHERE resource_id=? ORDER BY id
            """, (resource_id,)).fetchall()
        return [{"event": r["event"], "detail": json.loads(r["detail_json"]),
                 "created_at": r["created_at"]} for r in rows]


class InfrastructureManager:
    """Provider-neutral image/template catalog and guarded VM lifecycle."""

    def __init__(self, store: InfrastructureStore, providers: dict[str, InfrastructureProvider],
                 *, default_provider="fake", provisioning_enabled=False):
        self.store = store
        self.providers = dict(providers)
        self.default_provider = default_provider
        self.provisioning_enabled = provisioning_enabled
        self.create_lock = threading.Lock()
        self.images = {
            "dcp-linux-ubuntu-24.04": {"id": "dcp-linux-ubuntu-24.04",
                "target_os": "linux", "version": "24.04", "architecture": "x64",
                "source": "catalog", "enabled": True},
            "dcp-windows-2025": {"id": "dcp-windows-2025",
                "target_os": "windows", "version": "2025", "architecture": "x64",
                "source": "catalog", "enabled": True},
            "dcp-macos-15-arm64": {"id": "dcp-macos-15-arm64",
                "target_os": "macos", "version": "15", "architecture": "arm64",
                "source": "catalog", "enabled": True},
        }
        self.templates = {
            "flutter-linux-small": {"id": "flutter-linux-small", "target_os": "linux",
                "cpu": 2, "memory_mb": 4096, "disk_gb": 40, "enabled": True},
            "flutter-windows-small": {"id": "flutter-windows-small", "target_os": "windows",
                "cpu": 4, "memory_mb": 8192, "disk_gb": 80, "enabled": True},
            "flutter-macos-small": {"id": "flutter-macos-small", "target_os": "macos",
                "cpu": 4, "memory_mb": 8192, "disk_gb": 80, "enabled": True},
        }

    def catalog(self):
        return {"providers": [{"id": key, "mode": "simulation" if key == "fake" else "external"}
                              for key in sorted(self.providers)],
                "images": [dict(v) for v in self.images.values()],
                "templates": [dict(v) for v in self.templates.values()],
                "provisioning_enabled": self.provisioning_enabled}

    def create(self, *, target_os: str, image_id: str, template_id: str,
               idempotency_key: str, provider_id: str | None = None):
        # Serialize idempotency reservation with provider creation to avoid orphaned
        # provider resources when concurrent requests reuse the same key.
        with self.create_lock:
            return self._create(target_os=target_os, image_id=image_id,
                                template_id=template_id, idempotency_key=idempotency_key,
                                provider_id=provider_id)

    def _create(self, *, target_os: str, image_id: str, template_id: str,
                idempotency_key: str, provider_id: str | None = None):
        if not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 200:
            raise ValueError("Idempotency key must be 8..200 characters")
        if not isinstance(target_os, str) or target_os not in _OS:
            raise ValueError("Unsupported target OS")
        image = self.images.get(image_id)
        template = self.templates.get(template_id)
        if not image or not template or not image["enabled"] or not template["enabled"]:
            raise ValueError("Unknown or disabled image/template")
        if image["target_os"] != target_os or template["target_os"] != target_os:
            raise ValueError("Image and template must match target OS")
        provider_name = provider_id or self.default_provider
        provider = self.providers.get(provider_name)
        if provider is None:
            raise ProviderUnavailable("Selected provider is not configured")
        existing = self.store.by_key(idempotency_key)
        if existing:
            if (existing["provider_id"], existing["target_os"], existing["image_id"], existing["template_id"]) != (
                provider_name, target_os, image_id, template_id
            ):
                raise LifecycleConflict("Idempotency key conflicts with another request")
            return existing, False
        if provider_name != "fake" and not self.provisioning_enabled:
            raise ProviderUnavailable("External provisioning is disabled")
        readiness = provider.readiness(image, template)
        if not isinstance(readiness, dict) or readiness.get("ready") is not True:
            raise ProviderUnavailable("Selected provider is not ready")
        result = provider.create({"target_os": target_os, "image_id": image_id,
                                  "template_id": template_id})
        if result.get("state") not in _STATES or result.get("provider_resource_id") is None:
            raise InfrastructureError("Provider returned an invalid resource")
        row = {"id": str(uuid.uuid4()), "idempotency_key": idempotency_key,
               "provider_id": provider_name,
               "provider_resource_id": result["provider_resource_id"],
               "target_os": target_os, "image_id": image_id, "template_id": template_id,
               "state": result["state"], "metadata": {"mode": "simulation" if provider_name == "fake" else "external"}}
        return self.store.create(row)

    def _operation(self, resource_id: str, action: str):
        row = self.store.get(resource_id)
        if row is None:
            raise ResourceNotFound(resource_id)
        if row["state"] == "deleted":
            if action == "delete":
                return row
            raise LifecycleConflict("Deleted resources cannot be changed")
        provider = self.providers.get(row["provider_id"])
        if provider is None:
            raise ProviderUnavailable("Recorded provider is not configured")
        observed = getattr(provider, action)(row["provider_resource_id"])
        state = observed.get("state")
        if state not in _STATES:
            raise InfrastructureError("Provider returned an invalid lifecycle state")
        return self.store.transition(resource_id, state)

    def inspect(self, resource_id: str):
        row = self.store.get(resource_id)
        if row is None:
            raise ResourceNotFound(resource_id)
        provider = self.providers.get(row["provider_id"])
        if provider is None:
            raise ProviderUnavailable("Recorded provider is not configured")
        observed = provider.inspect(row["provider_resource_id"])
        if observed.get("state") != row["state"]:
            row = self.store.transition(resource_id, observed["state"])
        return row

    def start(self, resource_id: str):
        return self._operation(resource_id, "start")

    def stop(self, resource_id: str):
        return self._operation(resource_id, "stop")

    def restart(self, resource_id: str):
        row = self.store.get(resource_id)
        if row is None:
            raise ResourceNotFound(resource_id)
        if row["state"] == "running":
            self.stop(resource_id)
        elif row["state"] != "stopped":
            raise LifecycleConflict("Only running or stopped resources can restart")
        return self.start(resource_id)

    def delete(self, resource_id: str):
        return self._operation(resource_id, "delete")

    def get(self, resource_id: str):
        row = self.store.get(resource_id)
        if row is None:
            raise ResourceNotFound(resource_id)
        return row

    def list_resources(self):
        return self.store.list_resources()
