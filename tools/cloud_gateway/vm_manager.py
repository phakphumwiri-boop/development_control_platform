"""Provider-neutral local VM and immutable image lifecycle manager.

Provisioning is disabled unless the operator explicitly enables the manager.
Provider calls are made only through injected adapters; no arbitrary command API exists.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OPERATING_SYSTEMS = {"linux", "windows", "macos"}
_ARCHITECTURES = {"x86_64", "arm64"}


class VMManagerError(RuntimeError):
    """VM lifecycle operation failed."""


class VMProvisioningDisabled(VMManagerError):
    pass


class VMQuotaExceeded(VMManagerError):
    pass


class VMConflict(VMManagerError):
    pass


class VMNotFound(VMManagerError):
    pass


class VMProvider(Protocol):
    provider_id: str

    def available(self) -> bool: ...
    def create(self, spec: dict) -> str: ...
    def start(self, vm: dict) -> None: ...
    def stop(self, vm: dict) -> None: ...
    def delete(self, vm: dict) -> None: ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class VMManager:
    """Persistent VM/image inventory with quotas, idempotency and explicit provisioning gate."""

    def __init__(
        self,
        database_path: str | os.PathLike,
        providers: dict[str, VMProvider],
        *,
        provisioning_enabled: bool = False,
        max_vms: int = 8,
        max_vcpus: int = 32,
        max_memory_mb: int = 131072,
        max_disk_gb: int = 2048,
    ):
        if not isinstance(provisioning_enabled, bool):
            raise ValueError("provisioning_enabled must be boolean")
        for name, value, minimum, maximum in (
            ("max_vms", max_vms, 1, 1024),
            ("max_vcpus", max_vcpus, 1, 4096),
            ("max_memory_mb", max_memory_mb, 512, 4 * 1024 * 1024),
            ("max_disk_gb", max_disk_gb, 10, 1024 * 1024),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise ValueError(f"{name} is outside its allowed range")
        if not isinstance(providers, dict) or any(
            key != getattr(provider, "provider_id", None) for key, provider in providers.items()
        ):
            raise ValueError("provider registry keys must match provider IDs")
        self.database_path = str(database_path)
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        self.providers = dict(providers)
        self.provisioning_enabled = provisioning_enabled
        self.quotas = {
            "max_vms": max_vms, "max_vcpus": max_vcpus,
            "max_memory_mb": max_memory_mb, "max_disk_gb": max_disk_gb,
        }
        self.lock = threading.RLock()
        with self.db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vm_images (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, provider TEXT NOT NULL,
                    os TEXT NOT NULL, architecture TEXT NOT NULL, path TEXT NOT NULL,
                    size INTEGER NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS virtual_machines (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, provider TEXT NOT NULL,
                    image_id TEXT NOT NULL, cpu INTEGER NOT NULL, memory_mb INTEGER NOT NULL,
                    disk_gb INTEGER NOT NULL, state TEXT NOT NULL, provider_ref TEXT,
                    idempotency_key TEXT NOT NULL UNIQUE, request_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_error TEXT,
                    FOREIGN KEY(image_id) REFERENCES vm_images(id)
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS vm_active_name_idx
                ON virtual_machines(provider,name) WHERE state NOT IN ('deleted','failed')
            """)

    @contextmanager
    def db(self):
        conn = sqlite3.connect(self.database_path, timeout=20)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _provider(self, provider_id: str) -> VMProvider:
        provider = self.providers.get(provider_id)
        if provider is None:
            raise VMManagerError("VM provider is not configured")
        try:
            ready = provider.available()
        except Exception:
            ready = False
        if not ready:
            raise VMManagerError("VM provider is not available on this host")
        return provider

    def register_image(
        self, name: str, provider: str, operating_system: str,
        architecture: str, path: str | os.PathLike, expected_sha256: str | None = None,
    ) -> dict:
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError("invalid VM image name")
        if operating_system not in _OPERATING_SYSTEMS or architecture not in _ARCHITECTURES:
            raise ValueError("unsupported VM image operating system or architecture")
        if provider not in self.providers:
            raise VMManagerError("VM image provider is not configured")
        image_path = Path(path).expanduser()
        if not image_path.is_absolute() or image_path.is_symlink() or not image_path.is_file():
            raise ValueError("VM image path must be an absolute regular file")
        info = image_path.stat()
        if info.st_size < 1:
            raise ValueError("VM image file is empty")
        digest = hashlib.sha256()
        with image_path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        sha256 = digest.hexdigest()
        if expected_sha256 is not None:
            if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256) or expected_sha256 != sha256:
                raise VMManagerError("VM image SHA-256 does not match the expected digest")
        image_id = str(uuid.uuid4())
        created = _now()
        with self.lock, self.db() as conn:
            conn.execute(
                "INSERT INTO vm_images(id,name,provider,os,architecture,path,size,sha256,created_at,enabled) VALUES(?,?,?,?,?,?,?,?,?,1)",
                (image_id, name, provider, operating_system, architecture,
                 str(image_path.resolve()), info.st_size, sha256, created),
            )
        return {
            "id": image_id, "name": name, "provider": provider,
            "os": operating_system, "architecture": architecture,
            "size": info.st_size, "sha256": sha256, "created_at": created,
        }

    def list_images(self) -> list[dict]:
        with self.lock, self.db() as conn:
            rows = conn.execute(
                "SELECT id,name,provider,os,architecture,size,sha256,created_at,enabled FROM vm_images ORDER BY created_at"
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _verify_image(image: sqlite3.Row | dict) -> None:
        path = Path(image["path"])
        if path.is_symlink() or not path.is_absolute() or not path.is_file():
            raise VMManagerError("registered VM image is missing or unsafe")
        info = path.stat()
        if info.st_size != image["size"]:
            raise VMManagerError("registered VM image size changed")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        if digest.hexdigest() != image["sha256"]:
            raise VMManagerError("registered VM image SHA-256 changed")

    def _vm(self, vm_id: str) -> dict:
        try:
            if str(uuid.UUID(vm_id)) != vm_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise VMNotFound("VM not found") from None
        with self.lock, self.db() as conn:
            row = conn.execute("SELECT * FROM virtual_machines WHERE id=?", (vm_id,)).fetchone()
        if row is None:
            raise VMNotFound("VM not found")
        item = dict(row)
        item.pop("request_hash", None)
        return item

    def get(self, vm_id: str) -> dict:
        return self._vm(vm_id)

    def list(self) -> list[dict]:
        with self.lock, self.db() as conn:
            rows = conn.execute(
                "SELECT * FROM virtual_machines ORDER BY created_at,id"
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item.pop("request_hash", None)
            result.append(item)
        return result

    def create(
        self, *, name: str, provider_id: str, image_id: str,
        cpu: int = 2, memory_mb: int = 4096, disk_gb: int = 40,
        idempotency_key: str,
    ) -> tuple[dict, bool]:
        if not self.provisioning_enabled:
            raise VMProvisioningDisabled("VM provisioning is disabled by operator policy")
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError("invalid VM name")
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY.fullmatch(idempotency_key):
            raise ValueError("invalid VM idempotency key")
        for field, value, minimum, maximum in (
            ("cpu", cpu, 1, min(64, self.quotas["max_vcpus"])),
            ("memory_mb", memory_mb, 512, self.quotas["max_memory_mb"]),
            ("disk_gb", disk_gb, 10, self.quotas["max_disk_gb"]),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise ValueError(f"{field} is outside configured bounds")
        if provider_id not in self.providers:
            raise VMManagerError("VM provider is not configured")
        try:
            if str(uuid.UUID(image_id)) != image_id:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ValueError("invalid image ID") from None

        with self.lock, self.db() as conn:
            old = conn.execute(
                "SELECT * FROM virtual_machines WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            request = {
                "name": name, "provider": provider_id, "image_id": image_id,
                "cpu": cpu, "memory_mb": memory_mb, "disk_gb": disk_gb,
            }
            request_hash = hashlib.sha256(
                json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            if old:
                if old["request_hash"] != request_hash:
                    raise VMConflict("idempotency key was already used for a different VM request")
                item = dict(old)
                item.pop("request_hash", None)
                return item, False
            image = conn.execute(
                "SELECT * FROM vm_images WHERE id=? AND enabled=1", (image_id,)
            ).fetchone()
            if image is None or image["provider"] != provider_id:
                raise VMManagerError("enabled VM image for this provider was not found")
            self._verify_image(image)
            provider = self._provider(provider_id)
            usage = conn.execute("""
                SELECT COUNT(*) AS count, COALESCE(SUM(cpu),0) AS cpu,
                       COALESCE(SUM(memory_mb),0) AS memory_mb,
                       COALESCE(SUM(disk_gb),0) AS disk_gb
                FROM virtual_machines WHERE state NOT IN ('deleted','failed')
            """).fetchone()
            if (usage["count"] >= self.quotas["max_vms"]
                    or usage["cpu"] + cpu > self.quotas["max_vcpus"]
                    or usage["memory_mb"] + memory_mb > self.quotas["max_memory_mb"]
                    or usage["disk_gb"] + disk_gb > self.quotas["max_disk_gb"]):
                raise VMQuotaExceeded("VM resource quota exceeded")
            vm_id = str(uuid.uuid4())
            created = _now()
            conn.execute("""
                INSERT INTO virtual_machines(
                    id,name,provider,image_id,cpu,memory_mb,disk_gb,state,
                    idempotency_key,request_hash,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,'provisioning',?,?,?,?)
            """, (vm_id, name, provider_id, image_id, cpu, memory_mb, disk_gb,
                  idempotency_key, request_hash, created, created))
            spec = {
                **request, "id": vm_id, "image_path": image["path"],
                "image_sha256": image["sha256"], "image_os": image["os"],
                "architecture": image["architecture"],
            }

        try:
            provider_ref = provider.create(spec)
            if not isinstance(provider_ref, str) or not provider_ref:
                raise VMManagerError("provider returned an invalid VM reference")
            with self.lock, self.db() as conn:
                conn.execute(
                    "UPDATE virtual_machines SET state='stopped',provider_ref=?,updated_at=?,last_error=NULL WHERE id=? AND state='provisioning'",
                    (provider_ref, _now(), vm_id),
                )
        except Exception as exc:
            with self.lock, self.db() as conn:
                conn.execute(
                    "UPDATE virtual_machines SET state='failed',updated_at=?,last_error=? WHERE id=?",
                    (_now(), type(exc).__name__, vm_id),
                )
            if isinstance(exc, VMManagerError):
                raise
            raise VMManagerError("VM provider create operation failed") from exc
        return self.get(vm_id), True

    def _transition(self, vm_id: str, action: str):
        if not self.provisioning_enabled:
            raise VMProvisioningDisabled("VM lifecycle operations are disabled by operator policy")
        vm = self._vm(vm_id)
        provider = self._provider(vm["provider"])
        transitions = {
            "start": ("stopped", "starting", "running"),
            "stop": ("running", "stopping", "stopped"),
            "delete": (("stopped", "running"), "deleting", "deleted"),
        }
        if action not in transitions:
            raise ValueError("unsupported VM action")
        allowed, transient, final = transitions[action]
        if isinstance(allowed, str):
            if vm["state"] == final:
                return vm
            if vm["state"] != allowed:
                raise VMConflict(f"cannot {action} VM in state {vm['state']}")
        elif vm["state"] not in allowed:
            if vm["state"] == "deleted" and action == "delete":
                return vm
            raise VMConflict(f"cannot {action} VM in state {vm['state']}")
        with self.lock, self.db() as conn:
            changed = conn.execute(
                "UPDATE virtual_machines SET state=?,updated_at=? WHERE id=? AND state=?",
                (transient, _now(), vm_id, vm["state"]),
            ).rowcount
            if changed != 1:
                raise VMConflict("VM state changed concurrently")
        try:
            if action == "start":
                provider.start(vm)
            elif action == "stop":
                provider.stop(vm)
            else:
                provider.delete(vm)
        except Exception as exc:
            with self.lock, self.db() as conn:
                conn.execute(
                    "UPDATE virtual_machines SET state=?,updated_at=?,last_error=? WHERE id=?",
                    (vm["state"], _now(), type(exc).__name__, vm_id),
                )
            raise VMManagerError(f"VM provider {action} operation failed") from exc
        with self.lock, self.db() as conn:
            conn.execute(
                "UPDATE virtual_machines SET state=?,updated_at=?,last_error=NULL WHERE id=?",
                (final, _now(), vm_id),
            )
        return self._vm(vm_id)

    def start(self, vm_id: str) -> dict:
        return self._transition(vm_id, "start")

    def stop(self, vm_id: str) -> dict:
        return self._transition(vm_id, "stop")

    def delete(self, vm_id: str) -> dict:
        return self._transition(vm_id, "delete")
