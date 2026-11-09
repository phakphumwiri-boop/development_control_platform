"""Opt-in local Hyper-V provider using fixed PowerShell scripts and VHDX differencing disks."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from .vm_manager import VMManagerError


class HyperVProvider:
    provider_id = "hyperv"

    def __init__(
        self,
        storage_root: str | os.PathLike,
        switch_name: str,
        *,
        enabled: bool = False,
        powershell: str | None = None,
        command_runner: Callable = subprocess.run,
        timeout_seconds: int = 300,
    ):
        raw = Path(storage_root).expanduser()
        if not raw.is_absolute():
            raise ValueError("Hyper-V storage root must be absolute")
        if raw.exists() and raw.is_symlink():
            raise VMManagerError("Hyper-V storage root must not be a symlink")
        if not isinstance(switch_name, str) or not re.fullmatch(r"[A-Za-z0-9_. -]{1,64}", switch_name):
            raise ValueError("invalid Hyper-V virtual switch name")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 1800:
            raise ValueError("timeout_seconds must be between 1 and 1800")
        self.storage_root = raw
        self.switch_name = switch_name
        self.enabled = enabled
        self.powershell = powershell or shutil.which("powershell.exe") or shutil.which("pwsh")
        self.command_runner = command_runner
        self.timeout_seconds = timeout_seconds
        self.script_root = Path(__file__).resolve().parent / "providers"

    def available(self) -> bool:
        return bool(self.enabled and os.name == "nt" and self.powershell and self.storage_root.is_absolute())

    def _environment(self, spec: dict, action: str | None = None) -> dict:
        allowed = ("SystemRoot", "WINDIR", "PATH", "TEMP", "TMP", "USERPROFILE",
                   "ProgramData", "PSModulePath")
        env = {key: os.environ[key] for key in allowed if key in os.environ}
        env.update({
            "DCP_VM_ID": str(spec["id"]),
            "DCP_VM_NAME": str(spec["name"]),
            "DCP_VM_IMAGE": str(spec["image_path"]),
            "DCP_VM_DISK": str(self.storage_root / str(spec["id"]) / "disk.vhdx"),
            "DCP_VM_SWITCH": self.switch_name,
            "DCP_VM_CPU": str(spec["cpu"]),
            "DCP_VM_MEMORY_MB": str(spec["memory_mb"]),
            "DCP_VM_DISK_GB": str(spec["disk_gb"]),
        })
        if action:
            env["DCP_VM_ACTION"] = action
        return env

    def _run_script(self, script_name: str, spec: dict, action: str | None = None) -> str:
        if not self.available():
            raise VMManagerError("Hyper-V provider is disabled or unavailable")
        script = self.script_root / script_name
        if not script.is_file():
            raise VMManagerError("fixed Hyper-V provider script is missing")
        result = self.command_runner(
            [
                self.powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-File", str(script),
            ],
            shell=False, check=False, capture_output=True, text=True,
            timeout=self.timeout_seconds, env=self._environment(spec, action),
        )
        if result.returncode != 0:
            raise VMManagerError("Hyper-V provider operation failed")
        return (result.stdout or "").strip()

    def create(self, spec: dict) -> str:
        if spec.get("image_os") not in ("windows", "linux"):
            raise VMManagerError("Hyper-V provider supports Windows and Linux guest images only")
        image = Path(spec["image_path"])
        if image.suffix.lower() != ".vhdx" or image.is_symlink() or not image.is_file():
            raise VMManagerError("Hyper-V base image must be a regular VHDX file")
        self.storage_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.storage_root.is_symlink():
            raise VMManagerError("Hyper-V storage root became unsafe")
        vm_dir = self.storage_root / spec["id"]
        if vm_dir.exists() or vm_dir.is_symlink():
            raise VMManagerError("Hyper-V VM storage directory already exists")
        vm_dir.mkdir(mode=0o700)
        try:
            provider_ref = self._run_script("hyperv_create.ps1", spec)
            return provider_ref or spec["id"]
        except Exception:
            try:
                self._run_script("hyperv_manage.ps1", spec, "delete")
            except Exception:
                pass
            shutil.rmtree(vm_dir, ignore_errors=True)
            raise

    def start(self, vm: dict) -> None:
        self._run_script("hyperv_manage.ps1", vm, "start")

    def stop(self, vm: dict) -> None:
        self._run_script("hyperv_manage.ps1", vm, "stop")

    def delete(self, vm: dict) -> None:
        self._run_script("hyperv_manage.ps1", vm, "delete")
        vm_dir = self.storage_root / vm["id"]
        if vm_dir.exists() and not vm_dir.is_symlink():
            shutil.rmtree(vm_dir)
