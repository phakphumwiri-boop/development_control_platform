"""Read-only host readiness checks for DCP Runner enrollment.

This module never contacts the Gateway, reads runner credentials, installs tools,
or executes project code. It only inspects the local toolchain.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def _tool(name: str, version_args=("--version",)) -> dict:
    executable = shutil.which(name)
    if not executable:
        return {"installed": False, "version": None}
    version = None
    try:
        result = subprocess.run(
            [executable, *version_args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            check=False,
        )
        output = (result.stdout or result.stderr).strip().splitlines()
        version = output[0][:240] if output else None
    except (OSError, subprocess.TimeoutExpired):
        version = "installed; version probe unavailable"
    return {"installed": True, "version": version}


def _android_sdk_root() -> Path | None:
    configured = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    candidates = [Path(configured)] if configured else []
    if not configured:
        if platform.system().lower() == "windows":
            local_app_data = os.environ.get("LOCALAPPDATA")
            if local_app_data:
                candidates.append(Path(local_app_data) / "Android" / "Sdk")
        elif platform.system().lower() == "darwin":
            candidates.append(Path.home() / "Library" / "Android" / "sdk")
        else:
            candidates.append(Path.home() / "Android" / "Sdk")
    return next((candidate for candidate in candidates if candidate.is_dir()), None)


def _adb_tool(sdk_root: Path | None) -> dict:
    discovered = _tool("adb", ("version",))
    if discovered["installed"] or sdk_root is None:
        return discovered
    executable = sdk_root / "platform-tools" / ("adb.exe" if platform.system().lower() == "windows" else "adb")
    if not executable.is_file():
        return {"installed": False, "version": None}
    try:
        result = subprocess.run(
            [str(executable), "version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            check=False,
        )
        output = (result.stdout or result.stderr).strip().splitlines()
        return {"installed": True, "version": output[0][:240] if output else None}
    except (OSError, subprocess.TimeoutExpired):
        return {"installed": True, "version": "installed; version probe unavailable"}


def _visual_studio() -> dict:
    candidates = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        / "Microsoft Visual Studio/Installer/vswhere.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        / "Microsoft Visual Studio/Installer/vswhere.exe",
    ]
    executable = next((item for item in candidates if item.is_file()), None)
    if executable is None:
        return {"installed": False, "version": None}
    try:
        result = subprocess.run(
            [str(executable), "-latest", "-property", "installationVersion"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            check=False,
        )
        version = result.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        version = None
    return {"installed": True, "version": version}


def collect_preflight() -> dict:
    system = platform.system().lower()
    host = {"darwin": "macos", "windows": "windows", "linux": "linux"}.get(system, system)
    android_sdk_root = _android_sdk_root()
    tools = {
        "python": {"installed": True, "version": platform.python_version()},
        "git": _tool("git"),
        "flutter": _tool("flutter"),
        "java": _tool("java", ("-version",)),
        "android_sdk": {
            "installed": android_sdk_root is not None,
            "version": str(android_sdk_root) if android_sdk_root else None,
        },
        "adb": _adb_tool(android_sdk_root),
    }
    if host == "windows":
        tools["visual_studio"] = _visual_studio()
    elif host == "macos":
        tools["xcodebuild"] = _tool("xcodebuild", ("-version",))
        tools["xcrun"] = _tool("xcrun", ("--version",))
        tools["cocoapods"] = _tool("pod", ("--version",))
    elif host == "linux":
        tools["clang"] = _tool("clang")
        tools["cmake"] = _tool("cmake")
        tools["ninja"] = _tool("ninja", ("--version",))

    flutter_ok = tools["flutter"]["installed"]
    git_ok = tools["git"]["installed"]
    capabilities = []
    if flutter_ok and git_ok:
        capabilities.extend(["flutter", "web"])
    if flutter_ok and git_ok and tools["java"]["installed"] and tools["android_sdk"]["installed"] and tools["adb"]["installed"]:
        capabilities.append("android")
    if host == "windows" and flutter_ok and git_ok and tools.get("visual_studio", {}).get("installed"):
        capabilities.append("windows")
    if host == "linux" and flutter_ok and git_ok and all(
        tools[name]["installed"] for name in ("clang", "cmake", "ninja")
    ):
        capabilities.append("linux")
    if host == "macos" and flutter_ok and git_ok and tools.get("xcodebuild", {}).get("installed"):
        capabilities.extend(["macos", "ios"])
    missing = [name for name in ("git", "flutter") if not tools[name]["installed"]]
    return {
        "schema_version": 1,
        "host_os": host,
        "python_version": platform.python_version(),
        "tools": tools,
        "detected_capabilities": sorted(set(capabilities)),
        "missing_required_tools": missing,
        "minimum_agent_prerequisites_met": not missing,
        "execution_enabled": False,
        "gateway_contacted": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only DCP Runner host preflight")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)
    report = collect_preflight()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        print("DCP Runner Host Preflight (read-only)")
        print("Host OS:", report["host_os"])
        for name, info in report["tools"].items():
            state = "FOUND" if info["installed"] else "MISSING"
            print(f"- {name}: {state}" + (f" ({info['version']})" if info.get("version") else ""))
        print("Detected capabilities:", ", ".join(report["detected_capabilities"]) or "none")
        print(
            "Minimum agent prerequisites:",
            "met" if report["minimum_agent_prerequisites_met"] else "missing",
        )
        print("Execution enabled: no")
        print("Gateway contacted: no")
    return 0 if report["minimum_agent_prerequisites_met"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
