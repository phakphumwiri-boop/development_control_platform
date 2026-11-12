"""DCP Runner Agent CLI: health check or one explicitly enabled job."""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
from pathlib import Path

from .client import GatewayClient, RunnerAgentConfig, RunnerGatewayError
from .checkout import GitHubCommitCheckout
from .execution import FlutterBuildExecutor
from .pipeline import RunnerPipeline
from .workspace import WorkspaceManager
from tools.runner_agent.preflight import collect_preflight, resolve_capabilities


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < 1:
        raise ValueError(f"{name} must be positive")
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="DCP local Runner Agent")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument(
        "--check", action="store_true",
        help="validate Gateway connectivity only; does not claim or execute a job",
    )
    modes.add_argument(
        "--once", action="store_true",
        help="claim and process at most one job; requires explicit execution opt-in",
    )
    args = parser.parse_args(argv)
    try:
        config = RunnerAgentConfig.from_env()
        client = GatewayClient(config)
        health = client.health()
        if health.get("status") != "ok":
            raise RunnerGatewayError("Gateway health check did not report ready")
        if args.check:
            print(json.dumps({
                "agent": "ready", "worker_id": config.worker_id,
                "gateway_status": health.get("status"),
                "mode": "control-plane-only", "job_execution_enabled": False,
            }, indent=2, sort_keys=True))
            return 0

        if os.environ.get("DCP_RUNNER_EXECUTION_ENABLED") != "1":
            raise ValueError("DCP_RUNNER_EXECUTION_ENABLED=1 is required for --once")
        root = os.environ.get("DCP_RUNNER_WORKSPACE_ROOT", "")
        if not root or not Path(root).is_absolute():
            raise ValueError("DCP_RUNNER_WORKSPACE_ROOT must be an absolute path")
        raw_repositories = json.loads(os.environ.get("DCP_RUNNER_TRUSTED_REPOSITORIES", "[]"))
        if (not isinstance(raw_repositories, list) or not raw_repositories
                or any(
                    not isinstance(item, str)
                    or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", item)
                    or any(part in (".", "..") for part in item.split("/"))
                    for item in raw_repositories
                )
                or len(raw_repositories) != len(set(raw_repositories))):
            raise ValueError("DCP_RUNNER_TRUSTED_REPOSITORIES must be a non-empty JSON string array")
        manager = WorkspaceManager(
            root,
            max_active=_positive_int("DCP_RUNNER_MAX_ACTIVE_WORKSPACES", 8),
            max_workspace_bytes=_positive_int(
                "DCP_RUNNER_MAX_WORKSPACE_BYTES", 2 * 1024 * 1024 * 1024
            ),
        )
        checkout = GitHubCommitCheckout(
            manager, token=os.environ.get("DCP_GITHUB_TOKEN") or None,
            max_archive_bytes=_positive_int("DCP_RUNNER_MAX_ARCHIVE_BYTES", 100 * 1024 * 1024),
            max_expanded_bytes=_positive_int(
                "DCP_RUNNER_MAX_EXPANDED_BYTES", 1024 * 1024 * 1024
            ),
        )
        executor = FlutterBuildExecutor(
            manager, enabled=True,
            timeout_seconds=_positive_int("DCP_RUNNER_BUILD_TIMEOUT_SECONDS", 1800),
            max_output_bytes=_positive_int(
                "DCP_RUNNER_MAX_OUTPUT_BYTES", 5 * 1024 * 1024
            ),
        )
        host_os = platform.system().lower()
        if host_os == "darwin":
            host_os = "macos"
        if host_os not in ("linux", "windows", "macos"):
            raise ValueError("unsupported Runner host operating system")
        preflight = collect_preflight()
        if preflight.get("host_os") != host_os:
            raise ValueError("Runner host preflight OS does not match this machine")
        raw_capabilities = os.environ.get("DCP_RUNNER_CAPABILITIES")
        configured_capabilities = (
            json.loads(raw_capabilities) if raw_capabilities is not None else None
        )
        capabilities = resolve_capabilities(preflight, configured_capabilities)
        pipeline = RunnerPipeline(
            client, manager, checkout, executor,
            trusted_repositories=frozenset(raw_repositories),
            worker_os=host_os,
            capabilities=frozenset(capabilities),
        )
        result = pipeline.run_once()
        if result is None:
            print(json.dumps({"agent": "idle", "worker_id": config.worker_id}))
            return 0
        job = result.get("job", {})
        summary = {
            "agent": "completed" if result.get("outcome") == "succeeded" else result.get("outcome"),
            "job_id": job.get("id", result.get("job_id")),
            "job_state": job.get("state"),
            "error": result.get("error"),
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if result.get("outcome") == "succeeded" else 1
    except (ValueError, RunnerGatewayError) as exc:
        print(json.dumps({"agent": "not_ready", "error": str(exc)}), file=sys.stderr)
        return 1
    except Exception as exc:
        # Never print arbitrary exception text; it may contain request or credential data.
        print(json.dumps({"agent": "failed", "error": type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
