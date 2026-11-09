"""One-job Runner pipeline joining Gateway, checkout, workspace and Flutter execution."""
from __future__ import annotations

import time
from dataclasses import asdict
from typing import Protocol

from .checkout import CheckoutError
from .execution import ExecutionError, FlutterBuildExecutor
from .workspace import WorkspaceError, WorkspaceManager


class CheckoutProvider(Protocol):
    def checkout(self, job_id: str, worker_id: str, repository: str, commit_sha: str):
        ...


class RunnerPipeline:
    """Claim and execute one allowlisted Flutter job; never polls indefinitely."""

    def __init__(
        self,
        client,
        workspaces: WorkspaceManager,
        checkout: CheckoutProvider,
        executor: FlutterBuildExecutor,
        *,
        heartbeat_interval_seconds: int = 10,
        trusted_repositories: set[str] | frozenset[str] = frozenset(),
    ):
        if isinstance(heartbeat_interval_seconds, bool) or not isinstance(heartbeat_interval_seconds, int) or not 5 <= heartbeat_interval_seconds <= 60:
            raise ValueError("heartbeat interval must be between 5 and 60 seconds")
        self.client = client
        self.workspaces = workspaces
        self.checkout_provider = checkout
        self.executor = executor
        self.heartbeat_interval_seconds = heartbeat_interval_seconds
        self.trusted_repositories = frozenset(trusted_repositories)

    def run_once(self) -> dict | None:
        """Claim at most one job. Returns None when the queue is empty."""
        job = self.client.claim(lease_seconds=120)
        if job is None:
            return None
        job_id = job["id"]
        worker_id = job["worker"]
        allocated = False
        outcome = "failed"
        error_code = "RUNNER_EXECUTION_FAILED"
        result = {}
        last_heartbeat = 0.0
        try:
            if job["repository"] not in self.trusted_repositories:
                raise ExecutionError("repository is not in the Runner trusted-repository allowlist")
            self.workspaces.create(job_id, worker_id)
            allocated = True
            self.client.append_log(job_id, "Runner claimed job; workspace allocated", "system")
            source = self.checkout_provider.checkout(
                job_id, worker_id, job["repository"], job["commit_sha"]
            )
            self.client.append_log(
                job_id, f"Checked out immutable commit {job['commit_sha']}", "system"
            )

            def cancellation_requested():
                nonlocal last_heartbeat
                now = time.monotonic()
                if now - last_heartbeat < self.heartbeat_interval_seconds:
                    return False
                current = self.client.heartbeat(job_id, lease_seconds=120)
                last_heartbeat = now
                return current.get("state") == "cancel_requested"

            self.executor.log = lambda stream, message: self.client.append_log(job_id, message, stream)
            build = self.executor.run(
                job_id, worker_id, job["target"],
                cancel_requested=cancellation_requested,
            )
            outcome = build.outcome
            error_code = build.error_code
            result = {
                "command": list(build.command),
                "return_code": build.return_code,
                "duration_seconds": build.duration_seconds,
                "output_bytes": build.output_bytes,
                "source_directory": str(source.relative_to(self.workspaces.get(job_id, worker_id))),
            }
            self.client.append_log(
                job_id,
                f"Flutter execution {outcome}; exit={build.return_code}; "
                f"duration={build.duration_seconds}s; output={build.output_bytes} bytes",
                "system",
            )
            if outcome == "succeeded":
                error_code = None
        except (CheckoutError, ExecutionError, WorkspaceError) as exc:
            self.client.append_log(
                job_id, f"Runner rejected job safely: {type(exc).__name__}", "stderr"
            )
            result = {"error": type(exc).__name__}
            error_code = "RUNNER_POLICY_OR_BUILD_ERROR"
        except Exception as exc:
            # Do not echo exception text: transport and provider errors can contain secrets.
            try:
                self.client.append_log(
                    job_id, f"Runner failed safely: {type(exc).__name__}", "stderr"
                )
            except Exception:
                pass
            result = {"error": type(exc).__name__}
            error_code = "RUNNER_INTERNAL_ERROR"
        finally:
            if allocated:
                try:
                    self.workspaces.cleanup(job_id, worker_id)
                    self.client.append_log(job_id, "Workspace cleaned", "system")
                except Exception:
                    outcome = "failed"
                    error_code = "WORKSPACE_CLEANUP_FAILED"
                    result["workspace_cleanup"] = "failed"
        try:
            completed = self.client.finish(
                job_id, outcome, result=result, error_code=error_code
            )
            return {"job": completed, "outcome": outcome, "result": result}
        except Exception:
            # A lost/expired lease must never be reported as a successful completion.
            return {
                "job_id": job_id, "outcome": "unconfirmed",
                "error": "JOB_FINISH_NOT_CONFIRMED",
            }
