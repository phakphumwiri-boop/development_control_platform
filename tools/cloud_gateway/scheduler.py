"""Capability- and host-aware scheduler for registered DCP local runners.

Scheduling only leases work to a live registered runner. Infrastructure catalog
entries and Fake Provider resources are never treated as executable hosts.
"""
from __future__ import annotations

from .runner_registry import RunnerRegistry


class RunnerScheduler:
    """Bridge the durable job queue to verified live Runner Registry entries."""

    def __init__(self, jobs, registry: RunnerRegistry, infrastructure_manager=None):
        self.jobs = jobs
        self.registry = registry
        self.infrastructure_manager = infrastructure_manager

    def eligible_runners(self, target):
        if target not in RunnerRegistryTargets.ALL:
            raise ValueError("Unsupported job target")
        required_host = RunnerRegistryTargets.REQUIRES_HOST.get(target)
        matches = []
        for runner in self.registry.list_workers():
            if runner.get("state") != "online":
                continue
            if required_host and runner.get("host_os") != required_host:
                continue
            if target in self.registry.allowed_targets(runner["worker_id"]):
                matches.append(runner)
        return matches

    def claim(self, worker_id, lease_seconds=30):
        runner = self.registry.get(worker_id)
        if runner is None:
            raise RunnerNotRegistered("Runner must register before claiming jobs")
        if runner.get("state") != "online":
            raise RunnerNotEligible("Runner is offline or draining")
        allowed = self.registry.allowed_targets(worker_id)
        host_os = runner.get("host_os")
        allowed = [
            target for target in allowed
            if target not in RunnerRegistryTargets.REQUIRES_HOST
            or RunnerRegistryTargets.REQUIRES_HOST[target] == host_os
        ]
        if not allowed:
            return None
        # Deliberately do not provision or bind Fake Provider resources here.
        return self.jobs.claim(worker_id, lease_seconds, allowed)

    def status(self):
        runners = self.registry.list_workers()
        return {
            "online": sum(row.get("state") == "online" for row in runners),
            "offline": sum(row.get("state") == "offline" for row in runners),
            "draining": sum(row.get("state") == "draining" for row in runners),
            "registered": len(runners),
            "provision_on_demand": False,
            "fake_infrastructure_is_executable": False,
            "infrastructure_provisioning_enabled": bool(
                getattr(self.infrastructure_manager, "provisioning_enabled", False)
            ),
        }


class RunnerNotRegistered(RuntimeError):
    pass


class RunnerNotEligible(RuntimeError):
    pass


class RunnerRegistryTargets:
    ALL = {
        "test", "build", "package", "build_android", "build_web",
        "build_windows", "build_linux", "build_macos", "build_ios",
    }
    REQUIRES_HOST = {
        "build_linux": "linux",
        "build_windows": "windows",
        "build_macos": "macos",
        "build_ios": "macos",
    }

