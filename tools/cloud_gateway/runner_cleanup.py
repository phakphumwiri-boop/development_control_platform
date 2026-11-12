"""Idempotent GitHub runner cleanup after provider deletion is confirmed."""
from .github_app import GitHubAppError


class GitHubRunnerCleanup:
    def __init__(self, github_app):
        self.github_app = github_app

    def __call__(self, row: dict, provider_state) -> str:
        if getattr(provider_state, "state", None) not in ("terminated", "failed"):
            raise GitHubAppError("Provider deletion is not confirmed")
        repository = row.get("repository")
        provider_id = row.get("provider_id")
        if not isinstance(repository, str) or not isinstance(provider_id, str):
            raise GitHubAppError("Runner cleanup record is missing repository identity")
        if ":" in provider_id:
            provider, runner_name = provider_id.split(":", 1)
            if provider not in ("azure", "orka") or not runner_name:
                raise GitHubAppError("Runner cleanup provider identity is invalid")
        else:
            # Preserve compatibility with records written before ProviderRouter
            # added the provider namespace to durable provider IDs.
            runner_name = provider_id
        accessible = getattr(self.github_app, "is_repository_accessible", None)
        if not callable(accessible) or accessible(repository, refresh=True) is not True:
            raise GitHubAppError("Repository is not accessible to the DCP GitHub App installation")
        runner = self.github_app.find_runner(repository, runner_name)
        if runner is None:
            return "already_absent"
        if runner["status"] != "offline":
            raise GitHubAppError("Refusing cleanup until the GitHub runner is offline")
        if self.github_app.remove_runner(repository, runner["id"]) is not True:
            raise GitHubAppError("GitHub runner deregistration request was not confirmed")
        remaining = self.github_app.find_runner(repository, runner_name)
        if remaining is not None:
            raise GitHubAppError("GitHub runner deregistration is not yet confirmed")
        return "removed"
