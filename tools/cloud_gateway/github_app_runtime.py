"""Fail-closed composition for GitHub App runner identity and cleanup."""
from __future__ import annotations

import os
import re

from .azure_identity import ManagedIdentityCredential
from .github_app import GitHubAppRunnerBootstrap, GitHubRunnerOnlineChecker
from .key_vault import KeyVaultSecretReader
from .runner_cleanup import GitHubRunnerCleanup


def build_github_app_runtime(settings, env=None):
    """Return (GitHub App, online checker, cleanup callback), or disabled tuple.

    All configuration is opt-in. The App private key is fetched from Key Vault
    at startup and retained only in process memory. No cloud resource is created.
    """
    values = os.environ if env is None else env
    names = (
        "DCP_AZURE_KEY_VAULT_URL",
        "DCP_GITHUB_APP_ID",
        "DCP_GITHUB_APP_INSTALLATION_ID",
        "DCP_GITHUB_APP_PRIVATE_KEY_SECRET_NAME",
    )
    configured = [bool(values.get(name, "").strip()) for name in names]
    if not any(configured):
        return None, None, None
    if not all(configured):
        raise ValueError("GitHub App runtime configuration is incomplete")
    # In GitHub App mode, the installation catalog is the source of truth;
    # legacy static allowlists must not silently hide installed repositories.
    repositories = ()
    installation_raw = values["DCP_GITHUB_APP_INSTALLATION_ID"]
    if not re.fullmatch(r"[0-9]{1,20}", installation_raw):
        raise ValueError("GitHub App installation ID must be numeric")

    credential = ManagedIdentityCredential(env=values)
    secret_reader = KeyVaultSecretReader(values["DCP_AZURE_KEY_VAULT_URL"], credential)
    private_key = secret_reader.get_secret(values["DCP_GITHUB_APP_PRIVATE_KEY_SECRET_NAME"])
    app = GitHubAppRunnerBootstrap(
        values["DCP_GITHUB_APP_ID"],
        int(installation_raw),
        private_key,
        repositories,
    )
    checker = GitHubRunnerOnlineChecker(app)

    cleanup = GitHubRunnerCleanup(app)

    return app, checker, cleanup
