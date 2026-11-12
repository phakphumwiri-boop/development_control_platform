"""Opt-in composition for the Azure ephemeral runner provider.

Constructors are local-only: no ARM, Key Vault, or GitHub API request is made
until the normal runner lifecycle invokes the provider or guest-profile factory.
The adapter is disabled unless DCP_AZURE_PROVIDER_ENABLED=true.
"""
from __future__ import annotations

import json
from collections.abc import Mapping

from .azure_identity import ManagedIdentityCredential
from .azure_network_policy import AzureEffectiveNetworkPolicyVerifier
from .azure_vm import AzureArmClient, AzureVMProvider
from .key_vault import KeyVaultSecretReader
from .runner_bootstrap import AzureRunnerBootstrapFactory


class AzureRuntimeConfigurationError(ValueError):
    """Azure provider configuration is incomplete or invalid."""


_REQUIRED = (
    "DCP_AZURE_SUBSCRIPTION_ID",
    "DCP_AZURE_RESOURCE_GROUP",
    "DCP_AZURE_LOCATION",
    "DCP_AZURE_SUBNET_ID",
    "DCP_AZURE_NSG_ID",
    "DCP_AZURE_LINUX_VM_SIZE",
    "DCP_AZURE_WINDOWS_VM_SIZE",
    "DCP_AZURE_LINUX_IMAGE_PUBLISHER",
    "DCP_AZURE_LINUX_IMAGE_OFFER",
    "DCP_AZURE_LINUX_IMAGE_SKU",
    "DCP_AZURE_LINUX_IMAGE_VERSION",
    "DCP_AZURE_WINDOWS_IMAGE_PUBLISHER",
    "DCP_AZURE_WINDOWS_IMAGE_OFFER",
    "DCP_AZURE_WINDOWS_IMAGE_SKU",
    "DCP_AZURE_WINDOWS_IMAGE_VERSION",
    "DCP_AZURE_KEY_VAULT_URL",
    "DCP_AZURE_EXPECTED_FIREWALL_IP",
    "DCP_AZURE_REQUIRED_OUTBOUND_FLOWS_JSON",
    "DCP_AZURE_LINUX_ADMIN_USERNAME",
    "DCP_AZURE_LINUX_SSH_PUBLIC_KEY_SECRET_NAME",
    "DCP_AZURE_WINDOWS_ADMIN_USERNAME",
    "DCP_AZURE_WINDOWS_ADMIN_PASSWORD_SECRET_NAME",
    "DCP_RUNNER_VERSION",
    "DCP_RUNNER_LINUX_SHA256",
    "DCP_RUNNER_WINDOWS_SHA256",
)


def _required_values(env: Mapping[str, str]) -> dict[str, str]:
    missing = [name for name in _REQUIRED if not isinstance(env.get(name), str) or not env[name].strip()]
    if missing:
        # Names are safe to report; configured values and secret contents are never included.
        raise AzureRuntimeConfigurationError(
            "Azure provider configuration is incomplete: " + ", ".join(missing)
        )
    return {name: env[name].strip() for name in _REQUIRED}


def _image_references(values: Mapping[str, str]) -> dict[str, dict[str, str]]:
    references = {}
    for os_name in ("linux", "windows"):
        reference = {
            key: values[f"DCP_AZURE_{os_name.upper()}_IMAGE_{suffix}"]
            for key, suffix in (
                ("publisher", "PUBLISHER"),
                ("offer", "OFFER"),
                ("sku", "SKU"),
                ("version", "VERSION"),
            )
        }
        if any(not value or value.lower() == "latest" for value in reference.values()):
            raise AzureRuntimeConfigurationError(
                "Azure Marketplace image references must be explicitly version-pinned"
            )
        references[os_name] = reference
    return references


def build_azure_provider_from_env(env, github_app, runner_online_checker):
    """Return None when disabled; otherwise build a no-I/O Azure provider adapter.

    Guest SSH/password secret values are fetched only when the bootstrap factory
    is invoked for a specific provision request. The factory never logs them.
    """
    values = env
    raw_enabled = values.get("DCP_AZURE_PROVIDER_ENABLED", "false")
    if not isinstance(raw_enabled, str) or raw_enabled.lower() not in ("true", "false"):
        raise AzureRuntimeConfigurationError("DCP_AZURE_PROVIDER_ENABLED must be true or false")
    if raw_enabled.lower() != "true":
        return None
    if github_app is None or not callable(runner_online_checker):
        raise AzureRuntimeConfigurationError(
            "Azure provider requires the configured GitHub App and online checker"
        )

    config = _required_values(values)
    try:
        flows = json.loads(config["DCP_AZURE_REQUIRED_OUTBOUND_FLOWS_JSON"])
        if not isinstance(flows, list) or not flows:
            raise ValueError("outbound flow allowlist must be a non-empty JSON array")

        credential = ManagedIdentityCredential(env=values)
        arm = AzureArmClient(
            config["DCP_AZURE_SUBSCRIPTION_ID"],
            config["DCP_AZURE_RESOURCE_GROUP"],
            credential,
        )
        secret_reader = KeyVaultSecretReader(config["DCP_AZURE_KEY_VAULT_URL"], credential)

        linux_username = config["DCP_AZURE_LINUX_ADMIN_USERNAME"]
        windows_username = config["DCP_AZURE_WINDOWS_ADMIN_USERNAME"]

        def os_profile_factory(vm_name, os_name, payload):
            if os_name == "linux":
                public_key = secret_reader.get_secret(
                    config["DCP_AZURE_LINUX_SSH_PUBLIC_KEY_SECRET_NAME"]
                )
                return {
                    "computerName": vm_name,
                    "adminUsername": linux_username,
                    "linuxConfiguration": {
                        "disablePasswordAuthentication": True,
                        "ssh": {
                            "publicKeys": [{
                                "path": f"/home/{linux_username}/.ssh/authorized_keys",
                                "keyData": public_key,
                            }]
                        },
                    },
                }
            if os_name == "windows":
                password = secret_reader.get_secret(
                    config["DCP_AZURE_WINDOWS_ADMIN_PASSWORD_SECRET_NAME"]
                )
                # Azure Windows computer names are limited to 15 characters.
                suffix = vm_name.rsplit("-", 1)[-1]
                return {
                    "computerName": "DCPW" + suffix.upper(),
                    "adminUsername": windows_username,
                    "adminPassword": password,
                }
            raise AzureRuntimeConfigurationError("Unsupported Azure guest operating system")

        bootstrap_factory = AzureRunnerBootstrapFactory(
            github_app,
            config["DCP_RUNNER_VERSION"],
            config["DCP_RUNNER_LINUX_SHA256"],
            config["DCP_RUNNER_WINDOWS_SHA256"],
            os_profile_factory,
        )
        network_policy = AzureEffectiveNetworkPolicyVerifier(
            arm,
            config["DCP_AZURE_NSG_ID"],
            flows,
            config["DCP_AZURE_EXPECTED_FIREWALL_IP"],
        )
        return AzureVMProvider(
            arm=arm,
            location=config["DCP_AZURE_LOCATION"],
            subnet_id=config["DCP_AZURE_SUBNET_ID"],
            nsg_id=config["DCP_AZURE_NSG_ID"],
            vm_sizes={
                "linux": config["DCP_AZURE_LINUX_VM_SIZE"],
                "windows": config["DCP_AZURE_WINDOWS_VM_SIZE"],
            },
            image_references=_image_references(config),
            bootstrap_factory=bootstrap_factory,
            runner_online_checker=runner_online_checker,
            network_policy_checker=network_policy,
        )
    except AzureRuntimeConfigurationError:
        raise
    except Exception as exc:
        # Do not include exception text: SDKs may include URLs or response fragments.
        raise AzureRuntimeConfigurationError(
            "Azure provider configuration could not be constructed: " + type(exc).__name__
        ) from exc
