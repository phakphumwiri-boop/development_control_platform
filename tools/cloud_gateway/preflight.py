"""Redacted, read-only deployment preflight for the DCP Cloud Gateway.

This command validates configuration syntax and reports deployment-only gates as
UNKNOWN/SKIPPED. It never reads secret values, contacts cloud APIs, starts
services, or provisions infrastructure.
"""
from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Mapping
from urllib.parse import urlparse


def _present(env: Mapping[str, str], name: str) -> bool:
    value = env.get(name, "")
    return isinstance(value, str) and bool(value.strip())


def _https_origin(value: str) -> bool:
    try:
        parsed = urlparse(value)
        # Accessing .port also validates malformed port syntax.
        _ = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and parsed.path in ("", "/")
        and not parsed.query
        and not parsed.fragment
    )


def _valid_amount(value: str) -> bool:
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return False
    return math.isfinite(amount) and amount > 0


def _resource_id(value: str, subscription: str, kind: str) -> bool:
    if kind == "subnet":
        suffix = r"/providers/Microsoft\.Network/virtualNetworks/[^/]+/subnets/[^/]+"
    else:
        suffix = r"/providers/Microsoft\.Network/networkSecurityGroups/[^/]+"
    pattern = (
        r"^/subscriptions/" + re.escape(subscription)
        + r"/resourceGroups/[A-Za-z0-9_.()-]{1,90}" + suffix + r"$"
    )
    return bool(re.fullmatch(pattern, value, re.IGNORECASE))


def inspect_environment(env: Mapping[str, str] | None = None) -> dict:
    """Return status-only evidence; configured values are never included."""
    values = os.environ if env is None else env
    checks: list[dict[str, str]] = []

    def add(name: str, status: str, detail: str) -> None:
        checks.append({"check": name, "status": status, "detail": detail})

    token_present = _present(values, "DCP_GATEWAY_API_TOKEN")
    add("gateway_api_token", "PASS" if token_present else "UNKNOWN",
        "Server-to-server bearer token is configured" if token_present
        else "DCP_GATEWAY_API_TOKEN is missing")

    proxy_secret = values.get("DCP_TRUSTED_PROXY_HMAC_SECRET", "")
    proxy_origin = values.get("DCP_PUBLIC_ORIGIN", "")
    proxy_ok = isinstance(proxy_secret, str) and len(proxy_secret) >= 32 and _https_origin(proxy_origin)
    add("trusted_proxy", "PASS" if proxy_ok else ("UNKNOWN" if not proxy_secret or not proxy_origin else "FAIL"),
        "Trusted proxy HMAC and HTTPS origin are syntactically valid" if proxy_ok
        else "Requires a 32+ character HMAC secret and a valid HTTPS origin")

    enabled = values.get("DCP_GATEWAY_PROVISIONING_ENABLED", "false").lower() == "true"
    approved = values.get("DCP_GATEWAY_OWNER_APPROVED", "false").lower() == "true"
    add("provisioning_disabled_by_default", "FAIL" if enabled else "PASS",
        "Provisioning is enabled before live acceptance; this preflight blocks readiness"
        if enabled else "Provisioning remains disabled")

    add("owner_approval", "PASS" if approved else "UNKNOWN",
        "Owner approval flag is enabled" if approved else "Owner approval is absent")

    repositories = tuple(x.strip() for x in values.get("DCP_GATEWAY_ALLOWED_REPOSITORIES", "").split(",") if x.strip())
    allowlist_ok = bool(repositories) and len(set(repositories)) == len(repositories) and all(
        re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", item)
        for item in repositories
    )
    add("repository_allowlist", "PASS" if allowlist_ok else ("UNKNOWN" if not repositories else "FAIL"),
        "A unique, syntactically valid owner/repository allowlist is configured"
        if allowlist_ok else "A non-empty unique owner/repository allowlist is required")

    github_names = (
        "DCP_AZURE_KEY_VAULT_URL", "DCP_GITHUB_APP_ID",
        "DCP_GITHUB_APP_INSTALLATION_ID", "DCP_GITHUB_APP_PRIVATE_KEY_SECRET_NAME",
    )
    github_present = all(_present(values, name) for name in github_names)
    vault_url = values.get("DCP_AZURE_KEY_VAULT_URL", "")
    try:
        vault_host = urlparse(vault_url).hostname or ""
    except ValueError:
        vault_host = ""
    github_valid = (
        github_present
        and _https_origin(vault_url)
        and len(vault_host.split(".")) == 4
        and vault_host.endswith(".vault.azure.net")
        and bool(re.fullmatch(r"[0-9]{1,20}", values.get("DCP_GITHUB_APP_ID", "")))
        and bool(re.fullmatch(r"[0-9]{1,20}", values.get("DCP_GITHUB_APP_INSTALLATION_ID", "")))
        and bool(re.fullmatch(r"[A-Za-z0-9-]{1,127}", values.get("DCP_GITHUB_APP_PRIVATE_KEY_SECRET_NAME", "")))
    )
    add("github_app_configuration", "PASS" if github_valid else ("UNKNOWN" if not github_present else "FAIL"),
        "GitHub App identifiers and Key Vault reference are syntactically valid"
        if github_valid else "Requires numeric App/installation IDs, an Azure Key Vault HTTPS origin, and a valid secret name")

    azure_names = (
        "DCP_AZURE_SUBSCRIPTION_ID", "DCP_AZURE_RESOURCE_GROUP",
        "DCP_AZURE_LOCATION", "DCP_AZURE_SUBNET_ID", "DCP_AZURE_NSG_ID",
        "DCP_AZURE_BUDGET_NAME", "DCP_AZURE_PROJECTED_RUN_COST_USD",
        "DCP_AZURE_LINUX_VM_SIZE", "DCP_AZURE_WINDOWS_VM_SIZE",
        "DCP_RUNNER_VERSION", "DCP_RUNNER_LINUX_SHA256", "DCP_RUNNER_WINDOWS_SHA256",
    )
    azure_present = all(_present(values, name) for name in azure_names)
    subscription = values.get("DCP_AZURE_SUBSCRIPTION_ID", "")
    azure_valid = (
        azure_present
        and bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", subscription))
        and bool(re.fullmatch(r"[A-Za-z0-9_.()-]{1,90}", values.get("DCP_AZURE_RESOURCE_GROUP", "")))
        and bool(re.fullmatch(r"[a-z0-9]+", values.get("DCP_AZURE_LOCATION", "")))
        and _resource_id(values.get("DCP_AZURE_SUBNET_ID", ""), subscription, "subnet")
        and _resource_id(values.get("DCP_AZURE_NSG_ID", ""), subscription, "nsg")
        and bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", values.get("DCP_AZURE_BUDGET_NAME", "")))
        and _valid_amount(values.get("DCP_AZURE_PROJECTED_RUN_COST_USD", ""))
        and all(re.fullmatch(r"[A-Za-z0-9_]+", values.get(name, "")) for name in
                ("DCP_AZURE_LINUX_VM_SIZE", "DCP_AZURE_WINDOWS_VM_SIZE"))
        and bool(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", values.get("DCP_RUNNER_VERSION", "")))
        and all(re.fullmatch(r"[a-fA-F0-9]{64}", values.get(name, "")) for name in
                ("DCP_RUNNER_LINUX_SHA256", "DCP_RUNNER_WINDOWS_SHA256"))
    )
    add("azure_configuration_presence", "PASS" if azure_valid else ("UNKNOWN" if not azure_present else "FAIL"),
        "Azure resource IDs, budget projection, VM sizes, and pinned runner artifacts are syntactically valid"
        if azure_valid else "Azure configuration is missing or contains invalid identifiers/values; values are not echoed")
    add("azure_network_policy", "UNKNOWN",
        "Subnet/NSG and effective egress policy require independent live verification")
    add("azure_guest_profile", "UNKNOWN",
        "Guest login profile and protected bootstrap require deployment-specific verification")

    orka_names = ("DCP_ORKA_URL", "DCP_ORKA_NAMESPACE", "DCP_ORKA_VM_CONFIG", "DCP_ORKA_API_TOKEN_SECRET_NAME")
    orka_present = all(_present(values, name) for name in orka_names)
    orka_url = values.get("DCP_ORKA_URL", "")
    try:
        orka_host = urlparse(orka_url).hostname or ""
    except ValueError:
        orka_host = ""
    orka_valid = (
        orka_present and _https_origin(orka_url)
        and bool(orka_host)
        and bool(re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", values.get("DCP_ORKA_NAMESPACE", "")))
        and bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", values.get("DCP_ORKA_VM_CONFIG", "")))
        and bool(re.fullmatch(r"[A-Za-z0-9-]{1,127}", values.get("DCP_ORKA_API_TOKEN_SECRET_NAME", "")))
    )
    add("orka_configuration_presence", "PASS" if orka_valid else ("UNKNOWN" if not orka_present else "FAIL"),
        "Orka HTTPS endpoint, namespace, VM config, and Key Vault secret reference are syntactically valid"
        if orka_valid else "Orka configuration is missing or invalid; values are not echoed")
    add("orka_budget_source", "UNKNOWN",
        "An authoritative Orka-specific budget reader and freshness policy are not implemented")
    add("orka_user_data_bootstrap", "UNKNOWN",
        "Protected macOS runner User Data bootstrap and registration verification are not implemented")

    add("live_provider_acceptance", "SKIPPED",
        "This read-only preflight never contacts Azure, Orka, GitHub, or creates resources")

    statuses = [item["status"] for item in checks]
    overall = "FAIL" if "FAIL" in statuses else (
        "UNKNOWN" if any(status in ("UNKNOWN", "SKIPPED") for status in statuses) else "PASS"
    )
    return {"overall": overall, "provisioning_enabled": enabled, "checks": checks}


def main() -> int:
    result = inspect_environment()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["overall"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
