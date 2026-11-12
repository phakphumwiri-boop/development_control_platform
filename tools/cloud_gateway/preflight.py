"""Redacted, read-only deployment preflight for the DCP Cloud Gateway.

This command validates configuration syntax and reports deployment-only gates as
UNKNOWN/SKIPPED. It never reads secret values, contacts cloud APIs, starts
services, or provisions infrastructure.
"""
from __future__ import annotations

import ipaddress
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


def _valid_firewall_ip(value: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return False
    return (
        address.version == 4
        and address.is_private
        and not (
            address.is_loopback or address.is_link_local
            or address.is_multicast or address.is_unspecified
            or address.is_reserved
        )
    )


def _valid_outbound_flows(value: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        flows = json.loads(value)
    except (TypeError, ValueError):
        return False
    if not isinstance(flows, list) or not 1 <= len(flows) <= 64:
        return False
    seen = set()
    for flow in flows:
        if not isinstance(flow, dict) or set(flow) != {"protocol", "port", "destination"}:
            return False
        protocol = flow.get("protocol")
        port = flow.get("port")
        destination = flow.get("destination")
        if protocol not in ("Tcp", "Udp"):
            return False
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return False
        if not isinstance(destination, str):
            return False
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            return False
        if network.version != 4 or network.prefixlen == 0 or network.is_multicast or network.is_unspecified:
            return False
        key = (protocol, port, str(network))
        if key in seen:
            return False
        seen.add(key)
    return True


def _valid_guest_profile_references(env: Mapping[str, str]) -> bool:
    linux_user = env.get("DCP_AZURE_LINUX_ADMIN_USERNAME", "")
    windows_user = env.get("DCP_AZURE_WINDOWS_ADMIN_USERNAME", "")
    linux_key_name = env.get("DCP_AZURE_LINUX_SSH_PUBLIC_KEY_SECRET_NAME", "")
    windows_password_name = env.get("DCP_AZURE_WINDOWS_ADMIN_PASSWORD_SECRET_NAME", "")
    if not all(isinstance(item, str) for item in (
        linux_user, windows_user, linux_key_name, windows_password_name
    )):
        return False
    user_pattern = r"[a-z_][a-z0-9_-]{0,31}"
    reserved = {"root", "admin", "administrator", "guest"}
    return (
        bool(re.fullmatch(user_pattern, linux_user))
        and linux_user not in reserved
        and bool(re.fullmatch(user_pattern, windows_user))
        and windows_user not in reserved
        and bool(re.fullmatch(r"[A-Za-z0-9-]{1,127}", linux_key_name))
        and bool(re.fullmatch(r"[A-Za-z0-9-]{1,127}", windows_password_name))
    )


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
        "DCP_AZURE_LINUX_IMAGE_PUBLISHER", "DCP_AZURE_LINUX_IMAGE_OFFER",
        "DCP_AZURE_LINUX_IMAGE_SKU", "DCP_AZURE_LINUX_IMAGE_VERSION",
        "DCP_AZURE_WINDOWS_IMAGE_PUBLISHER", "DCP_AZURE_WINDOWS_IMAGE_OFFER",
        "DCP_AZURE_WINDOWS_IMAGE_SKU", "DCP_AZURE_WINDOWS_IMAGE_VERSION",
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
        and all(
            re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", values.get(name, ""))
            and values.get(name, "").lower() != "latest"
            for name in (
                "DCP_AZURE_LINUX_IMAGE_PUBLISHER", "DCP_AZURE_LINUX_IMAGE_OFFER",
                "DCP_AZURE_LINUX_IMAGE_SKU", "DCP_AZURE_LINUX_IMAGE_VERSION",
                "DCP_AZURE_WINDOWS_IMAGE_PUBLISHER", "DCP_AZURE_WINDOWS_IMAGE_OFFER",
                "DCP_AZURE_WINDOWS_IMAGE_SKU", "DCP_AZURE_WINDOWS_IMAGE_VERSION",
            )
        )
        and bool(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", values.get("DCP_RUNNER_VERSION", "")))
        and all(re.fullmatch(r"[a-fA-F0-9]{64}", values.get(name, "")) for name in
                ("DCP_RUNNER_LINUX_SHA256", "DCP_RUNNER_WINDOWS_SHA256"))
    )
    add("azure_configuration_presence", "PASS" if azure_valid else ("UNKNOWN" if not azure_present else "FAIL"),
        "Azure resource IDs, budget projection, VM sizes, and pinned runner artifacts are syntactically valid"
        if azure_valid else "Azure configuration is missing or contains invalid identifiers/values; values are not echoed")
    network_names = (
        "DCP_AZURE_EXPECTED_FIREWALL_IP",
        "DCP_AZURE_REQUIRED_OUTBOUND_FLOWS_JSON",
    )
    network_any = any(_present(values, name) for name in network_names)
    network_present = all(_present(values, name) for name in network_names)
    network_valid = (
        network_present
        and _valid_firewall_ip(values.get("DCP_AZURE_EXPECTED_FIREWALL_IP", ""))
        and _valid_outbound_flows(values.get("DCP_AZURE_REQUIRED_OUTBOUND_FLOWS_JSON", ""))
    )
    add(
        "azure_network_policy_configuration",
        "PASS" if network_valid else ("FAIL" if network_any else "UNKNOWN"),
        "Private firewall IP and bounded outbound flow allowlist are syntactically valid"
        if network_valid else "Requires a private IPv4 firewall IP and a non-empty, bounded TCP/UDP CIDR/port allowlist",
    )
    add("azure_network_policy", "UNKNOWN",
        "Subnet/NSG and effective egress policy require independent live verification")
    guest_names = (
        "DCP_AZURE_LINUX_ADMIN_USERNAME",
        "DCP_AZURE_LINUX_SSH_PUBLIC_KEY_SECRET_NAME",
        "DCP_AZURE_WINDOWS_ADMIN_USERNAME",
        "DCP_AZURE_WINDOWS_ADMIN_PASSWORD_SECRET_NAME",
    )
    guest_any = any(_present(values, name) for name in guest_names)
    guest_present = all(_present(values, name) for name in guest_names)
    guest_valid = guest_present and _valid_guest_profile_references(values)
    add(
        "azure_guest_profile_configuration",
        "PASS" if guest_valid else ("FAIL" if guest_any else "UNKNOWN"),
        "Linux/Windows administrator names and Key Vault secret references are syntactically valid"
        if guest_valid else "Requires valid Linux/Windows administrator names and Key Vault secret names; secret values are never read",
    )
    add("azure_guest_profile", "UNKNOWN",
        "Guest login profile and protected bootstrap require deployment-specific verification")

    provider_flag = values.get("DCP_AZURE_PROVIDER_ENABLED", "false")
    provider_flag_valid = isinstance(provider_flag, str) and provider_flag.lower() in ("true", "false")
    provider_enabled = provider_flag_valid and provider_flag.lower() == "true"
    identity_endpoint = values.get("IDENTITY_ENDPOINT", "")
    identity_header = values.get("IDENTITY_HEADER", "")
    use_imds = values.get("DCP_AZURE_USE_IMDS", "false")
    identity_mode_valid = isinstance(use_imds, str) and use_imds.lower() in ("true", "false")
    if identity_endpoint or identity_header:
        try:
            identity_url = urlparse(identity_endpoint)
            identity_endpoint_valid = (
                isinstance(identity_endpoint, str) and isinstance(identity_header, str)
                and bool(identity_header) and identity_url.scheme == "http"
                and identity_url.hostname in ("localhost", "127.0.0.1", "::1")
            )
        except ValueError:
            identity_endpoint_valid = False
    else:
        identity_endpoint_valid = False
    managed_identity_valid = identity_mode_valid and (
        identity_endpoint_valid or use_imds.lower() == "true"
    )
    add(
        "azure_managed_identity_configuration",
        "PASS" if (not provider_enabled and provider_flag_valid) or managed_identity_valid else "FAIL",
        "Azure provider is disabled; managed identity is not required"
        if not provider_enabled and provider_flag_valid else (
            "Trusted managed identity endpoint or explicit IMDS mode is configured"
            if managed_identity_valid else
            "Azure provider opt-in requires a trusted local identity endpoint with header or DCP_AZURE_USE_IMDS=true"
        ),
    )
    provider_ready_config = (
        provider_flag_valid and (
            not provider_enabled
            or (azure_valid and github_valid and network_valid and guest_valid and managed_identity_valid)
        )
    )
    add(
        "azure_provider_runtime",
        "PASS" if provider_ready_config else "FAIL",
        "Azure runtime adapter is explicitly disabled"
        if provider_ready_config and not provider_enabled else (
            "Azure runtime adapter configuration is complete; live Azure and per-NIC egress checks remain separate"
            if provider_ready_config else
            "Provider opt-in requires valid Azure IDs, pinned images, GitHub App, egress allowlist, and guest profile references"
        ),
    )

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
