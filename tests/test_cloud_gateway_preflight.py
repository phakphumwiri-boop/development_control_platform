"""Read-only deployment preflight tests; no network or secrets are used."""
import unittest

from tools.cloud_gateway.preflight import inspect_environment


SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"


def valid_environment():
    return {
        "DCP_GATEWAY_API_TOKEN": "x" * 40,
        "DCP_TRUSTED_PROXY_HMAC_SECRET": "h" * 40,
        "DCP_PUBLIC_ORIGIN": "https://dcp.example.test",
        "DCP_GATEWAY_ALLOWED_REPOSITORIES": "owner/repo",
        "DCP_GATEWAY_OWNER_APPROVED": "true",
        "DCP_AZURE_KEY_VAULT_URL": "https://dcp-vault.vault.azure.net",
        "DCP_GITHUB_APP_ID": "123456",
        "DCP_GITHUB_APP_INSTALLATION_ID": "987654",
        "DCP_GITHUB_APP_PRIVATE_KEY_SECRET_NAME": "github-app-key",
        "DCP_AZURE_SUBSCRIPTION_ID": SUBSCRIPTION,
        "DCP_AZURE_RESOURCE_GROUP": "dcp-runners",
        "DCP_AZURE_LOCATION": "eastus",
        "DCP_AZURE_SUBNET_ID": (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/network/providers/"
            "Microsoft.Network/virtualNetworks/dcp-vnet/subnets/runners"
        ),
        "DCP_AZURE_NSG_ID": (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/network/providers/"
            "Microsoft.Network/networkSecurityGroups/dcp-runners"
        ),
        "DCP_AZURE_BUDGET_NAME": "dcp-monthly",
        "DCP_AZURE_PROJECTED_RUN_COST_USD": "1.25",
        "DCP_AZURE_LINUX_VM_SIZE": "Standard_D2s_v5",
        "DCP_AZURE_WINDOWS_VM_SIZE": "Standard_D4s_v5",
        "DCP_AZURE_LINUX_IMAGE_PUBLISHER": "Canonical",
        "DCP_AZURE_LINUX_IMAGE_OFFER": "ubuntu-24_04-lts",
        "DCP_AZURE_LINUX_IMAGE_SKU": "server",
        "DCP_AZURE_LINUX_IMAGE_VERSION": "24.04.202501150",
        "DCP_AZURE_WINDOWS_IMAGE_PUBLISHER": "MicrosoftWindowsServer",
        "DCP_AZURE_WINDOWS_IMAGE_OFFER": "WindowsServer",
        "DCP_AZURE_WINDOWS_IMAGE_SKU": "2025-datacenter-g2",
        "DCP_AZURE_WINDOWS_IMAGE_VERSION": "20348.1.250101",
        "DCP_AZURE_PROVIDER_ENABLED": "false",
        "DCP_AZURE_USE_IMDS": "true",
        "DCP_AZURE_EXPECTED_FIREWALL_IP": "10.20.0.4",
        "DCP_AZURE_REQUIRED_OUTBOUND_FLOWS_JSON": (
            '[{"protocol":"Tcp","port":443,"destination":"198.51.100.0/24"}]'
        ),
        "DCP_AZURE_LINUX_ADMIN_USERNAME": "dcplinux",
        "DCP_AZURE_LINUX_SSH_PUBLIC_KEY_SECRET_NAME": "dcp-linux-ssh-public",
        "DCP_AZURE_WINDOWS_ADMIN_USERNAME": "dcpwindows",
        "DCP_AZURE_WINDOWS_ADMIN_PASSWORD_SECRET_NAME": "dcp-windows-admin-password",
        "DCP_RUNNER_VERSION": "2.331.0",
        "DCP_RUNNER_LINUX_SHA256": "a" * 64,
        "DCP_RUNNER_WINDOWS_SHA256": "b" * 64,
        "DCP_ORKA_URL": "https://orka.example.test",
        "DCP_ORKA_NAMESPACE": "dcp-runners",
        "DCP_ORKA_VM_CONFIG": "macos-15-arm64",
        "DCP_ORKA_API_TOKEN_SECRET_NAME": "orka-api-token",
    }


class GatewayPreflightTests(unittest.TestCase):
    def test_empty_environment_is_unknown_and_provisioning_stays_disabled(self):
        result = inspect_environment({})
        self.assertEqual(result["overall"], "UNKNOWN")
        self.assertFalse(result["provisioning_enabled"])
        self.assertTrue(any(item["status"] == "SKIPPED" for item in result["checks"]))

    def test_never_echoes_secret_values(self):
        marker = "DO-NOT-LEAK-THIS-SECRET-VALUE"
        result = inspect_environment({
            "DCP_GATEWAY_API_TOKEN": marker,
            "DCP_TRUSTED_PROXY_HMAC_SECRET": marker,
        })
        self.assertNotIn(marker, str(result))

    def test_syntax_checks_pass_but_live_gates_remain_unknown(self):
        result = inspect_environment(valid_environment())
        checks = {item["check"]: item for item in result["checks"]}
        for name in (
            "gateway_api_token", "trusted_proxy", "owner_approval",
            "repository_allowlist", "github_app_configuration",
            "azure_configuration_presence", "azure_network_policy_configuration",
            "azure_guest_profile_configuration", "azure_managed_identity_configuration",
            "azure_provider_runtime", "orka_configuration_presence",
        ):
            self.assertEqual(checks[name]["status"], "PASS", name)
        self.assertEqual(checks["azure_network_policy"]["status"], "UNKNOWN")
        self.assertEqual(checks["azure_guest_profile"]["status"], "UNKNOWN")
        self.assertEqual(checks["orka_budget_source"]["status"], "UNKNOWN")
        self.assertEqual(checks["orka_user_data_bootstrap"]["status"], "UNKNOWN")
        self.assertEqual(checks["live_provider_acceptance"]["status"], "SKIPPED")
        self.assertEqual(result["overall"], "UNKNOWN")

    def test_azure_provider_opt_in_requires_all_runtime_configuration(self):
        env = valid_environment()
        env["DCP_AZURE_PROVIDER_ENABLED"] = "true"
        env.pop("DCP_AZURE_WINDOWS_IMAGE_VERSION")
        result = inspect_environment(env)
        checks = {item["check"]: item for item in result["checks"]}
        self.assertEqual(checks["azure_configuration_presence"]["status"], "UNKNOWN")
        self.assertEqual(checks["azure_provider_runtime"]["status"], "FAIL")
        self.assertEqual(result["overall"], "FAIL")

    def test_azure_provider_opt_in_passes_syntax_but_live_gates_stay_unknown(self):
        env = valid_environment()
        env["DCP_AZURE_PROVIDER_ENABLED"] = "true"
        result = inspect_environment(env)
        checks = {item["check"]: item for item in result["checks"]}
        self.assertEqual(checks["azure_provider_runtime"]["status"], "PASS")
        self.assertEqual(checks["azure_network_policy"]["status"], "UNKNOWN")
        self.assertEqual(checks["azure_guest_profile"]["status"], "UNKNOWN")
        self.assertEqual(result["overall"], "UNKNOWN")

    def test_azure_provider_opt_in_requires_managed_identity(self):
        env = valid_environment()
        env["DCP_AZURE_PROVIDER_ENABLED"] = "true"
        env.pop("DCP_AZURE_USE_IMDS")
        result = inspect_environment(env)
        checks = {item["check"]: item for item in result["checks"]}
        self.assertEqual(checks["azure_managed_identity_configuration"]["status"], "FAIL")
        self.assertEqual(checks["azure_provider_runtime"]["status"], "FAIL")
        self.assertEqual(result["overall"], "FAIL")

    def test_azure_provider_rejects_identity_endpoint_userinfo(self):
        env = valid_environment()
        env["DCP_AZURE_PROVIDER_ENABLED"] = "true"
        env.pop("DCP_AZURE_USE_IMDS")
        env["IDENTITY_ENDPOINT"] = "http://user:pass@localhost:1234/identity"
        env["IDENTITY_HEADER"] = "platform-header"
        result = inspect_environment(env)
        checks = {item["check"]: item for item in result["checks"]}
        self.assertEqual(checks["azure_managed_identity_configuration"]["status"], "FAIL")
        self.assertEqual(checks["azure_provider_runtime"]["status"], "FAIL")

    def test_invalid_azure_provider_flag_fails_closed(self):
        env = valid_environment()
        env["DCP_AZURE_PROVIDER_ENABLED"] = "yes"
        result = inspect_environment(env)
        checks = {item["check"]: item for item in result["checks"]}
        self.assertEqual(checks["azure_provider_runtime"]["status"], "FAIL")
        self.assertEqual(result["overall"], "FAIL")

    def test_missing_azure_egress_and_guest_profile_inputs_remain_unknown(self):
        env = valid_environment()
        for name in (
            "DCP_AZURE_EXPECTED_FIREWALL_IP",
            "DCP_AZURE_REQUIRED_OUTBOUND_FLOWS_JSON",
            "DCP_AZURE_LINUX_ADMIN_USERNAME",
            "DCP_AZURE_LINUX_SSH_PUBLIC_KEY_SECRET_NAME",
            "DCP_AZURE_WINDOWS_ADMIN_USERNAME",
            "DCP_AZURE_WINDOWS_ADMIN_PASSWORD_SECRET_NAME",
        ):
            env.pop(name)
        checks = {item["check"]: item for item in inspect_environment(env)["checks"]}
        self.assertEqual(checks["azure_network_policy_configuration"]["status"], "UNKNOWN")
        self.assertEqual(checks["azure_guest_profile_configuration"]["status"], "UNKNOWN")

    def test_invalid_azure_egress_policy_is_rejected_without_echoing_values(self):
        env = valid_environment()
        marker = "DO-NOT-ECHO-FIREWALL"
        env["DCP_AZURE_EXPECTED_FIREWALL_IP"] = marker
        env["DCP_AZURE_REQUIRED_OUTBOUND_FLOWS_JSON"] = (
            '[{"protocol":"Tcp","port":0,"destination":"0.0.0.0/0"}]'
        )
        result = inspect_environment(env)
        checks = {item["check"]: item for item in result["checks"]}
        self.assertEqual(checks["azure_network_policy_configuration"]["status"], "FAIL")
        self.assertNotIn(marker, str(result))
        self.assertEqual(result["overall"], "FAIL")

    def test_invalid_azure_guest_profile_references_are_rejected(self):
        env = valid_environment()
        env["DCP_AZURE_LINUX_ADMIN_USERNAME"] = "root"
        env["DCP_AZURE_WINDOWS_ADMIN_PASSWORD_SECRET_NAME"] = "password_secret"
        result = inspect_environment(env)
        checks = {item["check"]: item for item in result["checks"]}
        self.assertEqual(checks["azure_guest_profile_configuration"]["status"], "FAIL")
        self.assertEqual(result["overall"], "FAIL")

    def test_empty_url_userinfo_fails_origin_validation(self):
        for variable in (
            "DCP_PUBLIC_ORIGIN",
            "DCP_AZURE_KEY_VAULT_URL",
            "DCP_ORKA_URL",
        ):
            env = valid_environment()
            env[variable] = "https://@example.test"
            result = inspect_environment(env)
            checks = {item["check"]: item for item in result["checks"]}
            check_name = {
                "DCP_PUBLIC_ORIGIN": "trusted_proxy",
                "DCP_AZURE_KEY_VAULT_URL": "github_app_configuration",
                "DCP_ORKA_URL": "orka_configuration_presence",
            }[variable]
            self.assertEqual(checks[check_name]["status"], "FAIL", variable)

    def test_enabled_provisioning_is_a_hard_failure_before_live_acceptance(self):
        env = valid_environment()
        env["DCP_GATEWAY_PROVISIONING_ENABLED"] = "true"
        result = inspect_environment(env)
        checks = {item["check"]: item for item in result["checks"]}
        self.assertEqual(checks["provisioning_disabled_by_default"]["status"], "FAIL")
        self.assertEqual(result["overall"], "FAIL")

    def test_invalid_allowlist_and_non_https_origin_do_not_pass(self):
        env = valid_environment()
        env["DCP_GATEWAY_ALLOWED_REPOSITORIES"] = "owner/repo,not-a-repo"
        env["DCP_PUBLIC_ORIGIN"] = "http://dcp.example.test"
        result = inspect_environment(env)
        checks = {item["check"]: item for item in result["checks"]}
        self.assertEqual(checks["repository_allowlist"]["status"], "FAIL")
        self.assertEqual(checks["trusted_proxy"]["status"], "FAIL")
        self.assertEqual(result["overall"], "FAIL")

    def test_invalid_azure_ids_checksums_and_github_app_ids_fail(self):
        env = valid_environment()
        env["DCP_AZURE_SUBNET_ID"] = "/subscriptions/other/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/vnet/subnets/runners"
        env["DCP_RUNNER_LINUX_SHA256"] = "not-a-checksum"
        env["DCP_GITHUB_APP_ID"] = "app-id"
        result = inspect_environment(env)
        checks = {item["check"]: item for item in result["checks"]}
        self.assertEqual(checks["azure_configuration_presence"]["status"], "FAIL")
        self.assertEqual(checks["github_app_configuration"]["status"], "FAIL")
        self.assertEqual(result["overall"], "FAIL")


if __name__ == "__main__":
    unittest.main()
