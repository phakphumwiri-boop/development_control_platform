"""Opt-in Azure provider composition tests; all dependencies are mocked."""
import unittest
from unittest.mock import MagicMock, patch

from tools.cloud_gateway import azure_runtime


SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"


def valid_environment():
    return {
        "DCP_AZURE_PROVIDER_ENABLED": "true",
        "DCP_AZURE_USE_IMDS": "true",
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
        "DCP_AZURE_KEY_VAULT_URL": "https://dcp-vault.vault.azure.net",
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
    }


class AzureRuntimeTests(unittest.TestCase):
    def patches(self):
        return (
            patch.object(azure_runtime, "ManagedIdentityCredential"),
            patch.object(azure_runtime, "AzureArmClient"),
            patch.object(azure_runtime, "KeyVaultSecretReader"),
            patch.object(azure_runtime, "AzureRunnerBootstrapFactory"),
            patch.object(azure_runtime, "AzureEffectiveNetworkPolicyVerifier"),
            patch.object(azure_runtime, "AzureVMProvider"),
        )

    def test_provider_is_disabled_by_default_without_constructing_dependencies(self):
        with self.patches()[0] as credential:
            self.assertIsNone(azure_runtime.build_azure_provider_from_env({}, None, None))
        credential.assert_not_called()

    def test_invalid_provider_flag_fails_closed(self):
        env = valid_environment()
        env["DCP_AZURE_PROVIDER_ENABLED"] = "yes"
        with self.assertRaisesRegex(azure_runtime.AzureRuntimeConfigurationError, "must be true or false"):
            azure_runtime.build_azure_provider_from_env(env, object(), lambda *args: True)

    def test_opt_in_requires_github_app_and_online_checker(self):
        env = valid_environment()
        with self.assertRaisesRegex(azure_runtime.AzureRuntimeConfigurationError, "GitHub App"):
            azure_runtime.build_azure_provider_from_env(env, None, lambda *args: True)
        with self.assertRaisesRegex(azure_runtime.AzureRuntimeConfigurationError, "GitHub App"):
            azure_runtime.build_azure_provider_from_env(env, object(), None)

    def test_opt_in_requires_a_trusted_managed_identity_mode(self):
        env = valid_environment()
        env.pop("DCP_AZURE_USE_IMDS")
        with self.assertRaisesRegex(azure_runtime.AzureRuntimeConfigurationError, "managed identity"):
            azure_runtime.build_azure_provider_from_env(env, object(), lambda *args: True)

    def test_opt_in_rejects_public_firewall_and_unbounded_outbound_flow(self):
        env = valid_environment()
        env["DCP_AZURE_EXPECTED_FIREWALL_IP"] = "8.8.8.8"
        with self.assertRaisesRegex(azure_runtime.AzureRuntimeConfigurationError, "private IPv4"):
            azure_runtime.build_azure_provider_from_env(env, object(), lambda *args: True)

        env = valid_environment()
        env["DCP_AZURE_REQUIRED_OUTBOUND_FLOWS_JSON"] = (
            '[{"protocol":"Tcp","port":443,"destination":"0.0.0.0/0"}]'
        )
        with self.assertRaisesRegex(azure_runtime.AzureRuntimeConfigurationError, "bounded IPv4 CIDR"):
            azure_runtime.build_azure_provider_from_env(env, object(), lambda *args: True)

    def test_opt_in_rejects_identity_endpoint_userinfo(self):
        env = valid_environment()
        env.pop("DCP_AZURE_USE_IMDS")
        env["IDENTITY_ENDPOINT"] = "http://user:pass@localhost:1234/identity"
        env["IDENTITY_HEADER"] = "platform-header"
        with self.assertRaisesRegex(azure_runtime.AzureRuntimeConfigurationError, "managed identity"):
            azure_runtime.build_azure_provider_from_env(env, object(), lambda *args: True)

    def test_opt_in_rejects_invalid_budget_projection(self):
        env = valid_environment()
        env["DCP_AZURE_PROJECTED_RUN_COST_USD"] = "inf"
        with self.assertRaisesRegex(azure_runtime.AzureRuntimeConfigurationError, "finite and positive"):
            azure_runtime.build_azure_provider_from_env(env, object(), lambda *args: True)

    def test_incomplete_configuration_fails_before_constructing_dependencies(self):
        env = valid_environment()
        env.pop("DCP_AZURE_WINDOWS_IMAGE_VERSION")
        with self.patches()[0] as credential:
            with self.assertRaisesRegex(azure_runtime.AzureRuntimeConfigurationError, "incomplete"):
                azure_runtime.build_azure_provider_from_env(env, object(), lambda *args: True)
        credential.assert_not_called()

    def test_provider_is_composed_without_cloud_io_and_guest_secrets_are_lazy(self):
        env = valid_environment()
        github_app = object()
        online_checker = lambda *args: True
        with (
            patch.object(azure_runtime, "ManagedIdentityCredential") as credential_type,
            patch.object(azure_runtime, "AzureArmClient") as arm_type,
            patch.object(azure_runtime, "KeyVaultSecretReader") as secret_type,
            patch.object(azure_runtime, "AzureRunnerBootstrapFactory") as bootstrap_type,
            patch.object(azure_runtime, "AzureEffectiveNetworkPolicyVerifier") as network_type,
            patch.object(azure_runtime, "AzureVMProvider") as provider_type,
        ):
            credential = credential_type.return_value
            arm = arm_type.return_value
            secret_reader = secret_type.return_value
            provider = provider_type.return_value
            secret_reader.get_secret.side_effect = [
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly",
                "Windows-Test-Only-Password-123!",
            ]

            result = azure_runtime.build_azure_provider_from_env(
                env, github_app, online_checker
            )

            self.assertIs(result, provider)
            credential_type.assert_called_once_with(env=env)
            arm_type.assert_called_once_with(SUBSCRIPTION, "dcp-runners", credential)
            secret_type.assert_called_once_with("https://dcp-vault.vault.azure.net", credential)
            secret_reader.get_secret.assert_not_called()
            bootstrap_type.assert_called_once()
            network_type.assert_called_once_with(
                arm, env["DCP_AZURE_NSG_ID"],
                [{"protocol": "Tcp", "port": 443, "destination": "198.51.100.0/24"}],
                "10.20.0.4",
            )
            provider_type.assert_called_once()

            os_profile_factory = bootstrap_type.call_args.args[4]
            linux = os_profile_factory("dcp-123-abcd1234", "linux", {})
            windows = os_profile_factory("dcp-123-abcd1234", "windows", {})
            self.assertEqual(linux["computerName"], "dcp-123-abcd1234")
            self.assertTrue(linux["linuxConfiguration"]["disablePasswordAuthentication"])
            self.assertEqual(
                linux["linuxConfiguration"]["ssh"]["publicKeys"][0]["keyData"],
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnly",
            )
            self.assertEqual(
                linux["linuxConfiguration"]["ssh"]["publicKeys"][0]["path"],
                "/home/dcplinux/.ssh/authorized_keys",
            )
            self.assertEqual(windows["computerName"], "DCPWABCD1234")
            self.assertLessEqual(len(windows["computerName"]), 15)
            self.assertEqual(windows["adminUsername"], "dcpwindows")
            self.assertEqual(windows["adminPassword"], "Windows-Test-Only-Password-123!")
            self.assertEqual(secret_reader.get_secret.call_count, 2)
            provider_type.assert_called_once_with(
                arm=arm,
                location="eastus",
                subnet_id=env["DCP_AZURE_SUBNET_ID"],
                nsg_id=env["DCP_AZURE_NSG_ID"],
                vm_sizes={"linux": "Standard_D2s_v5", "windows": "Standard_D4s_v5"},
                image_references={
                    "linux": {
                        "publisher": "Canonical", "offer": "ubuntu-24_04-lts",
                        "sku": "server", "version": "24.04.202501150",
                    },
                    "windows": {
                        "publisher": "MicrosoftWindowsServer", "offer": "WindowsServer",
                        "sku": "2025-datacenter-g2", "version": "20348.1.250101",
                    },
                },
                bootstrap_factory=bootstrap_type.return_value,
                runner_online_checker=online_checker,
                network_policy_checker=network_type.return_value,
            )


if __name__ == "__main__":
    unittest.main()
