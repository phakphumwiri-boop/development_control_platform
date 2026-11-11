"""Mock-only GitHub App runtime composition tests; no cloud or GitHub calls."""
import unittest
from unittest.mock import patch

from tools.cloud_gateway.policy import GatewaySettings
from tools.cloud_gateway import github_app_runtime


class RuntimeCompositionTests(unittest.TestCase):
    def setUp(self):
        self.settings = GatewaySettings(allowed_repositories=("owner/repo",))
        self.env = {
            "DCP_AZURE_KEY_VAULT_URL": "https://example.vault.azure.net",
            "DCP_GITHUB_APP_ID": "12345",
            "DCP_GITHUB_APP_INSTALLATION_ID": "98765",
            "DCP_GITHUB_APP_PRIVATE_KEY_SECRET_NAME": "github-app-private-key",
        }

    def test_missing_configuration_keeps_github_integration_disabled(self):
        self.assertEqual(
            github_app_runtime.build_github_app_runtime(self.settings, {}),
            (None, None, None),
        )

    def test_partial_configuration_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            github_app_runtime.build_github_app_runtime(self.settings, {
                "DCP_GITHUB_APP_ID": "12345",
            })

    def test_private_key_is_read_from_vault_and_not_from_environment(self):
        with patch.object(github_app_runtime, "ManagedIdentityCredential") as credential, \
             patch.object(github_app_runtime, "KeyVaultSecretReader") as reader, \
             patch.object(github_app_runtime, "GitHubAppRunnerBootstrap") as app_type:
            reader.return_value.get_secret.return_value = "PRIVATE-KEY-MATERIAL"
            app, checker, cleanup = github_app_runtime.build_github_app_runtime(
                self.settings, self.env
            )
        credential.assert_called_once_with(env=self.env)
        reader.assert_called_once()
        reader.return_value.get_secret.assert_called_once_with("github-app-private-key")
        app_type.assert_called_once_with("12345", 98765, "PRIVATE-KEY-MATERIAL", ())
        self.assertIs(checker.github_app, app)
        self.assertTrue(callable(cleanup))

    def test_cleanup_requires_installed_offline_runner(self):
        with patch.object(github_app_runtime, "ManagedIdentityCredential"), \
             patch.object(github_app_runtime, "KeyVaultSecretReader") as reader, \
             patch.object(github_app_runtime, "GitHubAppRunnerBootstrap") as app_type:
            reader.return_value.get_secret.return_value = "key"
            app, _, cleanup = github_app_runtime.build_github_app_runtime(self.settings, self.env)
        app.is_repository_accessible.side_effect = lambda repository, refresh=False: repository == "owner/repo"
        app.find_runner.return_value = {"id": 42, "status": "offline"}
        app.remove_runner.return_value = True
        self.assertEqual(cleanup(
            {"repository": "owner/repo", "provider_id": "azure:dcp-1-abcd1234"}, None
        ), "removed")
        app.remove_runner.assert_called_once_with("owner/repo", 42)

    def test_cleanup_refuses_online_and_unallowlisted_runners(self):
        with patch.object(github_app_runtime, "ManagedIdentityCredential"), \
             patch.object(github_app_runtime, "KeyVaultSecretReader") as reader, \
             patch.object(github_app_runtime, "GitHubAppRunnerBootstrap") as app_type:
            reader.return_value.get_secret.return_value = "key"
            app, _, cleanup = github_app_runtime.build_github_app_runtime(self.settings, self.env)
        app.is_repository_accessible.side_effect = lambda repository, refresh=False: repository == "owner/repo"
        app.find_runner.return_value = {"id": 42, "status": "online"}
        with self.assertRaisesRegex(RuntimeError, "not confirmed offline"):
            cleanup({"repository": "owner/repo", "provider_id": "orka:dcp-1-abcd1234"}, None)
        with self.assertRaisesRegex(RuntimeError, "not accessible to the DCP GitHub App installation"):
            cleanup({"repository": "attacker/repo", "provider_id": "dcp-1-abcd1234"}, None)
        app.remove_runner.assert_not_called()


    def test_default_disabled_provider_rejects_all_lifecycle_operations(self):
        from tools.cloud_gateway.server import DisabledProvider

        provider = DisabledProvider()
        operations = (
            lambda: provider.provision({"target_os": "linux"}),
            lambda: provider.status("runner-123"),
            lambda: provider.terminate("runner-123"),
        )
        for operation in operations:
            with self.subTest(operation=operation), self.assertRaisesRegex(
                RuntimeError, "No provider adapter configured"
            ):
                operation()

    def test_gateway_settings_default_to_live_provisioning_disabled(self):
        settings = GatewaySettings()
        self.assertFalse(settings.provisioning_enabled)
        self.assertFalse(settings.owner_approved)


if __name__ == "__main__":
    unittest.main()
