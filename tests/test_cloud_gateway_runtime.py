"""Mock-only GitHub App runtime composition tests; no cloud or GitHub calls."""
import unittest
from unittest.mock import patch

from tools.cloud_gateway.policy import GatewaySettings
from tools.cloud_gateway import github_app_runtime
from tools.cloud_gateway.runner_cleanup import GitHubRunnerCleanup
from tools.cloud_gateway.provider_router import ProviderRouter
from tools.cloud_gateway.server import DisabledProvider, _provider_router_from_env
from tools.runner_backend.provider import RunnerInstance


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

    def test_cleanup_requires_installed_offline_runner_and_confirms_absence(self):
        with patch.object(github_app_runtime, "ManagedIdentityCredential"), \
             patch.object(github_app_runtime, "KeyVaultSecretReader") as reader, \
             patch.object(github_app_runtime, "GitHubAppRunnerBootstrap") as app_type:
            reader.return_value.get_secret.return_value = "key"
            app, _, cleanup = github_app_runtime.build_github_app_runtime(self.settings, self.env)
        self.assertIsInstance(cleanup, GitHubRunnerCleanup)
        app.is_repository_accessible.side_effect = lambda repository, refresh=False: repository == "owner/repo"
        runner = {"id": 42, "status": "offline"}
        app.find_runner.side_effect = [runner, None]
        app.remove_runner.return_value = True
        self.assertEqual(cleanup(
            {"repository": "owner/repo", "provider_id": "azure:dcp-1-abcd1234"},
            RunnerInstance("azure:dcp-1-abcd1234", "terminated"),
        ), "removed")
        app.remove_runner.assert_called_once_with("owner/repo", 42)
        self.assertEqual(app.find_runner.call_count, 2)
        self.assertEqual(app.find_runner.call_args_list[0].args, ("owner/repo", "dcp-1-abcd1234"))
        self.assertEqual(app.find_runner.call_args_list[1].args, ("owner/repo", "dcp-1-abcd1234"))

    def test_cleanup_refuses_online_and_unallowlisted_runners(self):
        with patch.object(github_app_runtime, "ManagedIdentityCredential"), \
             patch.object(github_app_runtime, "KeyVaultSecretReader") as reader, \
             patch.object(github_app_runtime, "GitHubAppRunnerBootstrap") as app_type:
            reader.return_value.get_secret.return_value = "key"
            app, _, cleanup = github_app_runtime.build_github_app_runtime(self.settings, self.env)
        app.is_repository_accessible.side_effect = lambda repository, refresh=False: repository == "owner/repo"
        app.find_runner.return_value = {"id": 42, "status": "online"}
        terminal = RunnerInstance("dcp-1-abcd1234", "terminated")
        with self.assertRaisesRegex(RuntimeError, "not confirmed offline"):
            cleanup({"repository": "owner/repo", "provider_id": "orka:dcp-1-abcd1234"}, terminal)
        with self.assertRaisesRegex(RuntimeError, "not accessible to the DCP GitHub App installation"):
            cleanup({"repository": "attacker/repo", "provider_id": "dcp-1-abcd1234"}, terminal)
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

    def test_server_keeps_azure_and_orka_disabled_by_default(self):
        router = _provider_router_from_env({}, None, None)
        self.assertIsInstance(router, ProviderRouter)
        self.assertIsInstance(router.providers["azure"], DisabledProvider)
        self.assertIsInstance(router.providers["orka"], DisabledProvider)

    def test_server_composes_only_explicitly_enabled_azure_adapter(self):
        azure = object()
        with patch("tools.cloud_gateway.server.build_azure_provider_from_env", return_value=azure) as factory:
            router = _provider_router_from_env(
                {"DCP_AZURE_PROVIDER_ENABLED": "true"},
                object(),
                lambda *args: True,
            )
        factory.assert_called_once()
        self.assertIs(router.providers["azure"], azure)
        self.assertIsInstance(router.providers["orka"], DisabledProvider)

    def test_server_fails_startup_when_enabled_azure_configuration_is_invalid(self):
        from tools.cloud_gateway.azure_runtime import AzureRuntimeConfigurationError
        with patch(
            "tools.cloud_gateway.server.build_azure_provider_from_env",
            side_effect=AzureRuntimeConfigurationError("missing config"),
        ):
            with self.assertRaisesRegex(SystemExit, "missing config"):
                _provider_router_from_env({"DCP_AZURE_PROVIDER_ENABLED": "true"}, object(), lambda *args: True)

    def test_gateway_settings_default_to_live_provisioning_disabled(self):
        settings = GatewaySettings()
        self.assertFalse(settings.provisioning_enabled)
        self.assertFalse(settings.owner_approved)


if __name__ == "__main__":
    unittest.main()
