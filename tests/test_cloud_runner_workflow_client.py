"""Tests proving the DCP workflow client uses the multi-platform gateway contract."""
import unittest
from unittest.mock import patch
from tools.cloud_runner.backend import ProvisionRequest, RunnerSettings, request_provisioning
from tools.runner_backend.manager import PLATFORM_PROFILES
from tools.runner_backend.provider import RunnerInstance

class FakeProvider:
    def __init__(self): self.calls = []
    def provision(self, payload):
        self.calls.append(payload)
        return RunnerInstance("gateway-runner-1", "provisioning", "dcp-runner-1", tuple(payload["labels"]), "accepted")
    def status(self, provider_id): return RunnerInstance(provider_id, "online")
    def terminate(self, provider_id): return RunnerInstance(provider_id, "terminated")

class CloudRunnerWorkflowClientTests(unittest.TestCase):
    def setUp(self):
        self.settings = RunnerSettings(
            "https://gateway.example.test",
            "test-token",
            provisioning_enabled=True,
            owner_approved=True,
        )
        self.repository = "phakphum12345/generated-A4-pdf"
        self.sha = "A" * 40

    def test_each_supported_os_emits_exact_profile_and_security_contract(self):
        for target_os, profile in PLATFORM_PROFILES.items():
            with self.subTest(target_os=target_os):
                fake = FakeProvider()
                with patch("tools.cloud_runner.backend.CloudAPIProvider", return_value=fake):
                    result = request_provisioning(self.settings, ProvisionRequest(self.repository, self.sha, 12345, target_os))
                self.assertEqual(result.state, "provisioning")
                self.assertEqual(fake.calls, [{
                    "repository": self.repository, "workflow_run_id": 12345, "commit_sha": "a" * 40,
                    "target_os": target_os, "image": profile["image"], "labels": list(profile["labels"]),
                    "ephemeral": True, "max_runtime_minutes": 60, "network_policy": "restricted-egress",
                    "registration_token_handling": "provider-side-only",
                }])

    def test_provisioning_is_disabled_without_both_explicit_flags(self):
        request = ProvisionRequest(self.repository, self.sha, 12345)
        disabled = RunnerSettings("https://gateway.example.test", "test-token")
        owner_only = RunnerSettings(
            "https://gateway.example.test", "test-token",
            provisioning_enabled=True,
        )
        enabled_only = RunnerSettings(
            "https://gateway.example.test", "test-token",
            owner_approved=True,
        )
        for settings in (disabled, owner_only, enabled_only):
            with self.subTest(settings=settings), patch(
                "tools.cloud_runner.backend.CloudAPIProvider"
            ) as factory:
                with self.assertRaisesRegex(RuntimeError, "disabled|approval"):
                    request_provisioning(settings, request)
                factory.assert_not_called()

    def test_settings_from_env_default_to_disabled_and_require_explicit_flags(self):
        env = {
            "DCP_RUNNER_PROVIDER_URL": "https://gateway.example.test",
            "DCP_RUNNER_PROVIDER_TOKEN": "test-token",
        }
        settings = RunnerSettings.from_env(env)
        self.assertFalse(settings.provisioning_enabled)
        self.assertFalse(settings.owner_approved)
        env["DCP_CLOUD_RUNNER_PROVISIONING_ENABLED"] = "true"
        env["DCP_CLOUD_RUNNER_OWNER_APPROVED"] = "true"
        settings = RunnerSettings.from_env(env)
        self.assertTrue(settings.provisioning_enabled)
        self.assertTrue(settings.owner_approved)

    def test_unallowlisted_repository_is_rejected_before_provider_creation(self):
        with patch("tools.cloud_runner.backend.CloudAPIProvider") as factory:
            with self.assertRaisesRegex(ValueError, "allowlist"):
                request_provisioning(self.settings, ProvisionRequest("attacker/repo", "a" * 40, 12345, "linux"))
        factory.assert_not_called()

    def test_invalid_sha_run_id_and_os_are_rejected(self):
        for request in (ProvisionRequest(self.repository, "bad", 12345), ProvisionRequest(self.repository, "a"*40, True),
                        ProvisionRequest(self.repository, "a"*40, 0), ProvisionRequest(self.repository, "a"*40, 12345, "freebsd")):
            with self.subTest(request=request), self.assertRaises(ValueError): request.validate(self.settings)

    def test_settings_parse_comma_separated_allowlist(self):
        settings = RunnerSettings.from_env({"DCP_RUNNER_PROVIDER_URL":"https://gateway.example.test",
            "DCP_RUNNER_PROVIDER_TOKEN":"secret", "DCP_RUNNER_ALLOWED_REPOSITORIES":"owner/one, owner/two",
            "DCP_RUNNER_PROVIDER_TIMEOUT":"30"})
        self.assertEqual(settings.allowed_repositories, ("owner/one", "owner/two"))
        self.assertEqual(settings.timeout_seconds, 30)

    def test_settings_reject_unsafe_origins_and_timeouts(self):
        for endpoint in ("http://gateway.example.test", "https://user:pass@gateway.example.test",
                         "https://gateway.example.test/path", "https://gateway.example.test/?token=x",
                         "https://gateway.example.test/#fragment"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError): RunnerSettings(endpoint, "secret")
        with self.assertRaises(ValueError): RunnerSettings("https://gateway.example.test", "secret", timeout_seconds=0)

if __name__ == "__main__": unittest.main()
