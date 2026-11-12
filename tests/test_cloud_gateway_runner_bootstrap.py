"""Mock-only protected Azure bootstrap payload tests."""
import base64
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from tools.cloud_gateway.runner_bootstrap import AzureRunnerBootstrapFactory, RunnerBootstrapError


class FakeGitHubApp:
    def __init__(self, token="mock-registration-token", expiry_delta=45):
        self.token = token
        self.expiry_delta = expiry_delta
        self.repositories = []

    def create_registration_token(self, repository):
        self.repositories.append(repository)
        return SimpleNamespace(
            token=self.token,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=self.expiry_delta),
        )


def payload(os_name):
    labels = ["self-hosted", "Linux", "X64", "dcp-cloud-linux"] if os_name == "linux" else [
        "self-hosted", "Windows", "X64", "dcp-cloud-windows"
    ]
    return {
        "repository": "phakphum12345/generated-A4-pdf",
        "target_os": os_name,
        "labels": labels,
        "ephemeral": True,
        "network_policy": "restricted-egress",
    }


class AzureRunnerBootstrapTests(unittest.TestCase):
    @staticmethod
    def valid_profile(vm, os_name, request):
        if os_name == "linux":
            return {
                "computerName": vm,
                "adminUsername": "dcpadmin",
                "linuxConfiguration": {
                    "disablePasswordAuthentication": True,
                    "ssh": {"publicKeys": [{
                        "path": "/home/dcpadmin/.ssh/authorized_keys",
                        "keyData": "ssh-ed25519 YWJjZGVmZ2hpamtsbW5vcA== dcp-test",
                    }]},
                },
            }
        return {
            "computerName": "dcpwinrunner01",
            "adminUsername": "dcpadmin",
            "adminPassword": "Test-Only-Password-123!",
        }

    def make(self, app=None, os_profile_factory=None):
        return AzureRunnerBootstrapFactory(
            app or FakeGitHubApp(),
            "2.331.0",
            "a" * 64,
            "b" * 64,
            os_profile_factory or self.valid_profile,
        )

    def test_linux_registration_token_is_only_in_protected_script(self):
        app = FakeGitHubApp()
        result = self.make(app)("dcp-123-abcdef12", "linux", payload("linux"))
        props = result["extension"]["properties"]
        script = base64.b64decode(props["protectedSettings"]["script"]).decode()
        self.assertEqual(props["publisher"], "Microsoft.Azure.Extensions")
        self.assertEqual(props["settings"], {})
        self.assertIn("mock-registration-token", script)
        self.assertIn("sha256sum --check --status", script)
        self.assertIn("--ephemeral --disableupdate", script)
        self.assertNotIn("mock-registration-token", str(props["settings"]))
        self.assertEqual(app.repositories, ["phakphum12345/generated-A4-pdf"])

    def test_windows_token_is_only_in_encoded_protected_command(self):
        app = FakeGitHubApp()
        result = self.make(app)("dcp-123-abcdef12", "windows", payload("windows"))
        props = result["extension"]["properties"]
        command = props["protectedSettings"]["commandToExecute"]
        encoded = command.rsplit(" ", 1)[1]
        script = base64.b64decode(encoded).decode("utf-16le")
        self.assertEqual(props["publisher"], "Microsoft.Compute")
        self.assertEqual(props["settings"], {})
        self.assertIn("mock-registration-token", script)
        self.assertIn("Get-FileHash -Algorithm SHA256", script)
        self.assertIn("--ephemeral --disableupdate", script)
        self.assertIn("NT AUTHORITY\\NETWORK SERVICE", script)
        self.assertIn("schtasks.exe /Create", script)
        self.assertNotIn("svc.cmd install", script)
        self.assertNotIn("mock-registration-token", str(props["settings"]))

    def test_rejects_unpinned_runner_artifacts(self):
        with self.assertRaises(ValueError):
            AzureRunnerBootstrapFactory(FakeGitHubApp(), "latest", "a" * 64, "b" * 64, lambda *_: {})
        with self.assertRaises(ValueError):
            AzureRunnerBootstrapFactory(FakeGitHubApp(), "2.331.0", "bad", "b" * 64, lambda *_: {})

    def test_rejects_invalid_profile_before_minting_token(self):
        app = FakeGitHubApp()
        with self.assertRaises(RunnerBootstrapError):
            self.make(app)("dcp-123-abcdef12", "macos", payload("macos"))
        self.assertEqual(app.repositories, [])

    def test_rejects_unrestricted_or_non_ephemeral_request(self):
        app = FakeGitHubApp()
        bad = payload("linux")
        bad["network_policy"] = "public"
        with self.assertRaises(RunnerBootstrapError):
            self.make(app)("dcp-123-abcdef12", "linux", bad)
        self.assertEqual(app.repositories, [])

    def test_rejects_incomplete_linux_guest_login_before_minting_token(self):
        app = FakeGitHubApp()
        factory = self.make(app, lambda vm, os_name, request: {
            "computerName": vm, "adminUsername": "dcpadmin"
        })
        with self.assertRaises(RunnerBootstrapError):
            factory("dcp-123-abcdef12", "linux", payload("linux"))
        self.assertEqual(app.repositories, [])

    def test_rejects_linux_password_authentication_and_wrong_ssh_path(self):
        profile = self.valid_profile("dcp-123-abcdef12", "linux", payload("linux"))
        profile["linuxConfiguration"]["disablePasswordAuthentication"] = False
        with self.assertRaises(RunnerBootstrapError):
            self.make(os_profile_factory=lambda *_: profile)(
                "dcp-123-abcdef12", "linux", payload("linux")
            )
        profile = self.valid_profile("dcp-123-abcdef12", "linux", payload("linux"))
        profile["linuxConfiguration"]["ssh"]["publicKeys"][0]["path"] = "/root/.ssh/authorized_keys"
        with self.assertRaises(RunnerBootstrapError):
            self.make(os_profile_factory=lambda *_: profile)(
                "dcp-123-abcdef12", "linux", payload("linux")
            )

    def test_rejects_weak_windows_guest_password_before_minting_token(self):
        app = FakeGitHubApp()
        profile = self.valid_profile("dcp-123-abcdef12", "windows", payload("windows"))
        profile["adminPassword"] = "weak"
        with self.assertRaises(RunnerBootstrapError):
            self.make(app, lambda *_: profile)(
                "dcp-123-abcdef12", "windows", payload("windows")
            )
        self.assertEqual(app.repositories, [])

    def test_rejects_windows_computer_name_over_azure_limit(self):
        profile = self.valid_profile("dcp-123-abcdef12", "windows", payload("windows"))
        profile["computerName"] = "dcp-123-abcdef12"
        with self.assertRaises(RunnerBootstrapError):
            self.make(os_profile_factory=lambda *_: profile)(
                "dcp-123-abcdef12", "windows", payload("windows")
            )

    def test_rejects_invalid_registration_token(self):
        with self.assertRaises(RunnerBootstrapError):
            self.make(FakeGitHubApp("bad token"))("dcp-123-abcdef12", "linux", payload("linux"))


if __name__ == "__main__":
    unittest.main()
