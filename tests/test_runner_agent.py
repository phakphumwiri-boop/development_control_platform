"""DCP Runner Agent unit tests; no subprocess or network access."""
import unittest
from pathlib import Path
from unittest.mock import Mock

from tools.runner_agent.agent import GatewayClient, GatewayError, RunnerAgent, build_command, package_output


class RunnerAgentTests(unittest.TestCase):
    def test_build_command_allowlist(self):
        self.assertEqual(build_command("build_macos"), ["flutter", "build", "macos", "--release"])
        self.assertIn("--no-codesign", build_command("build_ios"))
        with self.assertRaises(ValueError):
            build_command("arbitrary-shell")

    def test_package_output_archives_expected_directory(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "build/web"
            output.mkdir(parents=True)
            (output / "index.html").write_text("ok")
            archive = package_output(root, "build_web")
            self.assertTrue(archive.is_file())
            import zipfile
            with zipfile.ZipFile(archive) as bundle:
                self.assertEqual(bundle.namelist(), ["web/index.html"])

    def test_runner_agent_target_allowlist(self):
        agent = RunnerAgent(Mock(), "runner-1", ["flutter"])
        self.assertIn("build_ios", agent.client_targets)
        self.assertNotIn("shell", agent.client_targets)

    def test_gateway_client_requires_token(self):
        client = GatewayClient("http://127.0.0.1:8000", "secret")
        self.assertEqual(client.base_url, "http://127.0.0.1:8000")


if __name__ == "__main__":
    unittest.main()
