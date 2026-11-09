"""DCP Runner Agent unit tests; no subprocess or network access."""
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tools.runner_agent.agent import GatewayClient, GatewayError, JobCancelled, RunnerAgent, build_command, package_output


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

    @patch("tools.runner_agent.agent.host_os", return_value="windows")
    def test_macos_job_is_rejected_on_windows_before_checkout(self, _host):
        client = Mock()
        agent = RunnerAgent(client, "windows-runner", ["flutter", "windows"])
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            agent.execute({
                "id": "00000000-0000-4000-8000-000000000001",
                "target": "build_macos", "repository": "owner/repo",
                "commit_sha": "a" * 40,
            })
        client.log.assert_not_called()

    def test_command_runner_uses_no_shell_and_renews_lease(self):
        import sys
        client = Mock()
        agent = RunnerAgent(client, "runner-1", ["flutter"], lease_seconds=15)
        agent._run([sys.executable, "-c", "print('runner-ok')"], Path.cwd(),
                   "00000000-0000-4000-8000-000000000001")
        client.log.assert_called()

    def test_cancellation_after_last_command_prevents_success(self):
        from unittest.mock import patch
        client = Mock()
        client.heartbeat.return_value = {"state": "cancel_requested"}
        agent = RunnerAgent(client, "runner-1", ["flutter"])
        commit = "a" * 40
        with patch("tools.runner_agent.agent.subprocess.check_output", return_value=commit), \
             patch.object(agent, "_run"):
            with self.assertRaises(JobCancelled):
                agent.execute({
                    "id": "00000000-0000-4000-8000-000000000001",
                    "target": "test", "repository": "owner/repo",
                    "commit_sha": commit,
                })
        client.finish.assert_not_called()
        client.upload.assert_not_called()

    @patch("tools.runner_agent.agent.collect_preflight")
    @patch("tools.runner_agent.agent.GatewayClient")
    @patch.dict("os.environ", {
        "DCP_GATEWAY_URL": "http://127.0.0.1:8789",
        "DCP_RUNNER_ID": "windows-enroll-test",
        "DCP_RUNNER_TOKEN": "x" * 40,
    }, clear=True)
    def test_enroll_only_does_not_require_execution_or_claim_jobs(self, client_type, preflight):
        from tools.runner_agent.agent import main
        preflight.return_value = {
            "host_os": "windows",
            "minimum_agent_prerequisites_met": True,
            "detected_capabilities": ["flutter", "web", "windows"],
        }
        client = client_type.return_value
        client.enroll.return_value = {"runner": {
            "worker_id": "windows-enroll-test", "host_os": "windows",
            "capabilities": ["flutter", "web", "windows"], "state": "offline",
        }}

        self.assertEqual(main(["--enroll-only"]), 0)
        client.enroll.assert_called_once_with(
            "windows", ["flutter", "web", "windows"]
        )
        client.register.assert_not_called()
        client.ping.assert_not_called()
        client.claim.assert_not_called()

    @patch("tools.runner_agent.agent.collect_preflight")
    @patch("tools.runner_agent.agent.GatewayClient")
    @patch.dict("os.environ", {
        "DCP_GATEWAY_URL": "http://127.0.0.1:8789",
        "DCP_RUNNER_ID": "windows-enroll-test",
        "DCP_RUNNER_TOKEN": "x" * 40,
        "DCP_RUNNER_CAPABILITIES": "flutter,windows,macos",
    }, clear=True)
    def test_enrollment_rejects_capabilities_not_detected_by_preflight(self, client_type, preflight):
        from tools.runner_agent.agent import main
        preflight.return_value = {
            "host_os": "windows",
            "minimum_agent_prerequisites_met": True,
            "detected_capabilities": ["flutter", "web", "windows"],
        }
        with self.assertRaises(SystemExit):
            main(["--enroll-only"])
        client_type.assert_not_called()

    def test_gateway_client_requires_token(self):
        client = GatewayClient("http://127.0.0.1:8000", "secret")
        self.assertEqual(client.base_url, "http://127.0.0.1:8000")


if __name__ == "__main__":
    unittest.main()
