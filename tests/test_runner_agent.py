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
    @patch("tools.runner_agent.agent.host_os", return_value="windows")
    @patch.dict("os.environ", {
        "DCP_GATEWAY_URL": "http://127.0.0.1:8789",
        "DCP_RUNNER_ID": "windows-enroll-test",
        "DCP_RUNNER_TOKEN": "x" * 40,
    }, clear=True)
    def test_enroll_only_does_not_require_execution_or_claim_jobs(self, _host, client_type, preflight):
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
    @patch("tools.runner_agent.agent.host_os", return_value="windows")
    @patch.dict("os.environ", {
        "DCP_GATEWAY_URL": "http://127.0.0.1:8789",
        "DCP_RUNNER_ID": "windows-enroll-test",
        "DCP_RUNNER_TOKEN": "x" * 40,
        "DCP_RUNNER_CAPABILITIES": "flutter,windows,macos",
    }, clear=True)
    def test_enrollment_rejects_capabilities_not_detected_by_preflight(self, _host, client_type, preflight):
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
        client = GatewayClient("http://127.0.0.1:8000", "x" * 40)
        self.assertEqual(client.base_url, "http://127.0.0.1:8000")

    def test_gateway_client_rejects_lookalike_loopback_host_and_url_paths(self):
        token = "x" * 40
        for url in (
            "http://127.0.0.1.evil.example:8789",
            "http://127.0.0.2:8789",
            "https://example.com/api",
            "https://user:pass@example.com",
            "https://example.com/?redirect=evil",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    GatewayClient(url, token)

    def test_runner_agent_rejects_untrusted_repository_before_checkout(self):
        client = Mock()
        agent = RunnerAgent(client, "runner-1", ["flutter"])
        with self.assertRaisesRegex(RuntimeError, "trusted-repository"):
            agent.execute({
                "id": "00000000-0000-4000-8000-000000000001",
                "target": "test", "repository": "owner/repo",
                "commit_sha": "a" * 40,
            })
        client.log.assert_not_called()

    def test_runner_agent_requires_target_capability_before_checkout(self):
        client = Mock()
        agent = RunnerAgent(
            client, "runner-1", ["flutter"],
            trusted_repositories={"owner/repo"},
        )
        with self.assertRaisesRegex(RuntimeError, "required build capabilities"):
            agent.execute({
                "id": "00000000-0000-4000-8000-000000000001",
                "target": "build_android", "repository": "owner/repo",
                "commit_sha": "a" * 40,
            })
        client.log.assert_not_called()

    def test_build_subprocess_does_not_inherit_runner_or_github_tokens(self):
        import io
        import os
        import sys
        client = Mock()
        agent = RunnerAgent(client, "runner-1", ["flutter"])
        process = Mock()
        process.stdout = io.StringIO("runner-safe-output\\n")
        process.returncode = 0
        process.poll.return_value = 0
        with patch.dict(os.environ, {
            "DCP_RUNNER_TOKEN": "runner-secret-value",
            "DCP_GITHUB_TOKEN": "github-secret-value",
            "GITHUB_TOKEN": "github-token-value",
        }):
            with patch("tools.runner_agent.agent.subprocess.Popen", return_value=process) as popen:
                agent._run([sys.executable, "-c", "pass"], Path.cwd(),
                           "00000000-0000-4000-8000-000000000001")
        child_env = popen.call_args.kwargs["env"]
        self.assertNotIn("DCP_RUNNER_TOKEN", child_env)
        self.assertNotIn("DCP_GITHUB_TOKEN", child_env)
        self.assertNotIn("GITHUB_TOKEN", child_env)
        self.assertEqual(popen.call_args.kwargs["shell"], False)

    def test_package_output_rejects_symlink_artifact(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "build" / "web"
            output.mkdir(parents=True)
            target = root / "outside.txt"
            target.write_text("outside")
            link = output / "index.html"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation is not available on this host")
            with self.assertRaisesRegex(RuntimeError, "non-regular"):
                package_output(root, "build_web")


if __name__ == "__main__":
    unittest.main()
