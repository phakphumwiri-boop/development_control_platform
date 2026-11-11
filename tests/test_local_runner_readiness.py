"""Local Runner CLI must enforce read-only host readiness before job claims."""
import json
import unittest
from unittest.mock import patch

from tools.local_runner_agent import __main__ as runner_cli


TOKEN = "local-runner-test-token-that-is-at-least-32-bytes-long"


class LocalRunnerReadinessTests(unittest.TestCase):
    def _environment(self, **extra):
        values = {
            "DCP_GATEWAY_URL": "http://127.0.0.1:8789",
            "DCP_RUNNER_WORKER_ID": "windows-android-runner",
            "DCP_RUNNER_TOKEN": TOKEN,
            "DCP_RUNNER_EXECUTION_ENABLED": "1",
            "DCP_RUNNER_WORKSPACE_ROOT": "C:/DCP/workspaces",
            "DCP_RUNNER_TRUSTED_REPOSITORIES": '["owner/repo"]',
        }
        values.update(extra)
        return values

    @patch("tools.local_runner_agent.__main__.platform.system", return_value="Windows")
    @patch("tools.local_runner_agent.__main__.FlutterBuildExecutor")
    @patch("tools.local_runner_agent.__main__.GitHubCommitCheckout")
    @patch("tools.local_runner_agent.__main__.WorkspaceManager")
    @patch("tools.local_runner_agent.__main__.RunnerPipeline")
    @patch("tools.local_runner_agent.__main__.GatewayClient")
    @patch("tools.local_runner_agent.__main__.collect_preflight")
    @patch.dict("os.environ", {}, clear=True)
    def test_windows_without_visual_studio_can_claim_only_detected_android_and_web(
        self, preflight, client_type, pipeline_type, workspace_type,
        checkout_type, executor_type, _system
    ):
        import os
        os.environ.update(self._environment())
        preflight.return_value = {
            "host_os": "windows",
            "minimum_agent_prerequisites_met": True,
            "detected_capabilities": ["flutter", "android", "web"],
        }
        client_type.return_value.health.return_value = {"status": "ok"}
        pipeline_type.return_value.run_once.return_value = {
            "outcome": "succeeded", "job": {"id": "job-1"}
        }

        self.assertEqual(runner_cli.main(["--once"]), 0)
        kwargs = pipeline_type.call_args.kwargs
        self.assertEqual(kwargs["worker_os"], "windows")
        self.assertEqual(kwargs["capabilities"], frozenset({"flutter", "android", "web"}))
        self.assertNotIn("windows", kwargs["capabilities"])
        pipeline_type.return_value.run_once.assert_called_once()

    @patch("tools.local_runner_agent.__main__.platform.system", return_value="Windows")
    @patch("tools.local_runner_agent.__main__.RunnerPipeline")
    @patch("tools.local_runner_agent.__main__.GatewayClient")
    @patch("tools.local_runner_agent.__main__.collect_preflight")
    @patch.dict("os.environ", {}, clear=True)
    def test_rejects_configured_capability_not_detected_before_claiming(
        self, preflight, client_type, pipeline_type, _system
    ):
        import os
        os.environ.update(self._environment(
            DCP_RUNNER_CAPABILITIES='["flutter","windows"]'
        ))
        preflight.return_value = {
            "host_os": "windows",
            "minimum_agent_prerequisites_met": True,
            "detected_capabilities": ["flutter", "android", "web"],
        }
        client_type.return_value.health.return_value = {"status": "ok"}

        self.assertEqual(runner_cli.main(["--once"]), 1)
        pipeline_type.assert_not_called()


if __name__ == "__main__":
    unittest.main()
