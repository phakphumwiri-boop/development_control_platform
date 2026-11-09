"""Read-only Runner host preflight tests; never contact a Gateway."""
import unittest
from unittest.mock import patch

from tools.runner_agent import preflight


class RunnerPreflightTests(unittest.TestCase):
    @patch("tools.runner_agent.preflight.platform.system", return_value="Linux")
    @patch("tools.runner_agent.preflight.platform.python_version", return_value="3.12.0")
    @patch("tools.runner_agent.preflight.shutil.which")
    @patch("tools.runner_agent.preflight.subprocess.run")
    def test_linux_capabilities_require_complete_platform_toolchain(
        self, run, which, _python, _system
    ):
        which.side_effect = lambda name: f"/usr/bin/{name}" if name in {
            "git", "flutter", "clang", "cmake", "ninja"
        } else None
        run.return_value.stdout = "tool version"
        run.return_value.stderr = ""
        with patch.dict("os.environ", {}, clear=True):
            report = preflight.collect_preflight()
        self.assertEqual(report["host_os"], "linux")
        self.assertIn("linux", report["detected_capabilities"])
        self.assertIn("web", report["detected_capabilities"])
        self.assertNotIn("android", report["detected_capabilities"])
        self.assertTrue(report["minimum_agent_prerequisites_met"])
        self.assertFalse(report["execution_enabled"])
        self.assertFalse(report["gateway_contacted"])

    @patch("tools.runner_agent.preflight.platform.system", return_value="Darwin")
    @patch("tools.runner_agent.preflight.shutil.which")
    @patch("tools.runner_agent.preflight.subprocess.run")
    def test_macos_ios_requires_xcode_and_flutter_git(self, run, which, _system):
        which.side_effect = lambda name: f"/usr/bin/{name}" if name in {
            "git", "flutter", "xcodebuild", "xcrun"
        } else None
        run.return_value.stdout = "version"
        run.return_value.stderr = ""
        report = preflight.collect_preflight()
        self.assertIn("macos", report["detected_capabilities"])
        self.assertIn("ios", report["detected_capabilities"])

    @patch("tools.runner_agent.preflight.platform.system", return_value="Windows")
    @patch("tools.runner_agent.preflight.shutil.which")
    @patch("tools.runner_agent.preflight._visual_studio", return_value={"installed": False, "version": None})
    def test_missing_flutter_is_reported_without_claiming_prerequisites(self, _vs, which, _system):
        which.side_effect = lambda name: "C:/git.exe" if name == "git" else None
        report = preflight.collect_preflight()
        self.assertFalse(report["minimum_agent_prerequisites_met"])
        self.assertEqual(report["missing_required_tools"], ["flutter"])
        self.assertNotIn("windows", report["detected_capabilities"])
        self.assertFalse(report["execution_enabled"])

    @patch("tools.runner_agent.preflight.subprocess.run")
    @patch("tools.runner_agent.preflight.shutil.which", return_value="C:/flutter/bin/flutter.bat")
    def test_tool_version_probe_uses_utf8_replacement_decoding(self, _which, run):
        run.return_value.stdout = "Flutter 3.44.4"
        run.return_value.stderr = ""
        report = preflight._tool("flutter")
        self.assertTrue(report["installed"])
        self.assertEqual(report["version"], "Flutter 3.44.4")
        self.assertEqual(run.call_args.kwargs["encoding"], "utf-8")
        self.assertEqual(run.call_args.kwargs["errors"], "replace")


if __name__ == "__main__":
    unittest.main()
