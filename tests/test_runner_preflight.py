"""Read-only Runner host preflight tests; never contact a Gateway."""
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from tools.runner_agent import preflight


class RunnerPreflightTests(unittest.TestCase):
    def test_windows_host_without_visual_studio_keeps_android_and_web_capabilities(self):
        report = {
            "host_os": "windows",
            "minimum_agent_prerequisites_met": True,
            "detected_capabilities": ["flutter", "web", "android"],
        }
        self.assertEqual(
            preflight.resolve_capabilities(report),
            ["android", "flutter", "web"],
        )
        self.assertEqual(
            preflight.resolve_capabilities(report, ["android", "flutter"]),
            ["android", "flutter"],
        )
        with self.assertRaisesRegex(ValueError, "subset"):
            preflight.resolve_capabilities(report, ["flutter", "windows"])

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

    @patch("tools.runner_agent.preflight.platform.system", return_value="Windows")
    @patch("tools.runner_agent.preflight._visual_studio", return_value={"installed": False, "version": None})
    @patch("tools.runner_agent.preflight.shutil.which")
    @patch("tools.runner_agent.preflight.subprocess.run")
    def test_android_sdk_and_adb_are_discovered_from_default_windows_sdk_path(self, run, which, _vs, _system):
        with tempfile.TemporaryDirectory() as temp_dir:
            sdk = Path(temp_dir) / "Android" / "Sdk"
            adb = sdk / "platform-tools" / "adb.exe"
            adb.parent.mkdir(parents=True)
            adb.write_text("", encoding="utf-8")
            which.side_effect = lambda name: f"C:/{name}.exe" if name in {"git", "flutter", "java"} else None
            run.return_value.stdout = "Android Debug Bridge version 1.0.41"
            run.return_value.stderr = ""
            with patch.dict("os.environ", {"LOCALAPPDATA": temp_dir}, clear=True):
                report = preflight.collect_preflight()
        self.assertTrue(report["tools"]["android_sdk"]["installed"])
        self.assertTrue(report["tools"]["adb"]["installed"])
        self.assertIn("android", report["detected_capabilities"])

    @patch("tools.runner_agent.preflight.platform.system", return_value="Windows")
    @patch("tools.runner_agent.preflight._visual_studio", return_value={"installed": False, "version": None})
    @patch("tools.runner_agent.preflight.shutil.which")
    def test_android_sdk_without_adb_is_not_reported_as_android_ready(self, which, _vs, _system):
        which.side_effect = lambda name: f"C:/{name}.exe" if name in {"git", "flutter", "java"} else None
        with tempfile.TemporaryDirectory() as temp_dir:
            sdk = Path(temp_dir) / "Android" / "Sdk"
            sdk.mkdir(parents=True)
            with patch.dict("os.environ", {"LOCALAPPDATA": temp_dir}, clear=True):
                report = preflight.collect_preflight()
        self.assertTrue(report["tools"]["android_sdk"]["installed"])
        self.assertFalse(report["tools"]["adb"]["installed"])
        self.assertNotIn("android", report["detected_capabilities"])


if __name__ == "__main__":
    unittest.main()
