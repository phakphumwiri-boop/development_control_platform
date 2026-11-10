"""Contract tests for the guarded Cloud Runner dashboard view."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")


class CloudRunnerDashboardContractTests(unittest.TestCase):
    def test_user_controls_and_platform_choices_exist(self):
        for expected in (
            'data-tab="cloud-runners"', 'id="cloud-runners"',
            'id="runner-refresh"', 'id="runner-create"', 'id="runner-list"',
            'id="runner-gate-budget"', 'data-runner-os="linux"',
            'data-runner-os="windows"', 'data-runner-os="macos"',
            'id="runner-workflow-id"', 'id="runner-commit-sha"',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, HTML)

    def test_start_is_disabled_until_server_side_gates_pass(self):
        for expected in (
            'disabled>Start ephemeral runner', 'function runnerCanCreate()',
            '(s.provider_budget_gates||{})[runnerUI.os]', 'budgetGate==="PASS"',
            's.owner_approved===true',
            's.bootstrap_ready===true', 'p.ready===true',
            'credentials:"same-origin"', '"X-CSRF-Token"',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, HTML)

    def test_no_gateway_or_registration_token_is_embedded(self):
        self.assertIn("registration_token_handling:\"provider-side-only\"", HTML)
        self.assertIn("Gateway credential", HTML)
        self.assertNotIn("DCP_GATEWAY_API_TOKEN", HTML)
        self.assertNotIn("DCP_TRUSTED_PROXY_HMAC_SECRET", HTML)
        self.assertIn("./api/cloud-runners/status", HTML)

    def test_offline_enrolled_runner_cannot_be_enabled_from_dashboard(self):
        self.assertIn('worker.state==="draining"&&worker.can_enable===true', HTML)
        self.assertIn('worker.state==="online"?"drain"', HTML)
        self.assertIn('Agent heartbeat required', HTML)
        self.assertIn('data-local-runner-action]:not(:disabled)', HTML)


if __name__ == "__main__":
    unittest.main()
