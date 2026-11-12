"""Mock-only end-to-end acceptance for the protected Cloud Runner control path."""
import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from tools.cloud_gateway.budget_guard import AzureBudgetGuard
from tools.cloud_gateway.runner_cleanup import GitHubRunnerCleanup
from tools.cloud_gateway.policy import GatewaySettings
from tools.cloud_gateway.server import make_handler
from tools.cloud_gateway.service import GatewayService
from tools.cloud_gateway.store import RunnerStore
from tools.cloud_gateway.oidc_assertion import sign_verified_oidc_assertion
from tools.runner_backend.provider import RunnerInstance


REPOSITORY = "phakphum12345/generated-A4-pdf"
ORIGIN = "https://dcp.example.test"
ISSUER = "https://identity.example.test/"
AUDIENCE = "dcp-web"
SECRET = "end-to-end-test-hmac-secret-32-bytes-minimum"


def request_payload():
    return {
        "repository": REPOSITORY,
        "workflow_run_id": 12345,
        "commit_sha": "a" * 40,
        "target_os": "linux",
        "image": "ubuntu-24.04-x64",
        "labels": ["self-hosted", "Linux", "X64", "dcp-cloud-linux"],
        "ephemeral": True,
        "max_runtime_minutes": 30,
        "network_policy": "restricted-egress",
        "registration_token_handling": "provider-side-only",
    }


class FakeBudgetSnapshot:
    currency = "USD"
    current_spend = 10.0
    forecast_spend = 25.0
    amount = 100.0

    def permits(self, projected):
        return projected >= 0 and self.forecast_spend + projected <= self.amount


class FakeBudgetReader:
    def read(self):
        return FakeBudgetSnapshot()


class FakeGitHubApp:
    def __init__(self):
        self.runner = None
        self.removals = []

    def is_repository_accessible(self, repository, refresh=False):
        return repository == REPOSITORY

    def find_runner(self, repository, runner_name):
        if self.runner and self.runner["name"] == runner_name:
            return dict(self.runner)
        return None

    def remove_runner(self, repository, runner_id):
        self.removals.append((repository, runner_id))
        if self.runner and self.runner["id"] == runner_id:
            self.runner = None
        return True


class FakeProvider:
    requires_budget_guard = True
    requires_runner_cleanup = True

    def __init__(self, github):
        self.github = github
        self.state = "provisioning"
        self.runner_name = None
        self.labels = ()

    def budget_provider_for_os(self, os_name):
        return "orka" if os_name == "macos" else "azure"

    def readiness(self, os_name):
        return {"ready": os_name in ("linux", "macos"), "message": "mock provider ready"}

    def provision(self, payload):
        self.runner_name = "dcp-12345-abcdef12"
        self.labels = tuple(payload["labels"])
        self.state = "online"
        self.github.runner = {
            "id": 77,
            "name": self.runner_name,
            "status": "online",
            "labels": [{"name": label} for label in self.labels],
        }
        return RunnerInstance(self.runner_name, "provisioning", self.runner_name, self.labels)

    def status(self, provider_id):
        return RunnerInstance(provider_id, self.state, self.runner_name, self.labels)

    def terminate(self, provider_id):
        self.state = "terminated"
        if self.github.runner:
            self.github.runner["status"] = "offline"
        return RunnerInstance(provider_id, "terminated", self.runner_name, self.labels)


class CloudRunnerEndToEndAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = RunnerStore(str(Path(self.temp.name) / "gateway.sqlite"))
        self.github = FakeGitHubApp()
        self.provider = FakeProvider(self.github)
        settings = GatewaySettings(
            provisioning_enabled=True,
            owner_approved=True,
            allowed_repositories=(REPOSITORY,),
            budget_limit_usd=100,
            current_spend_usd=10,
            projected_run_cost_usd=5,
            max_concurrent_runners=2,
            max_runtime_minutes=180,
        )
        budget = AzureBudgetGuard(FakeBudgetReader(), 5)
        cleanup = GitHubRunnerCleanup(self.github)
        self.service = GatewayService(
            settings, self.store, self.provider,
            budget_guard=budget, runner_cleanup=cleanup,
        )
        handler = make_handler(
            self.service,
            token="internal-api-token-for-test-only",
            proxy_secret=SECRET,
            public_origin=ORIGIN,
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_address[1])
        self.session_id = "session_e2e_1234567890abcdef"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()

    def signed_headers(self, method, path):
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "oidc-owner-subject",
            "groups": ["dcp-owners"],
            "iat": now,
            "exp": now + 300,
        }
        headers = sign_verified_oidc_assertion(
            method, path, claims, self.session_id, SECRET,
            ISSUER, AUDIENCE, ["dcp-owners"], ["dcp-operators"],
        )
        headers["Origin"] = ORIGIN
        return headers

    def request_json(self, method, path, body=None, csrf=None, idempotency_key=None, headers=None):
        request_headers = headers or self.signed_headers(method, path)
        request_headers["Accept"] = "application/json"
        if csrf:
            request_headers["X-CSRF-Token"] = csrf
        if idempotency_key:
            request_headers["Idempotency-Key"] = idempotency_key
        data = None if body is None else json.dumps(body).encode("utf-8")
        if data is not None:
            request_headers["Content-Type"] = "application/json"
        request = Request(self.base + path, data=data, method=method, headers=request_headers)
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))

    def test_oidc_to_budgeted_create_status_terminate_and_verified_cleanup(self):
        status, session = self.request_json("GET", "/api/auth/session")
        self.assertEqual(status, 200)
        self.assertTrue(session["authenticated"])
        csrf = session["csrfToken"]

        status, created = self.request_json(
            "POST", "/api/cloud-runners", request_payload(), csrf,
            "e2e-idempotency-key-0001",
        )
        self.assertEqual(status, 202)
        self.assertEqual(created["state"], "provisioning")
        runner_id = created["id"]

        status, online = self.request_json("GET", "/api/cloud-runners/" + runner_id)
        self.assertEqual(status, 200)
        self.assertEqual(online["state"], "online")

        status, terminated = self.request_json(
            "DELETE", "/api/cloud-runners/" + runner_id, csrf=csrf,
        )
        self.assertEqual(status, 200)
        self.assertEqual(terminated["state"], "terminated")
        self.assertIsNone(self.github.runner)
        self.assertEqual(self.github.removals, [(REPOSITORY, 77)])

        status, final = self.request_json("GET", "/api/cloud-runners/" + runner_id)
        self.assertEqual(status, 200)
        self.assertEqual(final["state"], "terminated")
        events = self.store.audit_events(runner_id)
        self.assertIn("runner_cleanup_confirmed", [event["event"] for event in events])
        summary = self.store.lifecycle_summary()
        self.assertEqual(summary["cleanup_pending"], 0)
        self.assertEqual(summary["cleanup_confirmed"], 1)

    def test_orka_uses_its_own_budget_when_azure_budget_is_unavailable(self):
        # The top-level budget_gate is the legacy Azure summary. A macOS
        # request must use Orka's independent provider budget instead.
        self.service.budget_guard = None
        self.service.provider_budget_guards = {
            "orka": AzureBudgetGuard(FakeBudgetReader(), 5),
        }
        payload = request_payload()
        payload.update({
            "target_os": "macos",
            "image": "macos-15-arm64",
            "labels": ["self-hosted", "macOS", "ARM64", "dcp-cloud-macos"],
        })

        status, session = self.request_json("GET", "/api/auth/session")
        self.assertEqual(status, 200)
        self.assertTrue(session["authenticated"])
        csrf = session["csrfToken"]

        status, readiness = self.request_json("GET", "/api/cloud-runners/status")
        self.assertEqual(status, 200)
        self.assertEqual(readiness["budget_gate"], "UNKNOWN")
        self.assertEqual(readiness["provider_budget_gates"]["macos"], "PASS")
        self.assertIn("USD budget", readiness["provider_budget_messages"]["macos"])
        self.assertTrue(readiness["providers"]["macos"]["ready"])

        status, created = self.request_json(
            "POST", "/api/cloud-runners", payload, csrf,
            "e2e-orka-budget-key-0001",
        )
        self.assertEqual(status, 202)
        self.assertEqual(created["state"], "provisioning")

    def test_signed_oidc_assertion_cannot_be_replayed(self):
        headers = self.signed_headers("GET", "/api/auth/session")
        status, first = self.request_json("GET", "/api/auth/session", headers=headers)
        self.assertEqual(status, 200)
        request = Request(
            self.base + "/api/auth/session", method="GET",
            headers={**headers, "Accept": "application/json"},
        )
        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=5)
        try:
            self.assertEqual(caught.exception.code, 401)
        finally:
            caught.exception.close()


if __name__ == "__main__":
    unittest.main()
