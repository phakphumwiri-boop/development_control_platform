"""Authenticated dashboard <-> Runner Agent lifecycle E2E tests.

All traffic uses ephemeral loopback HTTP servers and in-memory/local SQLite
stores. No cloud provider, VM provisioning, repository checkout, or build runs.
"""
import hashlib
import hmac
import json
import secrets
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from types import SimpleNamespace

from tools.cloud_gateway.job_control import JobStore
from tools.cloud_gateway.policy import GatewaySettings
from tools.cloud_gateway.runner_registry import RunnerRegistry
from tools.cloud_gateway.server import make_handler
from tools.cloud_gateway.service import GatewayService
from tools.cloud_gateway.store import RunnerStore
from tools.runner_agent.agent import GatewayClient


class NeverCalledProvider:
    def provision(self, payload):
        raise AssertionError("Runner lifecycle must not provision infrastructure")

    def status(self, runner_id):
        raise AssertionError("Runner lifecycle must not query cloud providers")

    def terminate(self, runner_id):
        raise AssertionError("Runner lifecycle must not terminate cloud resources")


class RunnerLifecycleDashboardE2ETests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        store = RunnerStore(root / "gateway.sqlite3")
        self.registry = RunnerRegistry(root / "runners.sqlite3", stale_after_seconds=15)
        self.jobs = JobStore(root / "jobs.sqlite3")
        self.service = GatewayService(GatewaySettings(), store, NeverCalledProvider())
        self.service.runner_registry = self.registry
        self.service.job_store = self.jobs
        self.service.runner_scheduler = None

        self.proxy_secret = "proxy-lifecycle-test-" + ("p" * 40)
        self.origin = "http://127.0.0.1"
        self.worker_id = "windows-lifecycle-e2e"
        self.runner_token = "runner-lifecycle-token-" + ("r" * 40)
        handler = make_handler(
            self.service,
            token="unused-dashboard-bearer",
            proxy_secret=self.proxy_secret,
            public_origin=self.origin,
            runner_tokens={self.worker_id: self.runner_token},
        )
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:%s" % self.server.server_port
        self.runner = GatewayClient(self.base, self.runner_token)

        self.subject = "owner@example.test"
        self.session = "runner_lifecycle_session_123"
        self.csrf = hmac.new(
            self.proxy_secret.encode(),
            ("csrf\n" + self.subject + "\n" + self.session).encode(),
            hashlib.sha256,
        ).hexdigest()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temp.cleanup()

    def dashboard_headers(self, method, path, role="owner", csrf=False, origin=None):
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(24)
        canonical = "\n".join((
            method, path, self.subject, role, self.session, timestamp, nonce
        )).encode()
        signature = hmac.new(
            self.proxy_secret.encode(), canonical, hashlib.sha256
        ).hexdigest()
        headers = {
            "X-DCP-User": self.subject,
            "X-DCP-Role": role,
            "X-DCP-Session": self.session,
            "X-DCP-Auth-Timestamp": timestamp,
            "X-DCP-Auth-Nonce": nonce,
            "X-DCP-Auth-Signature": signature,
        }
        if csrf:
            headers["Origin"] = self.origin if origin is None else origin
            headers["X-CSRF-Token"] = self.csrf
        return headers

    def dashboard_request(self, method, path, role="owner", csrf=False, origin=None):
        headers = self.dashboard_headers(method, path, role, csrf, origin)
        data = b"{}" if method == "POST" else None
        request = Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read())
            finally:
                exc.close()

    def test_enroll_drain_heartbeat_enable_and_dashboard_inventory(self):
        enrolled = self.runner.enroll("windows", ["flutter", "windows"])
        self.assertEqual(enrolled["runner"]["state"], "offline")
        self.assertEqual(self.registry.allowed_targets(self.worker_id), [])

        status, inventory = self.dashboard_request("GET", "/api/runners", role="operator")
        self.assertEqual(status, 200)
        row = next(item for item in inventory["runners"] if item["worker_id"] == self.worker_id)
        self.assertEqual(row["state"], "offline")
        self.assertFalse(row["can_enable"])

        # Offline enrollment must never be promoted by a dashboard button/API call.
        status, payload = self.dashboard_request(
            "POST", "/api/runners/" + self.worker_id + "/enable", csrf=True
        )
        self.assertEqual(status, 409)
        self.assertIn("recently heartbeating", payload["error"])
        self.assertEqual(self.registry.get(self.worker_id)["state"], "offline")

        # Only the real agent's authenticated registration establishes liveness.
        self.runner.register("windows", ["flutter", "windows"])
        status, payload = self.dashboard_request(
            "POST", "/api/runners/" + self.worker_id + "/drain", csrf=True
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["runner"]["state"], "draining")
        self.assertEqual(self.registry.allowed_targets(self.worker_id), [])

        # Heartbeats keep a draining runner alive but do not make it schedulable.
        self.assertEqual(self.runner.ping()["runner"]["state"], "draining")
        status, inventory = self.dashboard_request("GET", "/api/runners")
        row = next(item for item in inventory["runners"] if item["worker_id"] == self.worker_id)
        self.assertTrue(row["can_enable"])

        status, payload = self.dashboard_request(
            "POST", "/api/runners/" + self.worker_id + "/enable", csrf=True
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["runner"]["state"], "online")
        self.assertIn("build_windows", self.registry.allowed_targets(self.worker_id))

    def test_dashboard_lifecycle_mutations_require_owner_same_origin_and_csrf(self):
        self.runner.register("windows", ["flutter", "windows"])
        path = "/api/runners/" + self.worker_id + "/drain"

        status, _ = self.dashboard_request("POST", path, role="operator", csrf=True)
        self.assertEqual(status, 403)

        status, _ = self.dashboard_request("POST", path, role="owner", csrf=False)
        self.assertEqual(status, 403)

        status, _ = self.dashboard_request(
            "POST", path, role="owner", csrf=True, origin="https://attacker.example"
        )
        self.assertEqual(status, 403)

        status, _ = self.dashboard_request(
            "POST", "/api/runners/missing-runner/drain", role="owner", csrf=True
        )
        self.assertEqual(status, 404)

        self.assertEqual(self.registry.get(self.worker_id)["state"], "online")

    def test_inventory_requires_authenticated_dashboard_identity(self):
        request = Request(self.base + "/api/runners", method="GET")
        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=3)
        try:
            self.assertEqual(caught.exception.code, 401)
        finally:
            caught.exception.close()


if __name__ == "__main__":
    unittest.main()
