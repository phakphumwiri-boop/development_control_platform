"""Authenticated HTTP tests for DCP Infrastructure Manager API.

Uses loopback HTTP, signed local proxy identities, SQLite temp storage and the
fake provider only. No live VM, cloud, Orka, or host provisioning is invoked.
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

from tools.cloud_gateway.infrastructure import (
    FakeInfrastructureProvider, InfrastructureManager, InfrastructureStore,
)
from tools.cloud_gateway.policy import GatewaySettings
from tools.cloud_gateway.server import make_handler
from tools.cloud_gateway.service import GatewayService
from tools.cloud_gateway.store import RunnerStore


class NoopProvider:
    def provision(self, payload):
        raise AssertionError("infrastructure API must not call legacy provider")

    def status(self, resource_id):
        raise AssertionError("unexpected legacy provider status")

    def terminate(self, resource_id):
        raise AssertionError("unexpected legacy provider termination")


class InfrastructureApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.secret = "local-infra-api-secret-" + ("x" * 32)
        self.origin = "https://dcp.example.test"
        store = RunnerStore(str(Path(self.temp.name) / "gateway.sqlite"))
        service = GatewayService(GatewaySettings(), store, NoopProvider())
        service.infrastructure_manager = InfrastructureManager(
            InfrastructureStore(Path(self.temp.name) / "infra.sqlite"),
            {"fake": FakeInfrastructureProvider()},
        )
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(service, "unused-token", self.secret, self.origin),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_port)
        self.subject = "infra-owner@example.test"
        self.session = "infra_session_identifier_123"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def headers(self, method, path, role="owner", csrf=False):
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(24)
        canonical = "\\n".join((method, path, self.subject, role,
                                  self.session, timestamp, nonce)).encode()
        signature = hmac.new(self.secret.encode(), canonical, hashlib.sha256).hexdigest()
        result = {
            "X-DCP-User": self.subject, "X-DCP-Role": role,
            "X-DCP-Session": self.session, "X-DCP-Auth-Timestamp": timestamp,
            "X-DCP-Auth-Nonce": nonce, "X-DCP-Auth-Signature": signature,
        }
        if csrf:
            result["Origin"] = self.origin
            result["X-CSRF-Token"] = hmac.new(
                self.secret.encode(),
                ("csrf\\n" + self.subject + "\\n" + self.session).encode(),
                hashlib.sha256,
            ).hexdigest()
        return result

    def request(self, method, path, role="owner", payload=None, extra=None):
        headers = self.headers(method, path, role, csrf=method != "GET")
        headers.update(extra or {})
        data = json.dumps(payload).encode() if payload is not None else None
        request = Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urlopen(request) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read())
            finally:
                exc.close()

    def test_owner_can_create_list_start_stop_and_delete_fake_resource(self):
        status, created = self.request(
            "POST", "/api/infrastructure",
            payload={"target_os": "linux", "image_id": "dcp-linux-ubuntu-24.04",
                     "template_id": "flutter-linux-small", "provider_id": "fake"},
            extra={"Idempotency-Key": "api-infra-create-0001"},
        )
        self.assertEqual(status, 201)
        resource_id = created["id"]
        self.assertEqual(created["state"], "provisioned")
        self.assertEqual(created["provider_id"], "fake")

        status, inventory = self.request("GET", "/api/infrastructure")
        self.assertEqual(status, 200)
        self.assertEqual(inventory["resources"][0]["id"], resource_id)

        status, running = self.request(
            "POST", "/api/infrastructure/" + resource_id + "/start", payload={}
        )
        self.assertEqual(status, 200)
        self.assertEqual(running["state"], "running")

        status, stopped = self.request(
            "POST", "/api/infrastructure/" + resource_id + "/stop", payload={}
        )
        self.assertEqual(status, 200)
        self.assertEqual(stopped["state"], "stopped")

        status, deleted = self.request("DELETE", "/api/infrastructure/" + resource_id)
        self.assertEqual(status, 200)
        self.assertEqual(deleted["state"], "deleted")

    def test_operator_cannot_delete_resource(self):
        status, created = self.request(
            "POST", "/api/infrastructure",
            payload={"target_os": "linux", "image_id": "dcp-linux-ubuntu-24.04",
                     "template_id": "flutter-linux-small"},
            extra={"Idempotency-Key": "api-infra-create-0002"},
        )
        self.assertEqual(status, 201)
        status, result = self.request(
            "DELETE", "/api/infrastructure/" + created["id"], role="operator"
        )
        self.assertEqual(status, 403)
        self.assertEqual(result["error"], "owner role required")

    def test_unauthenticated_inventory_is_rejected(self):
        request = Request(self.base + "/api/infrastructure")
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        try:
            self.assertEqual(caught.exception.code, 401)
        finally:
            caught.exception.close()


if __name__ == "__main__":
    unittest.main()
