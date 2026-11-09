"""Authenticated browser control API tests; no cloud resources or real credentials."""
import hashlib
import hmac
import json
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from tools.cloud_gateway.policy import GatewaySettings, PolicyDenied
from tools.cloud_gateway.server import DisabledProvider, ProxyIdentityVerifier, make_handler
from tools.cloud_gateway.oidc_assertion import OIDCAssertionError, sign_verified_oidc_assertion
from tools.cloud_gateway.budget_guard import AzureBudgetGuard
from tools.cloud_gateway.service import GatewayService
from tools.cloud_gateway.store import RunnerStore
from tools.cloud_gateway.job_control import JobStore
from tools.cloud_gateway.artifacts import ArtifactStore
from tools.local_runner_agent.client import GatewayClient, RunnerAgentConfig

SECRET = "test-proxy-secret-that-is-at-least-32-bytes-long"
ORIGIN = "https://dcp.example.test"


def signed_headers(method, path, nonce, role="operator", subject="test-user",
                   session="session_1234567890abcdef"):
    timestamp = str(int(time.time()))
    canonical = "\n".join((method, path, subject, role, session, timestamp, nonce)).encode()
    signature = hmac.new(SECRET.encode(), canonical, hashlib.sha256).hexdigest()
    return {
        "X-DCP-User": subject, "X-DCP-Role": role, "X-DCP-Session": session,
        "X-DCP-Auth-Timestamp": timestamp, "X-DCP-Auth-Nonce": nonce,
        "X-DCP-Auth-Signature": signature,
    }


class AuthenticatedControlAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = RunnerStore(str(Path(self.temp.name) / "gateway.sqlite"))
        self.settings = GatewaySettings(allowed_repositories=("phakphum12345/generated-A4-pdf",))
        self.service = GatewayService(self.settings, self.store, DisabledProvider())
        self.job_store = JobStore(str(Path(self.temp.name) / "jobs.sqlite"))
        self.service.job_store = self.job_store
        self.service.artifact_store = ArtifactStore(Path(self.temp.name) / "artifacts")
        self.runner_token = "runner-token-for-test-that-is-at-least-32-bytes"
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(self.service, "internal-gateway-token", SECRET, ORIGIN,
                         {"worker-test-01": self.runner_token}),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, nonce, extra=None, body=None, role="operator"):
        headers = signed_headers(method, path, nonce, role=role)
        headers.update(extra or {})
        data = None if body is None else json.dumps(body).encode()
        return Request(self.base + path, data=data, method=method, headers=headers)

    def test_session_status_and_inventory_require_signed_proxy_identity(self):
        with urlopen(self.request("GET", "/api/auth/session", "nonce_session_0001")) as response:
            session = json.loads(response.read())
            self.assertTrue(session["authenticated"])
            self.assertEqual(len(session["csrfToken"]), 64)
        with urlopen(self.request("GET", "/api/cloud-runners/status", "nonce_status_0001")) as response:
            status = json.loads(response.read())
            self.assertEqual(status["gateway"], "READY")
            self.assertFalse(status["bootstrap_ready"])
            self.assertFalse(status["providers"]["linux"]["ready"])
            self.assertEqual(status["budget_gate"], "UNKNOWN")
            self.assertEqual(status["active_runners"], 0)
            self.assertEqual(status["lifecycle"]["cleanup_pending"], 0)
            self.assertEqual(status["lifecycle"]["cleanup_retries"], 0)
        with urlopen(self.request("GET", "/api/cloud-runners", "nonce_list_000001")) as response:
            self.assertEqual(json.loads(response.read()), {"runners": []})

    def test_authenticated_repository_catalog_endpoint_returns_safe_metadata(self):
        self.service.repository_catalog = lambda: [
            {
                "full_name": "example/private-app",
                "private": True,
                "default_branch": "main",
                "permissions": {"push": True, "pull": True},
            }
        ]
        with urlopen(self.request("GET", "/api/github/repositories", "nonce_repo_catalog_0001")) as response:
            payload = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertEqual(payload["repositories"][0]["full_name"], "example/private-app")
            self.assertTrue(payload["repositories"][0]["private"])

    def test_repository_catalog_endpoint_fails_closed_when_not_configured(self):
        with self.assertRaises(HTTPError) as error:
            urlopen(self.request("GET", "/api/github/repositories", "nonce_repo_catalog_0002"))
        try:
            self.assertEqual(error.exception.code, 503)
        finally:
            error.exception.close()

    def test_status_projects_budget_for_all_active_runners(self):
        self.store.create("seed-runner", "seed-budget-key", "seed-fingerprint", {"repository":"phakphum12345/generated-A4-pdf","workflow_run_id":1,"commit_sha":"a"*40,"target_os":"linux"}, "2999-01-01T00:00:00+00:00")
        self.store.transition("seed-runner", "online", "provider-seed")
        class Snapshot:
            currency = "USD"
            current_spend = 10
            forecast_spend = 40
            def permits(self, projected):
                return projected <= 15
        class Reader:
            def read(self):
                return Snapshot()
        self.service.budget_guard = AzureBudgetGuard(Reader(), 10)
        with urlopen(self.request("GET", "/api/cloud-runners/status", "nonce_budget_status_001")) as response:
            status = json.loads(response.read())
        self.assertEqual(status["active_runners"], 1)
        self.assertEqual(status["budget_gate"], "FAIL")
        self.assertIn("projected 20 for 2 runner(s)", status["budget_message"])

    def test_missing_or_invalid_identity_is_denied(self):
        req = Request(self.base + "/api/cloud-runners/status")
        with self.assertRaises(HTTPError) as error:
            urlopen(req)
        try:
            self.assertEqual(error.exception.code, 401)
        finally:
            error.exception.close()
        headers = signed_headers("GET", "/api/cloud-runners/status", "nonce_forged_00001")
        headers["X-DCP-Auth-Signature"] = "0" * 64
        with self.assertRaises(HTTPError) as error:
            urlopen(Request(self.base + "/api/cloud-runners/status", headers=headers))
        try:
            self.assertEqual(error.exception.code, 401)
        finally:
            error.exception.close()

    def test_oidc_verified_claims_map_to_signed_gateway_assertion(self):
        claims = {
            "iss": "https://idp.example.test/",
            "aud": ["dcp-web", "other-client"], "azp": "dcp-web",
            "sub": "oidc-subject-123",
            "groups": ["dcp-operators"],
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        }
        headers = sign_verified_oidc_assertion(
            "GET", "/api/cloud-runners/status?view=compact", claims,
            "session_1234567890abcdef", SECRET,
            "https://idp.example.test/", "dcp-web",
            ["dcp-owners"], ["dcp-operators"],
        )
        self.assertEqual(headers["X-DCP-User"], "oidc-subject-123")
        self.assertEqual(headers["X-DCP-Role"], "operator")
        class Handler:
            command = "GET"
            path = "/api/cloud-runners/status?view=compact"
            def __init__(self, headers):
                self.headers = headers
        verifier = ProxyIdentityVerifier(SECRET)
        identity = verifier.verify(Handler(headers))
        self.assertEqual(identity["subject"], "oidc-subject-123")
        self.assertEqual(identity["role"], "operator")

    def test_oidc_owner_group_has_owner_role_and_invalid_claims_fail_closed(self):
        claims = {
            "iss": "https://idp.example.test/", "aud": "dcp-web",
            "sub": "owner-subject", "groups": ["dcp-owners"],
            "iat": int(time.time()), "exp": int(time.time()) + 300,
        }
        headers = sign_verified_oidc_assertion(
            "POST", "/api/cloud-runners", claims, "session_1234567890abcdef",
            SECRET, "https://idp.example.test/", "dcp-web",
            ["dcp-owners"], ["dcp-operators"],
        )
        self.assertEqual(headers["X-DCP-Role"], "owner")
        with self.assertRaises(OIDCAssertionError):
            sign_verified_oidc_assertion(
                "GET", "/api/cloud-runners", claims, "session_1234567890abcdef",
                SECRET, "https://wrong.example/", "dcp-web",
                ["dcp-owners"], ["dcp-operators"],
            )
        bad_azp = dict(claims, azp="other-client")
        with self.assertRaises(OIDCAssertionError):
            sign_verified_oidc_assertion(
                "GET", "/api/cloud-runners", bad_azp, "session_1234567890abcdef",
                SECRET, "https://idp.example.test/", "dcp-web",
                ["dcp-owners"], ["dcp-operators"],
            )
        not_yet_valid = dict(claims, nbf=int(time.time()) + 300)
        with self.assertRaises(OIDCAssertionError):
            sign_verified_oidc_assertion(
                "GET", "/api/cloud-runners", not_yet_valid, "session_1234567890abcdef",
                SECRET, "https://idp.example.test/", "dcp-web",
                ["dcp-owners"], ["dcp-operators"],
            )
        expired = dict(claims, exp=int(time.time()) - 1)
        with self.assertRaises(OIDCAssertionError):
            sign_verified_oidc_assertion(
                "GET", "/api/cloud-runners", expired, "session_1234567890abcdef",
                SECRET, "https://idp.example.test/", "dcp-web",
                ["dcp-owners"], ["dcp-operators"],
            )

    def test_durable_nonce_expiry_allows_reuse_only_after_window(self):
        nonce = "durable_nonce_000001"
        self.assertTrue(self.store.consume_auth_nonce(nonce, 100.0, 160.0))
        self.assertFalse(self.store.consume_auth_nonce(nonce, 120.0, 180.0))
        self.assertTrue(self.store.consume_auth_nonce(nonce, 161.0, 221.0))

    def test_oidc_assertion_is_bound_to_method_and_path(self):
        claims = {
            "iss": "https://idp.example.test/", "aud": "dcp-web",
            "sub": "oidc-subject-789", "groups": ["dcp-operators"],
            "iat": int(time.time()), "exp": int(time.time()) + 300,
        }
        headers = sign_verified_oidc_assertion(
            "GET", "/api/cloud-runners/status", claims,
            "session_1234567890abcdef", SECRET,
            "https://idp.example.test/", "dcp-web",
            ["dcp-owners"], ["dcp-operators"],
        )
        class Handler:
            command = "GET"
            path = "/api/cloud-runners"
            def __init__(self, value):
                self.headers = value
        self.assertIsNone(ProxyIdentityVerifier(SECRET).verify(Handler(headers)))

    def test_durable_nonce_replay_is_rejected_across_verifier_instances(self):
        claims = {
            "iss": "https://idp.example.test/", "aud": "dcp-web",
            "sub": "oidc-subject-456", "groups": ["dcp-operators"],
            "iat": int(time.time()), "exp": int(time.time()) + 300,
        }
        headers = sign_verified_oidc_assertion(
            "GET", "/api/cloud-runners/status", claims,
            "session_1234567890abcdef", SECRET,
            "https://idp.example.test/", "dcp-web",
            ["dcp-owners"], ["dcp-operators"],
        )
        class Handler:
            command = "GET"
            path = "/api/cloud-runners/status"
            def __init__(self, value):
                self.headers = value
        first = ProxyIdentityVerifier(SECRET, nonce_store=self.store)
        second = ProxyIdentityVerifier(SECRET, nonce_store=self.store)
        self.assertIsNotNone(first.verify(Handler(headers)))
        self.assertIsNone(second.verify(Handler(headers)))

    def test_durable_nonce_store_fails_closed_when_unavailable(self):
        class BrokenStore:
            def consume_auth_nonce(self, *args):
                raise RuntimeError("database unavailable")
        headers = signed_headers("GET", "/api/cloud-runners/status", "nonce_durable_0001")
        class Handler:
            command = "GET"
            path = "/api/cloud-runners/status"
            def __init__(self, value):
                self.headers = value
        verifier = ProxyIdentityVerifier(SECRET, nonce_store=BrokenStore())
        self.assertIsNone(verifier.verify(Handler(headers)))

    def test_proxy_nonce_replay_is_rejected(self):
        req = self.request("GET", "/api/cloud-runners/status", "nonce_replay_00001")
        with urlopen(req) as response:
            self.assertEqual(response.status, 200)
        with self.assertRaises(HTTPError) as error:
            urlopen(req)
        try:
            self.assertEqual(error.exception.code, 401)
        finally:
            error.exception.close()

    def test_viewer_role_is_not_authorized(self):
        headers = signed_headers("GET", "/api/cloud-runners/status", "nonce_viewer_000001", role="viewer")
        with self.assertRaises(HTTPError) as error:
            urlopen(Request(self.base + "/api/cloud-runners/status", headers=headers))
        try:
            self.assertEqual(error.exception.code, 401)
        finally:
            error.exception.close()

    def test_mutation_requires_origin_and_csrf(self):
        session_req = self.request("GET", "/api/auth/session", "nonce_session_0002")
        with urlopen(session_req) as response:
            csrf = json.loads(response.read())["csrfToken"]
        body = {"repository": "phakphum12345/generated-A4-pdf"}
        headers = {"Content-Type": "application/json", "Origin": ORIGIN, "Idempotency-Key": "api-test-key-0001"}
        bad_csrf = self.request("POST", "/api/cloud-runners", "nonce_post_badcsrf_01", headers, body)
        with self.assertRaises(HTTPError) as error:
            urlopen(bad_csrf)
        try:
            self.assertEqual(error.exception.code, 403)
        finally:
            error.exception.close()
        headers["X-CSRF-Token"] = csrf
        headers["Origin"] = "https://attacker.example"
        bad_origin = self.request("POST", "/api/cloud-runners", "nonce_post_badorigin1", headers, body)
        with self.assertRaises(HTTPError) as error:
            urlopen(bad_origin)
        try:
            self.assertEqual(error.exception.code, 403)
        finally:
            error.exception.close()

    def test_valid_mutation_still_fails_closed_when_provisioning_disabled(self):
        session_req = self.request("GET", "/api/auth/session", "nonce_session_0003")
        with urlopen(session_req) as response:
            csrf = json.loads(response.read())["csrfToken"]
        payload = {
            "repository": "phakphum12345/generated-A4-pdf", "workflow_run_id": 123,
            "commit_sha": "a" * 40, "target_os": "linux",
            "image": "ubuntu-24.04-x64",
            "labels": ["self-hosted", "Linux", "X64", "dcp-cloud-linux"],
            "ephemeral": True, "max_runtime_minutes": 30,
            "network_policy": "restricted-egress",
            "registration_token_handling": "provider-side-only",
        }
        headers = {
            "Content-Type": "application/json", "Origin": ORIGIN,
            "X-CSRF-Token": csrf, "Idempotency-Key": "api-test-key-0002",
        }
        req = self.request(
            "POST", "/api/cloud-runners", "nonce_post_safe_000001",
            headers, payload, role="owner",
        )
        with self.assertRaises(HTTPError) as error:
            urlopen(req)
        try:
            self.assertEqual(error.exception.code, 503)
        finally:
            error.exception.close()
        self.assertEqual(self.store.active_count(), 0)


    def _csrf(self, nonce="nonce_job_session_0001"):
        with urlopen(self.request("GET", "/api/auth/session", nonce)) as response:
            return json.loads(response.read())["csrfToken"]

    def _dashboard_post(self, path, nonce, body, role="owner", key=None, csrf=None):
        headers = {"Content-Type": "application/json", "Origin": ORIGIN,
                   "X-CSRF-Token": csrf or self._csrf(nonce + "_session"),
                   "Idempotency-Key": key or "job-api-key-00001"}
        return self.request("POST", path, nonce, headers, body, role=role)

    def test_dashboard_job_api_create_list_get_cancel_and_role_guards(self):
        self.service.repository_authorizer = lambda repository: repository == "example/private-app"
        self.service.repository_commit_resolver = lambda repository, sha: {"commit_sha": sha}
        payload = {"repository": "example/private-app", "commit_sha": "a" * 40, "target": "test"}
        with urlopen(self._dashboard_post("/api/jobs", "nonce_job_create_0001", payload)) as response:
            created = json.loads(response.read())
            self.assertEqual(response.status, 202)
            self.assertEqual(created["state"], "queued")
        job_id = created["id"]
        with urlopen(self.request("GET", "/api/jobs", "nonce_job_list_00001")) as response:
            self.assertEqual(json.loads(response.read())["jobs"][0]["id"], job_id)
        with urlopen(self.request("GET", "/api/jobs/" + job_id, "nonce_job_get_000001")) as response:
            self.assertEqual(json.loads(response.read())["id"], job_id)
        csrf = self._csrf("nonce_job_session_owner")
        with self.assertRaises(HTTPError) as error:
            urlopen(self._dashboard_post("/api/jobs/" + job_id + "/cancel",
                                         "nonce_job_cancel_operator", {}, role="operator", csrf=csrf))
        try:
            self.assertEqual(error.exception.code, 403)
        finally:
            error.exception.close()
        with urlopen(self._dashboard_post("/api/jobs/" + job_id + "/cancel",
                                          "nonce_job_cancel_owner", {}, csrf=csrf)) as response:
            self.assertEqual(json.loads(response.read())["state"], "cancelled")

    def test_dashboard_job_create_requires_csrf_and_same_origin(self):
        payload = {"repository": "example/private-app", "commit_sha": "b" * 40, "target": "build"}
        headers = {"Content-Type": "application/json", "Origin": ORIGIN,
                   "Idempotency-Key": "job-api-key-00002"}
        with self.assertRaises(HTTPError) as error:
            urlopen(self.request("POST", "/api/jobs", "nonce_job_no_csrf_01", headers, payload, role="owner"))
        try:
            self.assertEqual(error.exception.code, 403)
        finally:
            error.exception.close()

    def test_runner_api_uses_dedicated_identity_and_enforces_worker_ownership(self):
        job, _ = self.job_store.create(
            {"repository": "example/private-app", "commit_sha": "c" * 40, "target": "test"},
            "runner-job-key-0001",
        )
        def runner_request(path, body):
            data = json.dumps(body).encode()
            return Request(self.base + path, data=data, method="POST", headers={
                "Authorization": "Bearer " + self.runner_token,
                "Content-Type": "application/json",
            })
        with urlopen(runner_request("/v1/runner/claim", {"lease_seconds": 60})) as response:
            claimed = json.loads(response.read())["job"]
        self.assertEqual(claimed["id"], job["id"])
        self.assertEqual(claimed["worker"], "worker-test-01")
        with urlopen(runner_request("/v1/runner/" + job["id"] + "/heartbeat", {})) as response:
            self.assertEqual(json.loads(response.read())["state"], "running")
        with urlopen(runner_request("/v1/runner/" + job["id"] + "/logs",
                                    {"message": "runner connected", "stream": "system"})) as response:
            self.assertEqual(response.status, 202)
        with urlopen(runner_request("/v1/runner/" + job["id"] + "/finish",
                                    {"outcome": "succeeded", "result": {"exit_code": 0}})) as response:
            self.assertEqual(json.loads(response.read())["state"], "succeeded")
        self.assertEqual(self.job_store.logs(job["id"])[0]["message"], "runner connected")

    def test_runner_api_rejects_dashboard_token(self):
        request = Request(self.base + "/v1/runner/claim", data=b"{}",
                          method="POST", headers={"Authorization": "Bearer internal-gateway-token"})
        with self.assertRaises(HTTPError) as error:
            urlopen(request)
        try:
            self.assertEqual(error.exception.code, 401)
        finally:
            error.exception.close()

    def test_runner_cannot_finish_another_workers_job(self):
        job, _ = self.job_store.create(
            {"repository": "example/private-app", "commit_sha": "d" * 40, "target": "test"},
            "runner-job-key-0002",
        )
        self.job_store.claim("worker-other")
        data = json.dumps({"outcome": "succeeded"}).encode()
        request = Request(self.base + "/v1/runner/" + job["id"] + "/finish", data=data,
                          method="POST", headers={"Authorization": "Bearer " + self.runner_token,
                          "Content-Type": "application/json"})
        with self.assertRaises(HTTPError) as error:
            urlopen(request)
        try:
            self.assertEqual(error.exception.code, 409)
        finally:
            error.exception.close()

    def test_local_runner_agent_end_to_end_job_receive_status_and_dashboard_visibility(self):
        job, created = self.job_store.create(
            {"repository": "example/private-app", "commit_sha": "e" * 40, "target": "test"},
            "agent-e2e-job-key-001",
        )
        self.assertTrue(created)
        agent = GatewayClient(RunnerAgentConfig(
            self.base, "worker-test-01", self.runner_token
        ))
        health = agent.health()
        self.assertEqual(health["status"], "ok")
        claimed = agent.claim(lease_seconds=60)
        self.assertEqual(claimed["id"], job["id"])
        self.assertEqual(claimed["worker"], "worker-test-01")
        heartbeat = agent.heartbeat(job["id"], lease_seconds=60)
        self.assertEqual(heartbeat["state"], "running")
        self.assertTrue(agent.append_log(job["id"], "agent handshake complete")["accepted"])
        completed = agent.finish(
            job["id"], "cancelled",
            {"execution_started": False, "mode": "handshake-test"},
        )
        self.assertEqual(completed["state"], "cancelled")

        with urlopen(self.request("GET", "/api/jobs/" + job["id"],
                                  "nonce_agent_e2e_job_0001")) as response:
            dashboard_job = json.loads(response.read())
        self.assertEqual(dashboard_job["state"], "cancelled")
        with urlopen(self.request("GET", "/api/jobs/" + job["id"] + "/logs",
                                  "nonce_agent_e2e_logs_0001")) as response:
            dashboard_logs = json.loads(response.read())["logs"]
        self.assertEqual(dashboard_logs[0]["message"], "agent handshake complete")
        with urlopen(self.request("GET", "/api/jobs/" + job["id"] + "/events",
                                  "nonce_agent_e2e_events_01")) as response:
            event_types = [event["event"] for event in json.loads(response.read())["events"]]
        self.assertIn("running", event_types)
        self.assertIn("cancelled", event_types)

    def test_authenticated_repository_refs_endpoint_returns_scoped_branch_metadata(self):
        self.service.repository_authorizer = lambda repository: repository == "example/private-app"
        self.service.repository_ref_catalog = lambda repository, kind: [
            {"name": "feature/one", "commit_sha": "a" * 40}
        ]
        path = "/api/github/repositories/example/private-app/refs"
        headers = signed_headers("GET", path, "nonce_repo_refs_000001")
        request = Request(self.base + path + "?kind=branches", headers=headers)
        with urlopen(request) as response:
            payload = json.loads(response.read())
        self.assertEqual(payload, {
            "repository": "example/private-app",
            "kind": "branches",
            "refs": [{"name": "feature/one", "commit_sha": "a" * 40}],
        })

    def test_repository_refs_endpoint_rejects_repository_outside_installation(self):
        self.service.repository_authorizer = lambda repository: False
        self.service.repository_ref_catalog = lambda *args: self.fail("ref API must not be called")
        path = "/api/github/repositories/attacker/repo/refs"
        headers = signed_headers("GET", path, "nonce_repo_refs_000002")
        with self.assertRaises(HTTPError) as error:
            urlopen(Request(self.base + path + "?kind=tags", headers=headers))
        try:
            self.assertEqual(error.exception.code, 403)
        finally:
            error.exception.close()

    def test_authenticated_repository_project_endpoint_returns_build_capabilities(self):
        self.service.repository_authorizer = lambda repository: repository == "example/flutter-app"
        self.service.repository_project_inspector = lambda repository, sha: {
            "repository": repository,
            "commit_sha": sha,
            "status": "target_detected",
            "project_types": ["flutter"],
            "file_count": 4,
            "truncated": False,
            "flutter": {
                "detected": True,
                "package_manifests": ["pubspec.yaml"],
                "macos_supported": True,
                "macos_runner_projects": ["macos/Runner.xcodeproj/project.pbxproj"],
            },
            "notes": ["read-only inspection"],
        }
        sha = "e" * 40
        path = "/api/github/repositories/example/flutter-app/projects/" + sha
        headers = signed_headers("GET", path, "nonce_repo_project_001")
        with urlopen(Request(self.base + path, headers=headers)) as response:
            payload = json.loads(response.read())
        self.assertEqual(payload["status"], "target_detected")
        self.assertTrue(payload["flutter"]["macos_supported"])

    def test_repository_project_endpoint_rejects_repository_outside_installation(self):
        self.service.repository_authorizer = lambda repository: False
        self.service.repository_project_inspector = lambda *args: self.fail("project inspector must not be called")
        sha = "e" * 40
        path = "/api/github/repositories/attacker/repo/projects/" + sha
        headers = signed_headers("GET", path, "nonce_repo_project_002")
        with self.assertRaises(HTTPError) as error:
            urlopen(Request(self.base + path, headers=headers))
        try:
            self.assertEqual(error.exception.code, 403)
        finally:
            error.exception.close()

    def test_repository_project_endpoint_rejects_repository_outside_installation(self):
        self.service.repository_authorizer = lambda repository: False
        self.service.repository_project_inspector = lambda *args: self.fail("project inspector must not be called")
        sha = "e" * 40
        path = "/api/github/repositories/attacker/repo/projects/" + sha
        headers = signed_headers("GET", path, "nonce_repo_project_003")
        with self.assertRaises(HTTPError) as error:
            urlopen(Request(self.base + path, headers=headers))
        try:
            self.assertEqual(error.exception.code, 403)
        finally:
            error.exception.close()

    def test_authenticated_repository_commit_endpoint_verifies_full_sha(self):
        self.service.repository_authorizer = lambda repository: repository == "example/private-app"
        self.service.repository_commit_resolver = lambda repository, sha: {"commit_sha": sha.lower()}
        sha = "c" * 40
        path = "/api/github/repositories/example/private-app/commits/" + sha
        headers = signed_headers("GET", path, "nonce_repo_commit_0001")
        with urlopen(Request(self.base + path, headers=headers)) as response:
            payload = json.loads(response.read())
        self.assertEqual(payload, {"repository": "example/private-app", "commit_sha": sha})

    def test_job_request_rejects_commit_not_resolved_in_selected_repository(self):
        self.service.repository_authorizer = lambda repository: True
        self.service.repository_commit_resolver = lambda repository, sha: {"commit_sha": "d" * 40}
        payload = {
            "repository": "phakphum12345/generated-A4-pdf",
            "workflow_run_id": 123,
            "commit_sha": "a" * 40,
            "target_os": "linux",
            "image": "ubuntu-24.04-x64",
            "labels": ["self-hosted", "Linux", "X64", "dcp-cloud-linux"],
            "ephemeral": True,
            "max_runtime_minutes": 30,
            "network_policy": "restricted-egress",
            "registration_token_handling": "provider-side-only",
        }
        with self.assertRaisesRegex(PolicyDenied, "does not resolve"):
            self.service.create(payload, "commit-check-key-001")

    def test_repository_refs_endpoint_rejects_unknown_ref_kind(self):
        path = "/api/github/repositories/example/private-app/refs"
        headers = signed_headers("GET", path, "nonce_repo_refs_000003")
        with self.assertRaises(HTTPError) as error:
            urlopen(Request(self.base + path + "?kind=commits", headers=headers))
        try:
            self.assertEqual(error.exception.code, 400)
        finally:
            error.exception.close()


    def test_runner_artifact_upload_and_authenticated_dashboard_download(self):
        job, _ = self.job_store.create({
            "repository": "phakphum12345/generated-A4-pdf",
            "commit_sha": "a" * 40,
            "target": "build",
        }, "api-artifact-job-0001")
        claimed = self.job_store.claim("worker-test-01")
        self.assertEqual(claimed["id"], job["id"])
        payload = b"compiled-artifact-bytes"
        artifact_file = Path(self.temp.name) / "app-release.apk"
        artifact_file.write_bytes(payload)
        client = GatewayClient(RunnerAgentConfig(
            gateway_url=self.base,
            worker_id="worker-test-01",
            token=self.runner_token,
        ))
        metadata = client.upload_artifact(job["id"], str(artifact_file))
        self.assertEqual(metadata["sha256"], hashlib.sha256(payload).hexdigest())

        list_path = f"/api/jobs/{job['id']}/artifacts"
        with urlopen(self.request("GET", list_path, "nonce_artifact_list_0001")) as response:
            listed = json.loads(response.read())["artifacts"]
        self.assertEqual(listed[0]["id"], metadata["id"])

        download_path = f"/api/artifacts/{metadata['id']}/download"
        with urlopen(self.request("GET", download_path, "nonce_artifact_download_001")) as response:
            self.assertEqual(response.read(), payload)
            self.assertEqual(response.headers.get("ETag"), '"' + metadata["sha256"] + '"')
            self.assertIn("app-release.apk", response.headers.get("Content-Disposition", ""))

    def test_dashboard_job_create_fails_closed_on_unverified_commit(self):
        self.service.repository_authorizer = lambda repository: True
        self.service.repository_commit_resolver = lambda repository, sha: {"commit_sha": "f" * 40}
        payload = {"repository": "example/private-app", "commit_sha": "a" * 40, "target": "build"}
        with self.assertRaises(HTTPError) as error:
            urlopen(self._dashboard_post("/api/jobs", "nonce_job_bad_commit_0001", payload))
        try:
            self.assertEqual(error.exception.code, 403)
        finally:
            error.exception.close()

if __name__ == "__main__":
    unittest.main()
