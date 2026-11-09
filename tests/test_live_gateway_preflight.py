"""Contract tests for the opt-in live Gateway read-only smoke probe."""
import json
import unittest
from pathlib import Path
from urllib.error import HTTPError

from live_gateway_preflight import run_readonly_preflight, validate_gateway_origin


class Response:
    def __init__(self, status, payload):
        self.status = status
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        return self.payload[:size]


class LiveGatewayPreflightTests(unittest.TestCase):
    def test_requires_https_origin_without_credentials_or_path(self):
        self.assertEqual(
            validate_gateway_origin("https://gateway.example.test/"),
            "https://gateway.example.test",
        )
        for value in (
            "http://gateway.example.test",
            "https://user:pass@gateway.example.test",
            "https://@gateway.example.test",
            "https://:pass@gateway.example.test",
            "https://gateway.example.test/api",
            "https://gateway.example.test/?token=secret",
            "https://gateway.example.test/#fragment",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_gateway_origin(value)

    def test_health_and_bearer_checks_are_get_only_and_read_only(self):
        calls = []

        def opener(request, timeout):
            calls.append((request.get_method(), request.full_url, request.headers))
            if request.full_url.endswith("/healthz"):
                return Response(
                    200,
                    json.dumps({
                        "status": "ok",
                        "provisioning_enabled": False,
                    }).encode(),
                )
            raise HTTPError(request.full_url, 404, "not found", {}, None)

        result = run_readonly_preflight(
            "https://gateway.example.test", "test-token-not-logged", opener
        )
        self.assertEqual(result["health"], "PASS")
        self.assertEqual(result["bearer_auth"], "PASS")
        self.assertEqual(result["provider_live_checks"], "SKIPPED")
        self.assertEqual([method for method, _, _ in calls], ["GET", "GET"])
        self.assertTrue(all("/v1/runners/" not in url or "dcp-live-preflight-" in url
                            for _, url, _ in calls))
        self.assertIn(
            "Bearer test-token-not-logged",
            calls[1][2].get("Authorization", ""),
        )

    def test_refuses_to_probe_when_live_provisioning_is_enabled(self):
        calls = []

        def opener(request, timeout):
            calls.append(request.get_method())
            return Response(
                200,
                b'{"status":"ok","provisioning_enabled":true}',
            )

        with self.assertRaisesRegex(RuntimeError, "must remain disabled"):
            run_readonly_preflight(
                "https://gateway.example.test", "test-token", opener
            )
        self.assertEqual(calls, ["GET"])

    def test_live_workflow_is_manual_opt_in_and_read_only(self):
        workflow = Path(
            ".github/workflows/cloud-gateway-live-smoke.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("default: false", workflow)
        self.assertIn("enable_live_readonly_smoke == true", workflow)
        self.assertIn("DCP_LIVE_GATEWAY_URL", workflow)
        self.assertIn("DCP_LIVE_GATEWAY_API_TOKEN", workflow)
        self.assertIn("python tests/live_gateway_preflight.py", workflow)
        self.assertNotIn("\n  pull_request:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)

    def test_rejects_empty_bearer_token_before_network(self):
        calls = []

        def opener(request, timeout):
            calls.append(request)
            raise AssertionError("network must not be called")

        with self.assertRaisesRegex(ValueError, "API_TOKEN is required"):
            run_readonly_preflight("https://gateway.example.test", "", opener)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
