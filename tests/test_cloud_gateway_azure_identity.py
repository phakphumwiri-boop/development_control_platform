import io
import json
import time
import unittest
from urllib.error import HTTPError

from tools.cloud_gateway.azure_identity import IdentityError, ManagedIdentityCredential
from tools.cloud_gateway.safe_http import NoRedirectHandler


class Response(io.BytesIO):
    def __init__(self, payload, content_type="application/json"):
        super().__init__(payload)
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class ManagedIdentityTests(unittest.TestCase):
    def make(self, payload=None, *, content_type="application/json", env=None, timeout=3):
        seen = {}
        payload = payload or {
            "access_token": "test-token", "token_type": "Bearer",
            "expires_on": str(int(time.time()) + 3600),
        }
        def opener(request, timeout):
            seen["url"] = request.full_url
            seen["headers"] = dict(request.header_items())
            seen["timeout"] = timeout
            return Response(json.dumps(payload).encode(), content_type)
        credential = ManagedIdentityCredential(
            env=env or {
                "IDENTITY_ENDPOINT": "http://127.0.0.1:41741/msi/token",
                "IDENTITY_HEADER": "local-header",
            },
            timeout=timeout, opener=opener,
        )
        return credential, seen

    def test_requests_bounded_bearer_token_from_app_service_identity_endpoint(self):
        credential, seen = self.make()
        self.assertEqual(credential.get_token("https://vault.azure.net"), "test-token")
        self.assertIn("resource=https%3A%2F%2Fvault.azure.net", seen["url"])
        self.assertEqual(seen["timeout"], 3)
        self.assertIn("X-identity-header", seen["headers"])

    def test_rejects_untrusted_endpoint_and_invalid_resource(self):
        for endpoint in (
            "https://127.0.0.1/token",
            "http://169.254.169.254/token",
            "http://attacker.example/token",
            "http://127.0.0.1/token#fragment",
            "http://127.0.0.1/token?redirect=1",
        ):
            credential, _ = self.make(env={
                "IDENTITY_ENDPOINT": endpoint, "IDENTITY_HEADER": "h"
            })
            with self.assertRaises(IdentityError):
                credential.get_token("https://vault.azure.net")
        credential, _ = self.make()
        for resource in ("http://vault.azure.net", "https://user@vault.azure.net", "https://vault.azure.net?x=1"):
            with self.assertRaises(IdentityError):
                credential.get_token(resource)

    def test_rejects_invalid_token_type_expiry_and_non_json(self):
        cases = (
            {"access_token": "t", "token_type": "Basic", "expires_on": str(int(time.time()) + 10)},
            {"access_token": "t", "token_type": "Bearer", "expires_on": "1"},
            {"access_token": "t", "token_type": "Bearer"},
        )
        for payload in cases:
            credential, _ = self.make(payload)
            with self.assertRaises(IdentityError):
                credential.get_token("https://vault.azure.net")
        credential, _ = self.make(content_type="text/plain")
        with self.assertRaises(IdentityError):
            credential.get_token("https://vault.azure.net")

    def test_rejects_oversized_response_and_invalid_timeout(self):
        def oversized(request, timeout):
            return Response(b"x" * (ManagedIdentityCredential.MAX_RESPONSE_BYTES + 1))
        credential = ManagedIdentityCredential(
            env={"IDENTITY_ENDPOINT":"http://127.0.0.1/token","IDENTITY_HEADER":"h"},
            opener=oversized,
        )
        with self.assertRaises(IdentityError):
            credential.get_token("https://vault.azure.net")
        with self.assertRaises(ValueError):
            ManagedIdentityCredential(timeout=0)

    def test_redirect_handler_never_creates_redirected_request(self):
        handler = NoRedirectHandler()
        request = handler.redirect_request(None, None, 302, "Found", {}, "https://attacker.test/")
        self.assertIsNone(request)


if __name__ == "__main__":
    unittest.main()
