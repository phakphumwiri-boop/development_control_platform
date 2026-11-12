"""OIDC callback orchestration tests with a local signed provider fixture."""
import base64
import json
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tools.cloud_gateway.oidc_auth_service import OIDCAuthService
from tools.cloud_gateway.oidc_client import OIDCProvider
from tools.cloud_gateway.oidc_config import OIDCProviderConfig
from tools.cloud_gateway.oidc_session_store import OIDCSessionStore


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def make_token(key, claims):
    header = b64(json.dumps({"alg": "RS256", "kid": "oidc-test-key"}).encode())
    payload = b64(json.dumps(claims).encode())
    signed = (header + "." + payload).encode()
    signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    return header + "." + payload + "." + b64(signature)


class OIDCAuthServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.issuer = "https://idp.example.test/tenant"
        self.client_id = "dcp-client"
        self.redirect = "https://dcp.example.test/api/auth/oidc/callback"
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = self.key.public_key().public_numbers()
        jwk = {"kty": "RSA", "kid": "oidc-test-key", "use": "sig", "alg": "RS256",
               "n": b64(numbers.n.to_bytes((numbers.n.bit_length()+7)//8, "big")),
               "e": b64(numbers.e.to_bytes((numbers.e.bit_length()+7)//8, "big"))}
        self.documents = {
            self.issuer + "/.well-known/openid-configuration": {
                "issuer": self.issuer,
                "authorization_endpoint": "https://idp.example.test/authorize",
                "token_endpoint": "https://idp.example.test/token",
                "jwks_uri": "https://idp.example.test/jwks",
                "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"],
            },
            "https://idp.example.test/jwks": {"keys": [jwk]},
        }
        self.provider = OIDCProvider(self.issuer, lambda url: self.documents[url])
        self.sessions = OIDCSessionStore(str(Path(self.temp.name) / "oidc.sqlite"))
        self.config = OIDCProviderConfig(self.issuer, self.client_id, self.redirect)
        self.token_form = {}

        def post_form(url, form):
            self.token_form.update(url=url, **form)
            now = int(time.time())
            claims = {"iss": self.issuer, "aud": self.client_id, "sub": "user-123",
                      "exp": now + 300, "iat": now, "nonce": self.nonce,
                      "groups": ["dcp-operators"]}
            return {"id_token": make_token(self.key, claims),
                    "access_token": "server-only-token"}

        self.post_form = post_form
        self.auth = OIDCAuthService(self.config, self.provider, self.sessions,
                                    self.post_form, ["dcp-owners"], ["dcp-operators"])

    def tearDown(self):
        self.temp.cleanup()

    def test_login_callback_creates_server_session_and_uses_pkce(self):
        url = self.auth.begin_login("browser-binding")
        query = parse_qs(urlsplit(url).query)
        self.nonce = query["nonce"][0]
        callback = "state=" + query["state"][0] + "&code=one-time-code"
        session_id, identity = self.auth.complete_callback(callback, "browser-binding")
        self.assertEqual(identity["subject"], "user-123")
        self.assertEqual(identity["role"], "operator")
        self.assertEqual(self.sessions.get_session(session_id)["subject"], "user-123")
        self.assertEqual(self.token_form["code"], "one-time-code")
        self.assertEqual(self.token_form["code_verifier"] != "", True)
        self.assertNotIn("access_token", identity)
        self.assertNotIn("id_token", identity)

    def test_state_is_bound_to_browser_and_one_time(self):
        url = self.auth.begin_login("browser-binding")
        query = parse_qs(urlsplit(url).query)
        self.nonce = query["nonce"][0]
        callback = "state=" + query["state"][0] + "&code=code"
        with self.assertRaises(Exception):
            self.auth.complete_callback(callback, "other-browser")
        with self.assertRaises(Exception):
            self.auth.complete_callback(callback, "browser-binding")

    def test_secure_cookie_and_logout_revoke_session(self):
        sid, _ = self.sessions.create_session("user-123", "owner")
        cookie = self.auth.session_cookie(sid)
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertTrue(self.auth.logout(sid))
        self.assertIsNone(self.sessions.get_session(sid))
        self.assertIn("Max-Age=0", self.auth.clear_session_cookie())

    def test_session_rotation_invalidates_old_handle(self):
        old, _ = self.sessions.create_session("user-123", "owner")
        new, identity = self.auth.rotate_session(old)
        self.assertNotEqual(old, new)
        self.assertIsNone(self.sessions.get_session(old))
        self.assertEqual(self.sessions.get_session(new)["subject"], identity["subject"])


if __name__ == "__main__":
    unittest.main()
