"""HTTPS WSGI route tests for OIDC login, callback, session, rotation and logout."""
import io
import unittest
from types import SimpleNamespace
from urllib.parse import urlsplit, parse_qs

from tools.cloud_gateway.oidc_wsgi import OIDCWSGIApplication


class FakeSessions:
    session_ttl = 3600
    def __init__(self):
        self.rows = {}
    def get_session(self, sid):
        return self.rows.get(sid)
    def csrf_valid(self, sid, token):
        return sid in self.rows and token == self.rows[sid]["csrf_token"]
    def revoke_session(self, sid):
        return self.rows.pop(sid, None) is not None


class FakeAuth:
    def __init__(self):
        self.config = SimpleNamespace(redirect_uri="https://dcp.example.test/api/auth/oidc/callback")
        self.sessions = FakeSessions()
        self.calls = []
    def begin_login(self, binding):
        self.calls.append(("begin", binding))
        return "https://idp.example.test/authorize?state=state123"
    def complete_callback(self, query, binding):
        self.calls.append(("callback", query, binding))
        self.sessions.rows["session-id"] = {
            "subject": "subject-1", "role": "operator",
            "csrf_token": "csrf-1", "expires_at": 9999999999,
        }
        return "session-id", {"subject": "subject-1", "role": "operator"}
    def session_cookie(self, sid, max_age):
        return f"DCP_OIDC_SESSION={sid}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax"
    def clear_session_cookie(self):
        return "DCP_OIDC_SESSION=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"
    def logout(self, sid):
        return self.sessions.revoke_session(sid)
    def rotate_session(self, sid):
        old = self.sessions.rows.pop(sid)
        self.sessions.rows["new-session"] = dict(old)
        return "new-session", old


class OIDCWSGITests(unittest.TestCase):
    def setUp(self):
        self.auth = FakeAuth()
        self.app = OIDCWSGIApplication(self.auth, "https://dcp.example.test")

    def call(self, path, method="GET", query="", cookie="", origin="", csrf="", scheme="https", host="dcp.example.test"):
        environ = {
            "REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query,
            "HTTP_COOKIE": cookie, "HTTP_ORIGIN": origin, "HTTP_X_CSRF_TOKEN": csrf,
            "wsgi.url_scheme": scheme, "HTTP_HOST": host, "wsgi.input": io.BytesIO(b""),
        }
        captured = {}
        def start_response(status, headers):
            captured["status"] = status
            captured["headers"] = headers
        body = b"".join(self.app(environ, start_response))
        return captured, body

    def test_rejects_backslash_post_login_redirect(self):
        with self.assertRaises(ValueError):
            OIDCWSGIApplication(self.auth, "https://dcp.example.test", "/\\\\attacker.example")

    def test_login_requires_https_and_sets_http_only_binding_cookie(self):
        result, _ = self.call("/api/auth/oidc/login", scheme="http")
        self.assertEqual(result["status"], "400 Bad Request")
        result, _ = self.call("/api/auth/oidc/login")
        self.assertEqual(result["status"], "302 Found")
        headers = dict(result["headers"])
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("Secure", headers["Set-Cookie"])
        self.assertEqual(headers["Location"].split("?")[0], "https://idp.example.test/authorize")

    def test_callback_sets_secure_session_cookie_and_clears_binding(self):
        cookie = "DCP_OIDC_BROWSER=browser-binding"
        result, _ = self.call("/api/auth/oidc/callback", query="state=state123&code=code", cookie=cookie)
        self.assertEqual(result["status"], "303 See Other")
        cookies = [value for key, value in result["headers"] if key == "Set-Cookie"]
        self.assertTrue(any("DCP_OIDC_SESSION=session-id" in value and "Secure" in value for value in cookies))
        self.assertTrue(any("DCP_OIDC_BROWSER=" in value and "Max-Age=0" in value for value in cookies))

    def test_session_endpoint_returns_identity_and_csrf_but_not_tokens(self):
        self.auth.sessions.rows["sid"] = {
            "subject": "subject-1", "role": "owner", "csrf_token": "csrf-1", "expires_at": 1234,
        }
        result, body = self.call("/api/auth/oidc/session", cookie="DCP_OIDC_SESSION=sid")
        self.assertEqual(result["status"], "200 OK")
        payload = __import__("json").loads(body)
        self.assertTrue(payload["authenticated"])
        self.assertEqual(payload["csrfToken"], "csrf-1")
        self.assertNotIn("access_token", payload)

    def test_logout_requires_same_origin_and_csrf(self):
        self.auth.sessions.rows["sid"] = {"subject": "s", "role": "owner", "csrf_token": "csrf"}
        result, _ = self.call("/api/auth/oidc/logout", "POST", cookie="DCP_OIDC_SESSION=sid",
                              origin="https://attacker.example", csrf="csrf")
        self.assertEqual(result["status"], "403 Forbidden")
        result, _ = self.call("/api/auth/oidc/logout", "POST", cookie="DCP_OIDC_SESSION=sid",
                              origin="https://dcp.example.test", csrf="csrf")
        self.assertEqual(result["status"], "200 OK")
        self.assertNotIn("sid", self.auth.sessions.rows)

    def test_rotation_replaces_cookie_and_old_session(self):
        self.auth.sessions.rows["sid"] = {"subject": "s", "role": "owner", "csrf_token": "csrf"}
        result, _ = self.call("/api/auth/oidc/rotate", "POST", cookie="DCP_OIDC_SESSION=sid",
                              origin="https://dcp.example.test", csrf="csrf")
        self.assertEqual(result["status"], "200 OK")
        self.assertNotIn("sid", self.auth.sessions.rows)
        self.assertIn("new-session", self.auth.sessions.rows)


if __name__ == "__main__":
    unittest.main()
