
import http.cookiejar
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import (
    HTTPCookieProcessor,
    Request,
    build_opener,
    urlopen,
)

from tools import local_auth_proxy as auth


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class LocalAuthProxyEndToEndTests(unittest.TestCase):

    @classmethod
    def _cleanup_resources(cls):
        """Stop test servers and release all temporary resources."""
        try:
            if hasattr(cls, "httpd"):
                try:
                    if (
                        hasattr(cls, "thread")
                        and cls.thread.is_alive()
                    ):
                        cls.httpd.shutdown()
                finally:
                    cls.httpd.server_close()
        finally:
            try:
                if hasattr(cls, "thread"):
                    cls.thread.join(timeout=5)
            finally:
                try:
                    if hasattr(cls, "gateway"):
                        if cls.gateway.poll() is None:
                            cls.gateway.terminate()

                        try:
                            cls.gateway.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            cls.gateway.kill()
                            cls.gateway.wait(timeout=5)
                        finally:
                            if cls.gateway.stderr is not None:
                                cls.gateway.stderr.close()
                finally:
                    if hasattr(cls, "temp"):
                        cls.temp.cleanup()

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.local_port = free_port()
        cls.gateway_port = free_port()

        while cls.gateway_port == cls.local_port:
            cls.gateway_port = free_port()

        auth.PORT = cls.local_port

        cls.token = "test-gateway-token-never-sent-to-browser"
        cls.secret = "test-proxy-hmac-secret-" + ("x" * 48)
        cls.gateway_db = str(
            Path(cls.temp.name) / "gateway.sqlite3"
        )

        env = os.environ.copy()
        env.update({
            "DCP_GATEWAY_HOST": "127.0.0.1",
            "DCP_GATEWAY_PORT": str(cls.gateway_port),
            "DCP_GATEWAY_API_TOKEN": cls.token,
            "DCP_TRUSTED_PROXY_HMAC_SECRET": cls.secret,
            "DCP_PUBLIC_ORIGIN": (
                f"http://127.0.0.1:{cls.local_port}"
            ),
            "DCP_GATEWAY_DATABASE": cls.gateway_db,
            "DCP_GATEWAY_PROVISIONING_ENABLED": "false",
            "DCP_GATEWAY_OWNER_APPROVED": "false",
        })

        cls.gateway = subprocess.Popen(
            [sys.executable, "-m", "tools.cloud_gateway.server"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        try:
            for _ in range(60):
                if cls.gateway.poll() is not None:
                    stderr = cls.gateway.stderr.read().decode(
                        errors="replace"
                    )
                    raise RuntimeError(
                        "Gateway failed to start: " + stderr
                    )

                try:
                    with urlopen(
                        f"http://127.0.0.1:{cls.gateway_port}/healthz",
                        timeout=1,
                    ):
                        break
                except Exception:
                    time.sleep(0.2)
            else:
                raise RuntimeError("Gateway health timeout")

            record = auth.password_record(
                "owner-test",
                "correct horse battery staple 2026!",
            )

            cls.app = auth.LocalAuthProxy(
                record,
                cls.token,
                cls.secret,
                cls.gateway_port,
            )

            cls.httpd = auth.ThreadingHTTPServer(
                ("127.0.0.1", cls.local_port),
                auth.make_handler(
                    cls.app,
                    Path(__file__).resolve().parents[1] / "dashboard",
                ),
            )

            cls.thread = threading.Thread(
                target=cls.httpd.serve_forever,
                daemon=True,
            )
            cls.thread.start()

            cls.base = f"http://127.0.0.1:{cls.local_port}"
            cls.cookie_jar = http.cookiejar.CookieJar()
            cls.opener = build_opener(
                HTTPCookieProcessor(cls.cookie_jar)
            )

        except Exception:
            try:
                cls._cleanup_resources()
            except Exception:
                # Preserve the original setup exception.
                pass
            raise

    @classmethod
    def tearDownClass(cls):
        cls._cleanup_resources()

    def request(
        self,
        path,
        method="GET",
        data=None,
        csrf=None,
        origin=True,
    ):
        headers = {
            "Accept": "application/json",
        }

        if origin:
            headers["Origin"] = self.base

        if data is not None:
            headers["Content-Type"] = "application/json"

        if csrf:
            headers["X-CSRF-Token"] = csrf

        req = Request(
            self.base + path,
            data=(
                json.dumps(data).encode()
                if data is not None
                else None
            ),
            headers=headers,
            method=method,
        )

        try:
            with self.opener.open(req, timeout=5) as response:
                return (
                    response.status,
                    response.headers,
                    response.read(),
                )
        except HTTPError as exc:
            try:
                return (
                    exc.code,
                    exc.headers,
                    exc.read(),
                )
            finally:
                exc.close()

    def test_full_login_gateway_session_logout_flow(self):
        status, headers, body = self.request(
            "/api/auth/session"
        )

        self.assertEqual(status, 200)
        self.assertIn(
            "HttpOnly",
            headers.get("Set-Cookie", ""),
        )
        self.assertIn(
            "SameSite=Strict",
            headers.get("Set-Cookie", ""),
        )

        preauth = json.loads(body)

        self.assertFalse(preauth["authenticated"])
        self.assertGreaterEqual(
            len(preauth["csrfToken"]),
            32,
        )

        denied, _, _ = self.request(
            "/api/cloud-runners/status"
        )
        self.assertEqual(denied, 401)

        denied, _, _ = self.request(
            "/api/auth/login",
            "POST",
            {
                "username": "owner-test",
                "password": "wrong-password",
            },
            preauth["csrfToken"],
        )
        self.assertEqual(denied, 401)

        logged_in, _, _ = self.request(
            "/api/auth/login",
            "POST",
            {
                "username": "owner-test",
                "password": "correct horse battery staple 2026!",
            },
            preauth["csrfToken"],
        )
        self.assertEqual(logged_in, 200)
        self.assertNotIn("127.0.0.1", self.app.failures)

        session_status, _, session_body = self.request(
            "/api/auth/session"
        )

        self.assertEqual(session_status, 200)

        session = json.loads(session_body)

        self.assertTrue(session["authenticated"])
        self.assertEqual(
            session["user"]["role"],
            "owner",
        )

        # Verify that the browser session becomes a valid signed
        # proxy identity accepted by the Gateway.
        api_status, _, api_body = self.request(
            "/api/cloud-runners/status"
        )

        self.assertEqual(
            api_status,
            200,
            api_body.decode(errors="replace"),
        )

        api = json.loads(api_body)

        self.assertEqual(api["gateway"], "READY")
        self.assertFalse(api["provisioning_enabled"])

        no_csrf, _, _ = self.request(
            "/api/auth/logout",
            "POST",
        )
        self.assertEqual(no_csrf, 403)

        logged_out, _, _ = self.request(
            "/api/auth/logout",
            "POST",
            csrf=session["csrfToken"],
        )
        self.assertEqual(logged_out, 200)

        denied_after_logout, _, _ = self.request(
            "/api/cloud-runners/status"
        )
        self.assertEqual(denied_after_logout, 401)

    def test_origin_and_csrf_protections_fail_closed(self):
        _, _, body = self.request(
            "/api/auth/session"
        )

        csrf = json.loads(body)["csrfToken"]

        bad_origin, _, _ = self.request(
            "/api/auth/login",
            "POST",
            {
                "username": "owner-test",
                "password": "wrong",
            },
            csrf,
            origin=False,
        )

        self.assertEqual(bad_origin, 403)

    def test_dashboard_served_by_same_origin_proxy_without_gateway_secret(
        self,
    ):
        with urlopen(
            self.base + "/",
            timeout=3,
        ) as response:
            html = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)

        self.assertIn("auth-login-form", html)
        self.assertNotIn(self.token, html)
        self.assertNotIn(self.secret, html)


if __name__ == "__main__":
    unittest.main()
