
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
from unittest.mock import patch
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


class OwnerCredentialSetupTests(unittest.TestCase):
    def test_first_time_setup_requires_fourteen_character_password(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "owner-auth.json"
            with patch("builtins.input", return_value="owner-kept"), patch(
                "tools.local_auth_proxy.getpass.getpass",
                side_effect=["x" * 13, "new-owner-passphrase", "new-owner-passphrase"],
            ):
                record = auth.load_or_create_credentials(path)
            self.assertTrue(
                auth.verify_password(record, "owner-kept", "new-owner-passphrase")
            )
            self.assertFalse(auth.verify_password(record, "owner-kept", "x" * 13))
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)


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
        self.assertIn('id="auth-forgot-password"', html)
        self.assertIn('id="auth-recovery-help"', html)
        self.assertIn("Reset-DCP-Owner-Password.cmd", html)
        self.assertIn("Start-DCP-Local.cmd", html)
        self.assertIn("ยังไม่มีการกู้คืนผ่านอีเมล", html)
        self.assertNotIn(self.token, html)
        self.assertNotIn(self.secret, html)
        with urlopen(self.base + "/recon-back-box/", timeout=3) as response:
            recon_html = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
        self.assertIn("Recon Back Box", recon_html)
        self.assertIn("/api/recon", recon_html)
        self.assertNotIn("https://api.github.com", recon_html)
        self.assertIn("/api/recon", html)
        self.assertNotIn("https://api.github.com", html)



    def test_recon_reads_require_owner_session_and_use_gateway_proxy(self):
        self.cookie_jar.clear()
        denied, _, _ = self.request("/api/recon/repository")
        self.assertEqual(denied, 401)

        _, _, preauth_body = self.request("/api/auth/session")
        csrf = json.loads(preauth_body)["csrfToken"]
        logged_in, _, _ = self.request(
            "/api/auth/login",
            "POST",
            {"username": "owner-test", "password": "correct horse battery staple 2026!"},
            csrf,
        )
        self.assertEqual(logged_in, 200)

        payload = b'{"full_name":"phakphum12345/Drive-letter","private":false}'
        with patch.object(self.app, "gateway_request", return_value=(200, payload)) as gateway_call:
            status, _, body = self.request("/api/recon/repository")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["full_name"], "phakphum12345/Drive-letter")
        self.assertEqual(gateway_call.call_args.args[0:2], ("GET", "/api/recon/repository"))

        unknown, _, _ = self.request("/api/not-allowlisted")
        self.assertEqual(unknown, 404)


class LocalRunnerCredentialFileTests(unittest.TestCase):
    def test_missing_runner_credential_file_returns_empty_map(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(auth.load_runner_tokens(Path(temp) / "missing.json"), {})

    def test_gateway_environment_uses_protected_file_runner_map(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "runner-tokens.json"
            credentials = {"windows-local-01": "r" * 48}
            path.write_text(json.dumps(credentials), encoding="utf-8")
            with patch.object(auth, "RUNNER_TOKENS_FILE", path):
                env = auth.gateway_child_environment({
                    "PATH": "safe-path",
                    "DCP_RUNNER_TOKENS": "inherited-value-must-be-overridden",
                })
            self.assertEqual(
                json.loads(env["DCP_RUNNER_TOKENS"]),
                credentials,
            )
            self.assertEqual(env["PATH"], "safe-path")

    def test_gateway_environment_keeps_explicit_environment_when_no_file_exists(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(auth, "RUNNER_TOKENS_FILE", Path(temp) / "missing.json"):
                env = auth.gateway_child_environment({"DCP_RUNNER_TOKENS": '{"worker":"' + "x" * 40 + '"}'})
            self.assertIn("DCP_RUNNER_TOKENS", env)

    def test_loads_valid_local_runner_credential_map(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "runner-tokens.json"
            credentials = {
                "windows-local-01": "a" * 48,
                "linux-build-01": "b" * 48,
            }
            path.write_text(json.dumps(credentials), encoding="utf-8")
            self.assertEqual(auth.load_runner_tokens(path), credentials)

    def test_rejects_invalid_or_duplicate_runner_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "runner-tokens.json"
            for credentials in (
                [],
                {"bad/worker": "a" * 48},
                {"worker": "short"},
                {"worker-a": "a" * 48, "worker-b": "a" * 48},
            ):
                with self.subTest(credentials=list(credentials) if isinstance(credentials, dict) else credentials):
                    path.write_text(json.dumps(credentials), encoding="utf-8")
                    with self.assertRaises(SystemExit):
                        auth.load_runner_tokens(path)

    def test_rejects_duplicate_json_worker_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "runner-tokens.json"
            path.write_text(
                '{"worker":"' + "a" * 48 + '","worker":"' + "b" * 48 + '"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SystemExit, "invalid JSON"):
                auth.load_runner_tokens(path)

    def test_rejects_broken_symlink_runner_credential_file(self):
        with tempfile.TemporaryDirectory() as temp:
            link = Path(temp) / "runner-tokens.json"
            try:
                link.symlink_to(Path(temp) / "missing-target.json")
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation is not available on this host")
            with self.assertRaisesRegex(SystemExit, "symlink"):
                auth.load_runner_tokens(link)

    def test_rejects_symlink_runner_credential_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            actual = root / "actual.json"
            actual.write_text(json.dumps({"worker": "a" * 48}), encoding="utf-8")
            link = root / "runner-tokens.json"
            try:
                link.symlink_to(actual)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation is not available on this host")
            with self.assertRaisesRegex(SystemExit, "symlink"):
                auth.load_runner_tokens(link)

    def test_rejects_oversized_runner_credential_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "runner-tokens.json"
            path.write_text(" " * (auth.MAX_RUNNER_TOKEN_FILE_BYTES + 1), encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "size limit"):
                auth.load_runner_tokens(path)

if __name__ == "__main__":
    unittest.main()
