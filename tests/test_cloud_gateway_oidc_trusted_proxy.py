"""Tests for the trusted HTTPS proxy boundary."""
import unittest

from tools.cloud_gateway.oidc_trusted_proxy import TrustedHTTPSProxyMiddleware


class TrustedHTTPSProxyTests(unittest.TestCase):
    def setUp(self):
        self.seen = {}
        def app(environ, start_response):
            self.seen.update(environ)
            start_response("200 OK", [("Content-Length", "0")])
            return [b""]
        self.middleware = TrustedHTTPSProxyMiddleware(
            app, trusted_proxy_cidrs=("127.0.0.1/32",),
            public_origin="https://dcp.example.test",
        )

    def call(self, **overrides):
        env = {
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_X_FORWARDED_PROTO": "https",
            "HTTP_X_FORWARDED_HOST": "dcp.example.test",
            "HTTP_X_DCP_USER": "attacker",
            "HTTP_X_DCP_ROLE": "owner",
            "HTTP_X_FORWARDED_CLIENT_CERT": "forged",
            "wsgi.url_scheme": "http",
            "HTTP_HOST": "internal:8080",
        }
        env.update(overrides)
        result = {}
        def start_response(status, headers):
            result["status"] = status
            result["headers"] = headers
        body = b"".join(self.middleware(env, start_response))
        return result, body

    def test_trusted_peer_sets_https_origin_and_strips_identity_headers(self):
        result, body = self.call()
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(body, b"")
        self.assertEqual(self.seen["wsgi.url_scheme"], "https")
        self.assertEqual(self.seen["HTTP_HOST"], "dcp.example.test")
        self.assertNotIn("HTTP_X_DCP_USER", self.seen)
        self.assertNotIn("HTTP_X_DCP_ROLE", self.seen)
        self.assertNotIn("HTTP_X_FORWARDED_CLIENT_CERT", self.seen)

    def test_rejects_untrusted_peer_and_missing_peer(self):
        for peer in ("198.51.100.10", "", "not-an-ip"):
            result, _ = self.call(REMOTE_ADDR=peer)
            self.assertEqual(result["status"], "403 Forbidden")

    def test_rejects_http_wrong_host_and_forwarded_chains(self):
        cases = (
            {"HTTP_X_FORWARDED_PROTO": "http"},
            {"HTTP_X_FORWARDED_PROTO": "https,http"},
            {"HTTP_X_FORWARDED_HOST": "attacker.example"},
            {"HTTP_X_FORWARDED_HOST": "dcp.example.test,attacker.example"},
            {"HTTP_X_FORWARDED_HOST": ""},
        )
        for case in cases:
            result, _ = self.call(**case)
            self.assertEqual(result["status"], "403 Forbidden")

    def test_requires_valid_explicit_proxy_networks_and_https_origin(self):
        app = lambda environ, start_response: []
        for cidrs in ((), ("invalid",), ("127.0.0.1/24",)):
            with self.assertRaises(ValueError):
                TrustedHTTPSProxyMiddleware(
                    app, trusted_proxy_cidrs=cidrs,
                    public_origin="https://dcp.example.test",
                )
        with self.assertRaises(ValueError):
            TrustedHTTPSProxyMiddleware(
                app, trusted_proxy_cidrs=("127.0.0.1/32",),
                public_origin="http://dcp.example.test",
            )


if __name__ == "__main__":
    unittest.main()
