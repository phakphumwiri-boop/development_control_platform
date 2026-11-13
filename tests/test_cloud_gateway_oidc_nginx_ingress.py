"""Static contract tests for the reviewed Nginx OIDC ingress template."""
from pathlib import Path
import unittest


class OIDCNginxIngressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Path("deploy/nginx/oidc-ingress.conf.example").read_text(encoding="utf-8")

    def test_rejects_unknown_hosts_and_uses_https_only_for_oidc(self):
        self.assertIn("listen 80 default_server;", self.config)
        self.assertIn("return 444;", self.config)
        self.assertIn("ssl_reject_handshake on;", self.config)
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3;", self.config)
        self.assertIn("return 308 https://dcp.example.invalid$request_uri;", self.config)

    def test_oidc_proxy_is_private_and_has_explicit_header_allowlist(self):
        self.assertIn("proxy_pass http://127.0.0.1:8080;", self.config)
        self.assertIn("proxy_pass_request_headers off;", self.config)
        self.assertIn("proxy_pass_request_body on;", self.config)
        self.assertIn("proxy_set_header Host dcp.example.invalid;", self.config)
        self.assertIn("proxy_set_header X-Forwarded-Host dcp.example.invalid;", self.config)
        self.assertIn("proxy_set_header X-Forwarded-Proto https;", self.config)
        self.assertIn("proxy_set_header Cookie $http_cookie;", self.config)
        self.assertIn("proxy_set_header Origin $http_origin;", self.config)
        self.assertIn("proxy_set_header X-CSRF-Token $http_x_csrf_token;", self.config)
        self.assertNotIn("$http_x_dcp_", self.config.lower())
        self.assertNotIn("proxy_set_header X-DCP-", self.config)

    def test_proxy_has_bounded_timeouts_body_and_no_automatic_retries(self):
        self.assertIn("client_max_body_size 8k;", self.config)
        self.assertIn("proxy_connect_timeout 3s;", self.config)
        self.assertIn("proxy_send_timeout 10s;", self.config)
        self.assertIn("proxy_read_timeout 10s;", self.config)
        self.assertIn("proxy_next_upstream off;", self.config)


if __name__ == "__main__":
    unittest.main()
