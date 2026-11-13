"""Tests for fail-closed production OIDC WSGI composition."""
import tempfile
import unittest
from pathlib import Path

from tools.cloud_gateway.oidc_config import OIDCConfigurationError
from tools.cloud_gateway.oidc_deployment import create_oidc_wsgi_app_from_env
from tools.cloud_gateway.oidc_wsgi import OIDCWSGIApplication


class OIDCDeploymentFactoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = {
            "DCP_OIDC_ISSUER": "https://idp.example.test/tenant",
            "DCP_OIDC_CLIENT_ID": "dcp-client",
            "DCP_OIDC_REDIRECT_URI": "https://dcp.example.test/api/auth/oidc/callback",
            "DCP_PUBLIC_ORIGIN": "https://dcp.example.test",
            "DCP_OIDC_SESSION_DB_PATH": str(Path(self.temp.name) / "oidc.sqlite"),
            "DCP_TRUSTED_PROXY_CIDRS": "127.0.0.1/32",
            "DCP_OIDC_OWNER_GROUPS": "owners,owners-secondary",
            "DCP_OIDC_OPERATOR_GROUPS": "operators",
        }
        self.fetch_json = lambda url: (_ for _ in ()).throw(AssertionError("network must not run during composition"))
        self.post_form = lambda url, form: (_ for _ in ()).throw(AssertionError("token exchange must not run during composition"))

    def tearDown(self):
        self.temp.cleanup()

    def build(self, env=None):
        return create_oidc_wsgi_app_from_env(
            self.env if env is None else env,
            fetch_json=self.fetch_json,
            post_form=self.post_form,
        )

    def test_builds_wsgi_app_without_network_or_secret_access(self):
        app = self.build()
        self.assertIsInstance(app, OIDCWSGIApplication)
        self.assertTrue(Path(self.env["DCP_OIDC_SESSION_DB_PATH"]).is_file())
        self.assertFalse(hasattr(app.auth.config, "client_secret"))

    def test_requires_explicit_durable_session_database(self):
        env = dict(self.env)
        del env["DCP_OIDC_SESSION_DB_PATH"]
        with self.assertRaises(OIDCConfigurationError):
            self.build(env)
        env = dict(self.env, DCP_OIDC_SESSION_DB_PATH=":memory:")
        with self.assertRaises(OIDCConfigurationError):
            self.build(env)

    def test_requires_explicit_trusted_proxy_allowlist(self):
        env = dict(self.env)
        del env["DCP_TRUSTED_PROXY_CIDRS"]
        with self.assertRaises(OIDCConfigurationError):
            self.build(env)
        env = dict(self.env, DCP_TRUSTED_PROXY_CIDRS="127.0.0.1/32,")
        with self.assertRaises(OIDCConfigurationError):
            self.build(env)
        env = dict(self.env, DCP_TRUSTED_PROXY_CIDRS="invalid")
        with self.assertRaises(OIDCConfigurationError):
            self.build(env)

    def test_requires_distinct_explicit_role_groups(self):
        env = dict(self.env)
        del env["DCP_OIDC_OWNER_GROUPS"]
        with self.assertRaises(OIDCConfigurationError):
            self.build(env)
        env = dict(self.env, DCP_OIDC_OPERATOR_GROUPS="owners")
        with self.assertRaises(OIDCConfigurationError):
            self.build(env)

    def test_rejects_invalid_session_ttl_and_origin_mismatch(self):
        env = dict(self.env, DCP_OIDC_SESSION_TTL_SECONDS="12")
        with self.assertRaises(OIDCConfigurationError):
            self.build(env)
        env = dict(self.env, DCP_PUBLIC_ORIGIN="https://other.example.test")
        with self.assertRaises(ValueError):
            self.build(env)

    def test_requires_explicit_transport_dependencies(self):
        with self.assertRaises(OIDCConfigurationError):
            create_oidc_wsgi_app_from_env(self.env, fetch_json=None, post_form=self.post_form)
        with self.assertRaises(OIDCConfigurationError):
            create_oidc_wsgi_app_from_env(self.env, fetch_json=self.fetch_json, post_form=None)


if __name__ == "__main__":
    unittest.main()
