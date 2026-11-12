"""Tests for provider-neutral OIDC configuration validation; no network or credentials."""
import unittest

from tools.cloud_gateway.oidc_config import (
    OIDCConfigurationError,
    OIDCProviderConfig,
    oidc_config_from_env,
    validate_oidc_config,
)


class OIDCConfigurationTests(unittest.TestCase):
    def valid(self, **overrides):
        values = {
            "issuer": "https://identity.example.test/tenant/v2.0",
            "client_id": "dcp-test-client",
            "redirect_uri": "https://dcp.example.test/auth/oidc/callback",
            "scopes": ("openid", "profile", "email"),
        }
        values.update(overrides)
        return OIDCProviderConfig(**values)

    def test_accepts_provider_neutral_https_configuration(self):
        config = validate_oidc_config(self.valid())
        self.assertEqual(
            config.discovery_url,
            "https://identity.example.test/tenant/v2.0/.well-known/openid-configuration",
        )
        self.assertEqual(config.scopes[0], "openid")

    def test_rejects_non_https_issuer_and_redirect(self):
        with self.assertRaises(OIDCConfigurationError):
            validate_oidc_config(self.valid(issuer="http://identity.example.test"))
        with self.assertRaises(OIDCConfigurationError):
            validate_oidc_config(self.valid(redirect_uri="http://dcp.example.test/callback"))

    def test_rejects_issuer_credentials_query_and_fragment(self):
        for issuer in (
            "https://user:password@identity.example.test",
            "https://identity.example.test?tenant=unsafe",
            "https://identity.example.test#fragment",
        ):
            with self.subTest(issuer=issuer), self.assertRaises(OIDCConfigurationError):
                validate_oidc_config(self.valid(issuer=issuer))

    def test_requires_openid_scope_and_rejects_duplicates(self):
        with self.assertRaises(OIDCConfigurationError):
            validate_oidc_config(self.valid(scopes=("profile", "email")))
        with self.assertRaises(OIDCConfigurationError):
            validate_oidc_config(self.valid(scopes=("openid", "openid")))

    def test_rejects_invalid_scope_tokens(self):
        with self.assertRaises(OIDCConfigurationError):
            validate_oidc_config(self.valid(scopes=("openid", "bad scope")))

    def test_environment_loader_requires_all_non_secret_settings(self):
        env = {
            "DCP_OIDC_ISSUER": "https://identity.example.test",
            "DCP_OIDC_CLIENT_ID": "dcp-client",
            "DCP_OIDC_REDIRECT_URI": "https://dcp.example.test/auth/oidc/callback",
        }
        config = oidc_config_from_env(env)
        self.assertEqual(config.client_id, "dcp-client")
        with self.assertRaises(OIDCConfigurationError):
            oidc_config_from_env({"DCP_OIDC_ISSUER": "https://identity.example.test"})

    def test_environment_loader_does_not_require_client_secret(self):
        env = {
            "DCP_OIDC_ISSUER": "https://identity.example.test",
            "DCP_OIDC_CLIENT_ID": "dcp-client",
            "DCP_OIDC_REDIRECT_URI": "https://dcp.example.test/auth/oidc/callback",
            "DCP_OIDC_CLIENT_SECRET": "must-not-be-read",
        }
        config = oidc_config_from_env(env)
        self.assertFalse(hasattr(config, "client_secret"))


if __name__ == "__main__":
    unittest.main()
