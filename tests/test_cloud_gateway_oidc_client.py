"""Offline OIDC discovery, PKCE and JWT verification regression tests."""
import base64
import hashlib
import json
import time
import unittest
from urllib.parse import parse_qs, urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from tools.cloud_gateway.oidc_client import (
    OIDCError, OIDCMetadata, OIDCProvider, authorization_url,
    exchange_authorization_code, new_pkce_transaction, verify_id_token,
)


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def jwt(private_key, header, claims, algorithm="RS256"):
    left = b64(json.dumps(header, separators=(",", ":")).encode())
    right = b64(json.dumps(claims, separators=(",", ":")).encode())
    message = (left + "." + right).encode()
    if algorithm == "RS256":
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    else:
        der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return left + "." + right + "." + b64(signature)


def jwk_for(key, kid="test-key"):
    numbers = key.public_key().public_numbers()
    if hasattr(numbers, "n"):
        return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
                "n": b64(numbers.n.to_bytes((numbers.n.bit_length()+7)//8, "big")),
                "e": b64(numbers.e.to_bytes((numbers.e.bit_length()+7)//8, "big"))}
    return {"kty": "EC", "kid": kid, "use": "sig", "alg": "ES256", "crv": "P-256",
            "x": b64(numbers.x.to_bytes(32, "big")), "y": b64(numbers.y.to_bytes(32, "big"))}


class OIDCClientTests(unittest.TestCase):
    issuer = "https://issuer.example.test/tenant"
    client_id = "dcp-client"
    nonce = "nonce-value"

    def setUp(self):
        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec_key = ec.generate_private_key(ec.SECP256R1())
        self.now = int(time.time())
        self.claims = {"iss": self.issuer, "aud": self.client_id, "sub": "subject-123",
                       "exp": self.now + 300, "iat": self.now, "nonce": self.nonce}
        self.documents = {
            self.issuer + "/.well-known/openid-configuration": {
                "issuer": self.issuer, "authorization_endpoint": "https://issuer.example.test/authorize",
                "token_endpoint": "https://issuer.example.test/token",
                "jwks_uri": "https://issuer.example.test/keys",
                "response_types_supported": ["code"], "code_challenge_methods_supported": ["S256"]},
            "https://issuer.example.test/keys": {"keys": [jwk_for(self.rsa_key)]},
        }
        self.provider = OIDCProvider(self.issuer, lambda url: self.documents[url])

    def test_discovery_requires_exact_issuer_and_pkce_s256(self):
        self.assertEqual(self.provider.discover().issuer, self.issuer)
        bad = dict(self.documents[self.issuer + "/.well-known/openid-configuration"])
        bad["issuer"] = self.issuer + "/"
        provider = OIDCProvider(self.issuer, lambda _: bad)
        with self.assertRaises(OIDCError):
            provider.discover()
        bad["issuer"] = self.issuer
        bad["code_challenge_methods_supported"] = ["plain"]
        with self.assertRaises(OIDCError):
            OIDCProvider(self.issuer, lambda _: bad).discover()

    def test_rejects_insecure_provider_endpoints(self):
        bad = dict(self.documents[self.issuer + "/.well-known/openid-configuration"])
        bad["jwks_uri"] = "http://attacker.example/keys"
        with self.assertRaises(OIDCError):
            OIDCProvider(self.issuer, lambda _: bad).discover()

    def test_pkce_url_contains_s256_state_nonce_and_verifier_challenge(self):
        tx = new_pkce_transaction(self.now)
        metadata = self.provider.discover()
        query = parse_qs(urlsplit(authorization_url(
            metadata, self.client_id, "https://dcp.example.test/callback", tx)).query)
        self.assertEqual(query["state"], [tx.state])
        self.assertEqual(query["nonce"], [tx.nonce])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["code_challenge"], [tx.code_challenge])
        self.assertNotIn(tx.code_verifier, str(query))

    def test_verifies_rs256_token_and_required_claims(self):
        token = jwt(self.rsa_key, {"alg": "RS256", "kid": "test-key", "typ": "JWT"}, self.claims)
        self.assertEqual(verify_id_token(token, self.provider, self.client_id, self.nonce, self.now)["sub"],
                         "subject-123")

    def test_verifies_es256_token(self):
        self.documents["https://issuer.example.test/keys"] = {"keys": [jwk_for(self.ec_key)]}
        token = jwt(self.ec_key, {"alg": "ES256", "kid": "test-key"}, self.claims, "ES256")
        self.assertEqual(verify_id_token(token, self.provider, self.client_id, self.nonce, self.now)["sub"],
                         "subject-123")

    def test_rejects_signature_tampering_and_alg_none(self):
        token = jwt(self.rsa_key, {"alg": "RS256", "kid": "test-key"}, self.claims)
        parts = token.split(".")
        with self.assertRaises(OIDCError):
            verify_id_token(parts[0] + "." + b64(b'{"iss":"attacker"}') + "." + parts[2],
                            self.provider, self.client_id, self.nonce, self.now)
        with self.assertRaises(OIDCError):
            verify_id_token(jwt(self.rsa_key, {"alg": "none", "kid": "test-key"}, self.claims),
                            self.provider, self.client_id, self.nonce, self.now)

    def test_rejects_issuer_audience_nonce_expiry_and_azp_mismatch(self):
        mutations = [
            {"iss": "https://attacker.example"},
            {"aud": "other-client"},
            {"nonce": "wrong"},
            {"exp": self.now - 100},
            {"aud": [self.client_id, "other"], "azp": "other"},
        ]
        for mutation in mutations:
            claims = dict(self.claims, **mutation)
            token = jwt(self.rsa_key, {"alg": "RS256", "kid": "test-key"}, claims)
            with self.subTest(mutation=mutation), self.assertRaises(OIDCError):
                verify_id_token(token, self.provider, self.client_id, self.nonce, self.now)

    def test_rejects_duplicate_matching_kids(self):
        self.documents["https://issuer.example.test/keys"] = {
            "keys": [jwk_for(self.rsa_key), jwk_for(self.rsa_key, "test-key")]}
        token = jwt(self.rsa_key, {"alg": "RS256", "kid": "test-key"}, self.claims)
        with self.assertRaises(OIDCError):
            verify_id_token(token, self.provider, self.client_id, self.nonce, self.now)

    def test_exchange_uses_pkce_and_does_not_require_client_secret(self):
        tx = new_pkce_transaction(self.now)
        seen = {}
        def post(url, form):
            seen.update(url=url, form=form)
            return {"id_token": "signed.id.token", "access_token": "server-only"}
        result = exchange_authorization_code(self.provider.discover(), self.client_id,
            "https://dcp.example.test/callback", "auth-code", tx, post)
        self.assertEqual(result["id_token"], "signed.id.token")
        self.assertEqual(seen["form"]["code_verifier"], tx.code_verifier)
        self.assertNotIn("client_secret", seen["form"])


if __name__ == "__main__":
    unittest.main()
