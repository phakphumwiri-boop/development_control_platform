import io
import json
import unittest

from tools.cloud_gateway.key_vault import KeyVaultError, KeyVaultSecretReader


class Response(io.BytesIO):
    def __init__(self, payload, content_type="application/json"):
        super().__init__(payload)
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class Credential:
    def get_token(self, resource):
        if resource != "https://vault.azure.net":
            raise AssertionError("unexpected resource")
        return "managed-identity-token"


class KeyVaultTests(unittest.TestCase):
    def make(self, payload=None, *, content_type="application/json", timeout=5):
        seen = {}
        payload = payload or {"value": "-----BEGIN PRIVATE KEY-----\nexample\n"}
        def opener(request, timeout):
            seen["url"] = request.full_url
            seen["auth"] = request.unredirected_hdrs.get("Authorization")
            seen["timeout"] = timeout
            return Response(json.dumps(payload).encode(), content_type)
        reader = KeyVaultSecretReader(
            "https://sample.vault.azure.net", Credential(), timeout=timeout, opener=opener
        )
        return reader, seen

    def test_reads_secret_with_managed_identity_and_no_redirect_opener(self):
        reader, seen = self.make()
        self.assertIn("BEGIN PRIVATE KEY", reader.get_secret("runner-private-key"))
        self.assertEqual(seen["auth"], "Bearer managed-identity-token")
        self.assertIn("/secrets/runner-private-key?api-version=7.4", seen["url"])
        self.assertEqual(seen["timeout"], 5)

    def test_rejects_invalid_vault_origin_timeout_and_secret_name(self):
        for url in (
            "http://sample.vault.azure.net",
            "https://sample.vault.azure.net.attacker.test",
            "https://user@sample.vault.azure.net",
            "https://sample.vault.azure.net/path",
        ):
            with self.assertRaises(ValueError):
                KeyVaultSecretReader(url, Credential())
        with self.assertRaises(ValueError):
            KeyVaultSecretReader("https://sample.vault.azure.net", Credential(), timeout=0)
        reader, _ = self.make()
        with self.assertRaises(ValueError):
            reader.get_secret("../other-secret")

    def test_rejects_non_json_oversized_and_missing_secret_values(self):
        reader, _ = self.make(content_type="text/plain")
        with self.assertRaises(KeyVaultError):
            reader.get_secret("private-key")
        reader, _ = self.make({"other": "value"})
        with self.assertRaises(KeyVaultError):
            reader.get_secret("private-key")
        def oversized(request, timeout):
            return Response(b"x" * (KeyVaultSecretReader.MAX_RESPONSE_BYTES + 1))
        reader = KeyVaultSecretReader(
            "https://sample.vault.azure.net", Credential(), opener=oversized
        )
        with self.assertRaises(KeyVaultError):
            reader.get_secret("private-key")


if __name__ == "__main__":
    unittest.main()
