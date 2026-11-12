"""Tests for durable OIDC transaction consumption and server-side sessions."""
import tempfile
import unittest
from pathlib import Path

from tools.cloud_gateway.oidc_session_store import OIDCSessionError, OIDCSessionStore


class OIDCSessionStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = OIDCSessionStore(str(Path(self.temp.name) / "auth.sqlite"),
                                      session_ttl=3600, transaction_ttl=300)

    def tearDown(self):
        self.temp.cleanup()

    def test_transaction_is_bound_to_browser_and_consumed_once(self):
        self.store.save_transaction("state", "nonce", "verifier", "browser-a", now=1000)
        result = self.store.consume_transaction("state", "browser-a", now=1001)
        self.assertEqual(result, {"nonce": "nonce", "code_verifier": "verifier"})
        with self.assertRaises(OIDCSessionError):
            self.store.consume_transaction("state", "browser-a", now=1002)

    def test_transaction_rejects_wrong_browser_and_expiry(self):
        self.store.save_transaction("state-a", "nonce", "verifier", "browser-a", now=1000)
        with self.assertRaises(OIDCSessionError):
            self.store.consume_transaction("state-a", "browser-b", now=1001)
        self.store.save_transaction("state-b", "nonce", "verifier", "browser-a", now=1000)
        with self.assertRaises(OIDCSessionError):
            self.store.consume_transaction("state-b", "browser-a", now=1301)

    def test_session_lookup_csrf_rotation_and_logout_revocation(self):
        old, session = self.store.create_session("subject-123", "operator", now=1000)
        self.assertTrue(self.store.csrf_valid(old, session["csrf_token"], now=1001))
        self.assertFalse(self.store.csrf_valid(old, "attacker-token", now=1001))
        new, rotated = self.store.rotate_session(old, now=1002)
        self.assertIsNone(self.store.get_session(old, now=1003))
        self.assertEqual(self.store.get_session(new, now=1003)["subject"], "subject-123")
        self.assertTrue(self.store.revoke_session(new, now=1004))
        self.assertIsNone(self.store.get_session(new, now=1005))

    def test_expired_session_is_not_authenticated(self):
        session_id, _ = self.store.create_session("subject-123", "owner", now=1000)
        self.assertIsNone(self.store.get_session(session_id, now=4600))

    def test_rejects_unverified_role_and_invalid_subject(self):
        with self.assertRaises(OIDCSessionError):
            self.store.create_session("subject", "admin", now=1000)
        with self.assertRaises(OIDCSessionError):
            self.store.create_session("", "owner", now=1000)


if __name__ == "__main__":
    unittest.main()
