import json
import tempfile
import unittest
from pathlib import Path

from tools import local_auth_proxy as auth
from tools.reset_owner_password import reset_owner_password


class ResetOwnerPasswordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "owner-auth.json"
        self.old_record = auth.password_record("owner-kept", "previous password 123")
        self.path.write_text(json.dumps(self.old_record), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_reset_preserves_username_and_backs_up_previous_hash(self):
        backup = reset_owner_password(self.path, "new-owner-passphrase", "new-owner-passphrase")
        updated = json.loads(self.path.read_text(encoding="utf-8"))
        previous = json.loads(backup.read_text(encoding="utf-8"))
        self.assertEqual(updated["username"], "owner-kept")
        self.assertTrue(auth.verify_password(updated, "owner-kept", "new-owner-passphrase"))
        self.assertFalse(auth.verify_password(updated, "owner-kept", "previous password 123"))
        self.assertTrue(auth.verify_password(previous, "owner-kept", "previous password 123"))
        self.assertEqual(updated["algorithm"], "pbkdf2_sha256")
        self.assertEqual(updated["rounds"], auth.PBKDF2_ROUNDS)

    def test_rejects_password_shorter_than_fourteen_without_changes(self):
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "at least 14"):
            reset_owner_password(self.path, "x" * 13, "x" * 13)
        self.assertEqual(self.path.read_bytes(), before)

    def test_rejects_mismatch_without_changes(self):
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "do not match"):
            reset_owner_password(self.path, "new-owner-passphrase", "different")
        self.assertEqual(self.path.read_bytes(), before)

    def test_refuses_missing_credential_file(self):
        missing = Path(self.temp.name) / "missing.json"
        with self.assertRaises(FileNotFoundError):
            reset_owner_password(missing, "new-owner-passphrase", "new-owner-passphrase")

    def test_refuses_invalid_credential_file_without_overwriting(self):
        self.path.write_text("{broken", encoding="utf-8")
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            reset_owner_password(self.path, "new-owner-passphrase", "new-owner-passphrase")
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
