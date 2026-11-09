"""Safe extraction tests for immutable GitHub commit archives."""
import io
import stat
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path

from tools.local_runner_agent.checkout import CheckoutError, GitHubCommitCheckout
from tools.local_runner_agent.workspace import WorkspaceManager


class _Response(io.BytesIO):
    headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class _Opener:
    def __init__(self, payload):
        self.payload = payload
        self.request_url = None

    def open(self, request, timeout):
        self.request_url = request.full_url
        return _Response(self.payload)


def archive(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as bundle:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            bundle.writestr(info, data)
    return output.getvalue()


class GitHubCommitCheckoutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = WorkspaceManager(Path(self.temp.name) / "workspaces")
        self.job_id = str(uuid.uuid4())
        self.worker = "checkout-test"
        self.manager.create(self.job_id, self.worker)
        self.sha = "a" * 40

    def tearDown(self):
        self.temp.cleanup()

    def test_extracts_only_one_immutable_commit_archive(self):
        payload = archive([
            ("repo-commit/pubspec.yaml", b"name: fixture_app\n", stat.S_IFREG | 0o644),
            ("repo-commit/lib/main.dart", b"void main() {}\n", stat.S_IFREG | 0o644),
        ])
        checkout = GitHubCommitCheckout(self.manager)
        checkout.opener = _Opener(payload)
        source = checkout.checkout(self.job_id, self.worker, "owner/repo", self.sha)
        self.assertEqual((source / "pubspec.yaml").read_text(), "name: fixture_app\n")
        self.assertEqual((source / "lib/main.dart").read_text(), "void main() {}\n")
        self.assertIn(self.sha, checkout.opener.request_url)

    def test_rejects_path_traversal_and_symlink_entries(self):
        traversal = archive([
            ("repo-commit/../../escape.txt", b"bad", stat.S_IFREG | 0o644),
        ])
        checkout = GitHubCommitCheckout(self.manager)
        checkout.opener = _Opener(traversal)
        with self.assertRaises(CheckoutError):
            checkout.checkout(self.job_id, self.worker, "owner/repo", self.sha)

        # A new Job workspace is required because the previous checkout created source/.
        next_job = str(uuid.uuid4())
        self.manager.create(next_job, self.worker)
        symlink = archive([
            ("repo-commit/pubspec.yaml", b"name: fixture\n", stat.S_IFREG | 0o644),
            ("repo-commit/escape", b"../../outside", stat.S_IFLNK | 0o777),
        ])
        checkout = GitHubCommitCheckout(self.manager)
        checkout.opener = _Opener(symlink)
        with self.assertRaises(CheckoutError):
            checkout.checkout(next_job, self.worker, "owner/repo", self.sha)

    def test_rejects_non_github_repository_and_invalid_sha(self):
        checkout = GitHubCommitCheckout(self.manager)
        with self.assertRaises(CheckoutError):
            checkout.checkout(self.job_id, self.worker, "https://evil.example/repo", self.sha)
        with self.assertRaises(CheckoutError):
            checkout.checkout(self.job_id, self.worker, "owner/repo", "main")


if __name__ == "__main__":
    unittest.main()
