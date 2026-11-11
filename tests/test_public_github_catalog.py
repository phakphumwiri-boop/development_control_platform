"""Tests for the allowlisted, read-only public GitHub repository runtime."""
import base64
import unittest
from unittest.mock import Mock

from tools.cloud_gateway.public_github import (
    PublicGitHubError,
    PublicGitHubRepositoryCatalog,
)


class PublicGitHubRepositoryCatalogTests(unittest.TestCase):
    def setUp(self):
        self.catalog = PublicGitHubRepositoryCatalog(["owner/mobile-app"])

    def test_rejects_invalid_or_duplicate_allowlist(self):
        for allowed in (
            ["../repo"],
            ["owner/repo", "OWNER/REPO"],
            ["owner/repo"] * 21,
            "owner/repo",
        ):
            with self.subTest(allowed=allowed):
                with self.assertRaises(ValueError):
                    PublicGitHubRepositoryCatalog(allowed)

    def test_rejects_repository_outside_allowlist_before_network(self):
        self.catalog._request = Mock()
        self.assertFalse(self.catalog.is_repository_accessible("other/repo"))
        with self.assertRaises(PermissionError):
            self.catalog.list_repository_refs("other/repo")
        self.catalog._request.assert_not_called()

    def test_lists_only_public_allowlisted_repository(self):
        self.catalog._request = Mock(return_value={
            "full_name": "owner/mobile-app",
            "private": False,
            "default_branch": "main",
            "html_url": "https://github.com/owner/mobile-app",
            "description": "Flutter application",
        })
        rows = self.catalog.list_repositories()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["full_name"], "owner/mobile-app")
        self.assertFalse(rows[0]["private"])

    def test_private_or_missing_repository_is_not_exposed(self):
        self.catalog._request = Mock(side_effect=PublicGitHubError("not found", 404))
        self.assertEqual(self.catalog.list_repositories(), [])
        self.assertFalse(self.catalog.is_repository_accessible("owner/mobile-app"))

    def test_lists_branch_and_tag_refs_as_immutable_shas(self):
        sha = "a" * 40
        self.catalog._request = Mock(return_value=[
            {"name": "main", "commit": {"sha": sha}},
        ])
        refs = self.catalog.list_repository_refs("owner/mobile-app", "branches")
        self.assertEqual(refs, [{"name": "main", "commit_sha": sha}])
        with self.assertRaises(ValueError):
            self.catalog.list_repository_refs("owner/mobile-app", "pulls")

    def test_resolves_only_the_exact_full_commit_sha(self):
        sha = "b" * 40
        self.catalog._request = Mock(return_value={"sha": sha})
        self.assertEqual(
            self.catalog.resolve_repository_commit("owner/mobile-app", sha),
            {"commit_sha": sha},
        )
        with self.assertRaises(ValueError):
            self.catalog.resolve_repository_commit("owner/mobile-app", "abc123")

    def test_inspects_flutter_project_from_bounded_git_tree_and_pubspec(self):
        commit_sha = "c" * 40
        tree_sha = "d" * 40
        pubspec = (
            "name: sample_app\n"
            "dependencies:\n"
            "  flutter:\n"
            "    sdk: flutter\n"
        )
        encoded = base64.b64encode(pubspec.encode("utf-8")).decode("ascii")
        self.catalog._request = Mock(side_effect=[
            {"sha": commit_sha, "commit": {"tree": {"sha": tree_sha}}},
            {
                "truncated": False,
                "tree": [
                    {"path": "pubspec.yaml", "type": "blob", "mode": "100644"},
                    {"path": "macos/Runner.xcodeproj/project.pbxproj", "type": "blob", "mode": "100644"},
                    {"path": "macos/Runner/Info.plist", "type": "blob", "mode": "100644"},
                    {"path": "lib/main.dart", "type": "blob", "mode": "100644"},
                ],
            },
            {"encoding": "base64", "size": len(pubspec.encode("utf-8")), "content": encoded},
        ])
        result = self.catalog.inspect_repository_project("owner/mobile-app", commit_sha)
        self.assertEqual(result["commit_sha"], commit_sha)
        self.assertEqual(result["status"], "target_detected")
        self.assertTrue(result["flutter"]["detected"])
        self.assertTrue(result["flutter"]["macos_supported"])
        self.assertIn("flutter", result["project_types"])

    def test_rejects_commit_response_for_another_sha(self):
        self.catalog._request = Mock(return_value={"sha": "e" * 40})
        with self.assertRaises(PublicGitHubError):
            self.catalog.resolve_repository_commit("owner/mobile-app", "f" * 40)


if __name__ == "__main__":
    unittest.main()
