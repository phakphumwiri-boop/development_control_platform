"""Mock-only GitHub App bootstrap tests; no GitHub or cloud calls."""
import base64
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tools.cloud_gateway.github_app import GitHubAppError, GitHubAppRunnerBootstrap, GitHubRunnerOnlineChecker


def encoded_part(part):
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


class GitHubAppBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    def make(self, opener=None):
        return GitHubAppRunnerBootstrap(
            "123456", 987654, self.pem,
            ["phakphum12345/generated-A4-pdf"],
            clock=lambda: 1_800_000_000,
            opener=opener,
        )

    def test_jwt_is_rs256_and_short_lived(self):
        jwt = self.make()._app_jwt()
        header, claims, signature = jwt.split(".")
        self.assertEqual(encoded_part(header), {"alg": "RS256", "typ": "JWT"})
        body = encoded_part(claims)
        self.assertEqual(body["iss"], "123456")
        self.assertEqual(body["exp"] - body["iat"], 570)
        self.assertTrue(signature)

    def test_rejects_unallowlisted_repository_before_network(self):
        app = self.make()
        with self.assertRaises(GitHubAppError):
            app.create_registration_token("attacker/repo")

    def test_rejects_invalid_app_configuration(self):
        with self.assertRaises(ValueError):
            GitHubAppRunnerBootstrap("not-numeric", 1, self.pem, ["owner/repo"])
        with self.assertRaises(ValueError):
            GitHubAppRunnerBootstrap("123", 0, self.pem, ["owner/repo"])
        with self.assertRaises(ValueError):
            GitHubAppRunnerBootstrap("123", 1, self.pem, ["owner/repo", "owner/repo"])

    def test_scopes_installation_and_registration_to_allowlisted_repo(self):
        app = self.make()
        future = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
        registration_expiry = (datetime.now(timezone.utc) + timedelta(minutes=50)).isoformat()
        responses = [
            {"token": "installation-secret", "expires_at": future, "permissions": {"administration": "write"}},
            {"token": "registration-secret", "expires_at": registration_expiry},
        ]
        seen = []

        def request(method, path, token, payload=None):
            seen.append((method, path, token, payload))
            return responses.pop(0)

        app._request = request
        credential = app.create_registration_token("phakphum12345/generated-A4-pdf")
        self.assertEqual(credential.token, "registration-secret")
        self.assertNotIn("registration-secret", repr(credential))
        self.assertEqual(seen[0][1], "/app/installations/987654/access_tokens")
        self.assertEqual(seen[0][3], {"repositories": ["phakphum12345/generated-A4-pdf"], "permissions": {"administration": "write"}})
        self.assertEqual(seen[1][1], "/repos/phakphum12345/generated-A4-pdf/actions/runners/registration-token")
        self.assertEqual(seen[1][2], "installation-secret")

    def test_requires_administration_write_permission(self):
        app = self.make()
        app._request = lambda *args, **kwargs: {
            "token": "installation-secret",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(),
            "permissions": {"administration": "read"},
        }
        with self.assertRaises(GitHubAppError):
            app.create_registration_token("phakphum12345/generated-A4-pdf")

    def test_rejects_expired_registration_token(self):
        app = self.make()
        app._request = lambda method, path, token, payload=None: (
            {"token": "installation-secret",
             "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(),
             "permissions": {"administration": "write"}}
            if path.startswith("/app/") else
            {"token": "registration-secret",
             "expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()}
        )
        with self.assertRaises(GitHubAppError):
            app.create_registration_token("phakphum12345/generated-A4-pdf")

    def test_bearer_token_is_marked_unredirected(self):
        captured = []
        class Response:
            headers = {"Content-Type": "application/json"}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size): return b"{}"
        def opener(request, timeout):
            captured.append(request)
            return Response()
        self.make(opener=opener)._request("GET", "/app/installations/1", "jwt-secret")
        request = captured[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer jwt-secret")
        self.assertTrue(any(key.lower() == "authorization" for key in request.unredirected_hdrs))

    def test_request_rejects_redirects_without_following_them(self):
        from urllib.error import HTTPError
        calls = []
        def opener(request, timeout):
            calls.append(request.full_url)
            raise HTTPError(request.full_url, 302, "redirect", {}, None)
        app = self.make(opener=opener)
        with self.assertRaisesRegex(GitHubAppError, "HTTP 302"):
            app._request("POST", "/app/installations/1/access_tokens", "jwt-secret")
        self.assertEqual(len(calls), 1)
        self.assertIn("api.github.com", calls[0])

    def test_request_rejects_oversized_and_non_json_responses(self):
        class Response:
            def __init__(self, payload, content_type):
                self.payload = payload
                self.headers = {"Content-Type": content_type}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, size): return self.payload[:size]
        for response in (
            Response(b"x" * (GitHubAppRunnerBootstrap.MAX_RESPONSE_BYTES + 1), "application/json"),
            Response(b"{}", "text/plain"),
        ):
            app = self.make(opener=lambda *a, response=response, **k: response)
            with self.assertRaises(GitHubAppError):
                app._request("GET", "/app/installations/1", "jwt-secret")

    def test_http_error_is_sanitized(self):
        from urllib.error import HTTPError
        app = self.make(opener=lambda *a, **k: (_ for _ in ()).throw(
            HTTPError("url", 403, "denied", {}, None)
        ))
        with self.assertRaisesRegex(GitHubAppError, "HTTP 403") as caught:
            app._request("POST", "/app/installations/1/access_tokens", "jwt")
        self.assertNotIn("jwt", str(caught.exception))


    def test_platform_online_checker_uses_expected_os_labels(self):
        class StubApp:
            def __init__(self):
                self.args = None
            def is_runner_online(self, repository, runner_name, labels):
                self.args = (repository, runner_name, tuple(labels))
                return True
        stub = StubApp()
        checker = GitHubRunnerOnlineChecker(stub)
        self.assertTrue(checker("dcp-123-abcdef12", "phakphum12345/generated-A4-pdf", "windows"))
        self.assertEqual(stub.args[2], ("self-hosted", "Windows", "X64", "dcp-cloud-windows"))
        self.assertFalse(checker("dcp-123-abcdef12", "phakphum12345/generated-A4-pdf", "unknown"))

    def test_runner_inventory_paginates_before_deciding_runner_is_absent(self):
        app = self.make()
        calls = []
        def request(method, path, token, payload=None):
            calls.append(path)
            if path.startswith("/app/"):
                return {
                    "token": "read-installation-token",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(),
                    "permissions": {"administration": "read"},
                }
            if path.endswith("page=1"):
                return {"runners": [
                    {"id": i + 1, "name": "other-" + str(i), "status": "offline"}
                    for i in range(100)
                ]}
            return {"runners": [{
                "id": 999, "name": "dcp-123-abcdef12", "status": "offline",
                "labels": [{"name": "self-hosted"}],
            }]}
        app._request = request
        runner = app.find_runner("phakphum12345/generated-A4-pdf", "dcp-123-abcdef12")
        self.assertEqual(runner["id"], 999)
        self.assertEqual(len([path for path in calls if "actions/runners?" in path]), 2)

    def test_runner_online_requires_exact_name_status_and_labels(self):
        app = self.make()
        calls = []
        def request(method, path, token, payload=None):
            calls.append((method, path, payload))
            if path.startswith("/app/"):
                return {
                    "token": "read-installation-token",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(),
                    "permissions": {"administration": "read"},
                }
            return {"runners": [{
                "id": 42,
                "name": "dcp-123-abcdef12",
                "status": "online",
                "labels": [{"name": "self-hosted"}, {"name": "Linux"}, {"name": "X64"}],
            }]}
        app._request = request
        self.assertTrue(app.is_runner_online(
            "phakphum12345/generated-A4-pdf",
            "dcp-123-abcdef12",
            ["self-hosted", "Linux", "X64"],
        ))
        self.assertEqual(calls[0][2], {
            "repositories": ["phakphum12345/generated-A4-pdf"],
            "permissions": {"administration": "read"},
        })
        self.assertEqual(calls[1][1], "/repos/phakphum12345/generated-A4-pdf/actions/runners?per_page=100&page=1")

    def test_runner_online_fails_closed_for_missing_runner(self):
        app = self.make()
        token_response = {
            "token": "read-installation-token",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(),
            "permissions": {"administration": "read"},
        }
        app._request = lambda method, path, token, payload=None: (
            token_response if path.startswith("/app/") else {"runners": []}
        )
        self.assertFalse(app.is_runner_online(
            "phakphum12345/generated-A4-pdf", "dcp-123-abcdef12", ["Linux"]
        ))

    def test_remove_runner_uses_scoped_admin_write_token_after_offline_check(self):
        app = self.make()
        calls = []
        def request(method, path, token, payload=None):
            calls.append((method, path, payload))
            if path.startswith("/app/"):
                permission = "read" if sum(1 for call in calls if call[1].startswith("/app/")) == 1 else "write"
                return {
                    "token": permission + "-installation-token",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(),
                    "permissions": {"administration": permission},
                }
            if method == "GET":
                return {"runners": [{"id": 42, "name": "dcp-123-abcdef12", "status": "offline"}]}
            return {}
        app._request = request
        self.assertTrue(app.remove_runner("phakphum12345/generated-A4-pdf", 42))
        self.assertEqual(calls[1][0], "GET")
        self.assertEqual(calls[2][1], "/app/installations/987654/access_tokens")
        self.assertEqual(calls[3][0], "DELETE")
        self.assertEqual(calls[3][1], "/repos/phakphum12345/generated-A4-pdf/actions/runners/42")
        with self.assertRaises(GitHubAppError):
            app.remove_runner("phakphum12345/generated-A4-pdf", True)

    def test_remove_runner_refuses_online_runner(self):
        app = self.make()
        def request(method, path, token, payload=None):
            if path.startswith("/app/"):
                return {
                    "token": "read-installation-token",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(),
                    "permissions": {"administration": "read"},
                }
            return {"runners": [{"id": 42, "name": "dcp-123-abcdef12", "status": "online"}]}
        app._request = request
        with self.assertRaisesRegex(GitHubAppError, "not confirmed offline"):
            app.remove_runner("phakphum12345/generated-A4-pdf", 42)


    def test_catalog_token_is_limited_to_metadata_read(self):
        app = GitHubAppRunnerBootstrap("123456", 987654, self.pem, [])
        app._app_jwt = lambda: "app-jwt"
        calls = []

        def request(method, path, token, payload=None):
            calls.append((method, path, token, payload))
            return {
                "token": "catalog-token",
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(),
                "permissions": {"metadata": "read"},
            }

        app._request = request
        self.assertEqual(app._installation_catalog_token(), "catalog-token")
        self.assertEqual(calls[0][0:3], (
            "POST", "/app/installations/987654/access_tokens", "app-jwt"
        ))
        self.assertEqual(calls[0][3], {"permissions": {"metadata": "read"}})

    def test_dynamic_installation_catalog_lists_only_installed_repositories(self):
        app = GitHubAppRunnerBootstrap(
            "123456", 987654, self.pem, [],
            clock=lambda: 1_800_000_000,
        )
        app._installation_catalog_token = lambda: "catalog-token"
        calls = []

        def request(method, path, token, payload=None):
            calls.append((method, path, token))
            return {
                "total_count": 2,
                "repositories": [
                    {
                        "full_name": "example/private-app",
                        "private": True,
                        "default_branch": "main",
                        "permissions": {"admin": True, "push": True, "metadata": "read"},
                        "html_url": "https://github.com/example/private-app",
                    },
                    {
                        "full_name": "example/public-app",
                        "private": False,
                        "default_branch": "trunk",
                        "permissions": {"pull": True, "push": False},
                    },
                ],
            }

        app._request = request
        catalog = app.list_installation_repositories()
        self.assertEqual([item["full_name"] for item in catalog], [
            "example/private-app", "example/public-app"
        ])
        self.assertTrue(catalog[0]["private"])
        self.assertEqual(catalog[0]["permissions"], {"admin": True, "push": True})
        self.assertNotIn("html_url", catalog[0])
        self.assertTrue(app.is_repository_accessible("example/private-app"))
        self.assertFalse(app.is_repository_accessible("example/not-installed"))
        self.assertEqual(len(calls), 1, "catalog should be cached for its short TTL")

    def test_dynamic_installation_catalog_fails_closed_on_malformed_repository(self):
        app = GitHubAppRunnerBootstrap(
            "123456", 987654, self.pem, [],
            clock=lambda: 1_800_000_000,
        )
        app._installation_catalog_token = lambda: "catalog-token"
        app._request = lambda *args, **kwargs: {
            "total_count": 1,
            "repositories": [{"full_name": "invalid-name", "private": True}],
        }
        with self.assertRaisesRegex(GitHubAppError, "malformed"):
            app.list_installation_repositories()

    def test_dynamic_registration_refuses_repository_outside_installation(self):
        app = GitHubAppRunnerBootstrap(
            "123456", 987654, self.pem, [],
            clock=lambda: 1_800_000_000,
        )
        app._installation_catalog_token = lambda: "catalog-token"
        app._request = lambda method, path, token, payload=None: {
            "total_count": 1,
            "repositories": [{
                "full_name": "example/installed",
                "private": True,
                "default_branch": "main",
            }],
        }
        with self.assertRaisesRegex(GitHubAppError, "not accessible"):
            app.create_registration_token("attacker/repo")


    def test_request_accepts_repository_catalog_response_over_64_kib(self):
        app = self.make()

        class Response:
            def __init__(self, body):
                self.body = body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, limit):
                return self.body[:limit]

        body = json.dumps({"repositories": [], "padding": "x" * 70000}).encode()
        app.opener = lambda request, timeout: Response(body)
        result = app._request("GET", "/installation/repositories", "catalog-token")
        self.assertEqual(result["repositories"], [])
        self.assertGreater(len(body), 65536)

    def test_request_rejects_response_over_configured_limit(self):
        app = self.make()

        class Response:
            def __init__(self, body):
                self.body = body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, limit):
                return self.body[:limit]

        body = json.dumps({"padding": "x" * (app.MAX_RESPONSE_BYTES + 1)}).encode()
        app.opener = lambda request, timeout: Response(body)
        with self.assertRaisesRegex(GitHubAppError, "size limit"):
            app._request("GET", "/installation/repositories", "catalog-token")


    def test_request_accepts_github_array_response(self):
        app = self.make()
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit): return b'[{"name":"main"}]'
        app.opener = lambda request, timeout: Response()
        self.assertEqual(app._request("GET", "/repos/example/repo/branches", "token"), [{"name": "main"}])

    def test_resolve_repository_commit_rejects_mismatched_response_sha(self):
        app = self.make()
        future = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
        def request(method, path, token, payload=None):
            if method == "POST":
                return {"token": "contents-token", "expires_at": future,
                        "permissions": {"contents": "read"}}
            return {"sha": "c" * 40}
        app._app_jwt = lambda: "app-jwt"
        app._request = request
        with self.assertRaisesRegex(GitHubAppError, "did not match"):
            app.resolve_repository_commit("phakphum12345/generated-A4-pdf", "b" * 40)

    def test_repository_branch_catalog_uses_scoped_contents_read_token(self):
        app = self.make()
        calls = []
        future = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
        def request(method, path, token, payload=None):
            calls.append((method, path, token, payload))
            if method == "POST":
                return {
                    "token": "contents-read-token",
                    "expires_at": future,
                    "permissions": {"contents": "read"},
                }
            return [{
                "name": "feature/example",
                "commit": {"sha": "A" * 40},
            }]
        app._app_jwt = lambda: "app-jwt"
        app._request = request
        refs = app.list_repository_refs("phakphum12345/generated-A4-pdf", "branches")
        self.assertEqual(refs, [{"name": "feature/example", "commit_sha": "a" * 40}])
        self.assertEqual(calls[0][3], {
            "repositories": ["phakphum12345/generated-A4-pdf"],
            "permissions": {"contents": "read"},
        })
        self.assertIn("/branches?per_page=100&page=1", calls[1][1])
        self.assertEqual(calls[1][2], "contents-read-token")

    def test_repository_ref_catalog_paginates_across_pages(self):
        app = self.make()
        future = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
        calls = []
        def request(method, path, token, payload=None):
            calls.append(path)
            if method == "POST":
                return {"token": "contents-token", "expires_at": future,
                        "permissions": {"contents": "read"}}
            if path.endswith("page=1"):
                return [{"name": "branch-" + str(i), "commit": {"sha": ("%040x" % (i + 1))}}
                        for i in range(100)]
            return [{"name": "branch-100", "commit": {"sha": "f" * 40}}]
        app._app_jwt = lambda: "app-jwt"
        app._request = request
        refs = app.list_repository_refs("phakphum12345/generated-A4-pdf", "branches")
        self.assertEqual(len(refs), 101)
        self.assertEqual(len([path for path in calls if "branches?" in path]), 2)

    def test_repository_ref_catalog_rejects_duplicate_names(self):
        app = self.make()
        future = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
        def request(method, path, token, payload=None):
            if method == "POST":
                return {"token": "contents-token", "expires_at": future,
                        "permissions": {"contents": "read"}}
            return [
                {"name": "main", "commit": {"sha": "a" * 40}},
                {"name": "main", "commit": {"sha": "b" * 40}},
            ]
        app._app_jwt = lambda: "app-jwt"
        app._request = request
        with self.assertRaisesRegex(GitHubAppError, "duplicates"):
            app.list_repository_refs("phakphum12345/generated-A4-pdf", "branches")

    def test_repository_project_inspection_detects_flutter_macos_runner(self):
        app = self.make()
        app.is_repository_accessible = lambda repository, refresh=False: repository == "example/flutter-app"
        future = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
        sha = "e" * 40
        tree_sha = "f" * 40
        calls = []
        def request(method, path, token, payload=None):
            calls.append((method, path, token, payload))
            if method == "POST":
                return {"token": "contents-token", "expires_at": future,
                        "permissions": {"contents": "read"}}
            if "/commits/" in path:
                return {"sha": sha, "commit": {"tree": {"sha": tree_sha}}}
            if "/contents/" in path:
                raw = b"dependencies:\n  flutter:\n    sdk: flutter\n"
                return {"encoding": "base64", "content": base64.b64encode(raw).decode(), "size": len(raw)}
            return {"truncated": False, "tree": [
                {"path": "pubspec.yaml", "type": "blob", "mode": "100644"},
                {"path": "lib/main.dart", "type": "blob", "mode": "100644"},
                {"path": "macos/Runner.xcodeproj/project.pbxproj", "type": "blob", "mode": "100644"},
                {"path": "macos/Runner/Info.plist", "type": "blob", "mode": "100644"},
            ]}
        app._app_jwt = lambda: "app-jwt"
        app._request = request
        result = app.inspect_repository_project("example/flutter-app", sha)
        self.assertEqual(result["status"], "target_detected")
        self.assertEqual(result["project_types"], ["flutter"])
        self.assertTrue(result["flutter"]["macos_supported"])
        self.assertTrue(any("/git/trees/" + tree_sha + "?recursive=1" in call[1] for call in calls))

    def test_repository_project_inspection_reports_flutter_macos_setup_needed(self):
        app = self.make()
        app.is_repository_accessible = lambda repository, refresh=False: True
        future = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
        sha = "e" * 40
        def request(method, path, token, payload=None):
            if method == "POST":
                return {"token": "contents-token", "expires_at": future,
                        "permissions": {"contents": "read"}}
            if "/commits/" in path:
                return {"sha": sha, "commit": {"tree": {"sha": "f" * 40}}}
            if "/contents/" in path:
                raw = b"dependencies:\n  flutter:\n    sdk: flutter\n"
                return {"encoding": "base64", "content": base64.b64encode(raw).decode(), "size": len(raw)}
            return {"truncated": False, "tree": [
                {"path": "pubspec.yaml", "type": "blob", "mode": "100644"},
                {"path": "lib/main.dart", "type": "blob", "mode": "100644"},
            ]}
        app._app_jwt = lambda: "app-jwt"
        app._request = request
        result = app.inspect_repository_project("owner/repo", sha)
        self.assertEqual(result["status"], "needs_setup")
        self.assertFalse(result["flutter"]["macos_supported"])

    def test_repository_project_inspection_does_not_misclassify_dart_package_as_flutter(self):
        app = self.make()
        app.is_repository_accessible = lambda repository, refresh=False: True
        future = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
        sha = "e" * 40
        def request(method, path, token, payload=None):
            if method == "POST":
                return {"token": "contents-token", "expires_at": future,
                        "permissions": {"contents": "read"}}
            if "/commits/" in path:
                return {"sha": sha, "commit": {"tree": {"sha": "f" * 40}}}
            if "/contents/" in path:
                raw = b"name: pure_dart\n"
                return {"encoding": "base64", "content": base64.b64encode(raw).decode(), "size": len(raw)}
            return {"truncated": False, "tree": [
                {"path": "pubspec.yaml", "type": "blob", "mode": "100644"},
                {"path": "lib/main.dart", "type": "blob", "mode": "100644"},
            ]}
        app._app_jwt = lambda: "app-jwt"
        app._request = request
        result = app.inspect_repository_project("owner/repo", sha)
        self.assertEqual(result["status"], "detected")
        self.assertEqual(result["project_types"], ["dart"])
        self.assertFalse(result["flutter"]["detected"])
        self.assertIsNone(result["flutter"]["macos_supported"])

    def test_repository_project_inspection_marks_flutter_support_not_applicable_for_other_stacks(self):
        app = self.make()
        app.is_repository_accessible = lambda repository, refresh=False: True
        future = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
        sha = "e" * 40
        def request(method, path, token, payload=None):
            if method == "POST":
                return {"token": "contents-token", "expires_at": future,
                        "permissions": {"contents": "read"}}
            if "/commits/" in path:
                return {"sha": sha, "commit": {"tree": {"sha": "f" * 40}}}
            return {"truncated": False, "tree": [
                {"path": "package.json", "type": "blob", "mode": "100644"},
                {"path": "src/index.js", "type": "blob", "mode": "100644"},
            ]}
        app._app_jwt = lambda: "app-jwt"
        app._request = request
        result = app.inspect_repository_project("owner/repo", sha)
        self.assertEqual(result["project_types"], ["node"])
        self.assertIsNone(result["flutter"]["macos_supported"])

    def test_repository_project_inspection_rejects_unsafe_tree_paths(self):
        app = self.make()
        app.is_repository_accessible = lambda repository, refresh=False: True
        future = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
        sha = "e" * 40
        def request(method, path, token, payload=None):
            if method == "POST":
                return {"token": "contents-token", "expires_at": future,
                        "permissions": {"contents": "read"}}
            if "/commits/" in path:
                return {"sha": sha, "commit": {"tree": {"sha": "f" * 40}}}
            return {"truncated": False, "tree": [
                {"path": "../pubspec.yaml", "type": "blob", "mode": "100644"},
            ]}
        app._app_jwt = lambda: "app-jwt"
        app._request = request
        with self.assertRaisesRegex(GitHubAppError, "unsafe path"):
            app.inspect_repository_project("owner/repo", sha)

    def test_repository_project_inspection_treats_truncated_tree_as_unknown(self):
        app = self.make()
        app.is_repository_accessible = lambda repository, refresh=False: True
        future = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
        sha = "e" * 40
        def request(method, path, token, payload=None):
            if method == "POST":
                return {"token": "contents-token", "expires_at": future,
                        "permissions": {"contents": "read"}}
            if "/commits/" in path:
                return {"sha": sha, "commit": {"tree": {"sha": "f" * 40}}}
            return {"truncated": True, "tree": [
                {"path": "pubspec.yaml", "type": "blob", "mode": "100644"},
            ]}
        app._app_jwt = lambda: "app-jwt"
        app._request = request
        result = app.inspect_repository_project("owner/repo", sha)
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["flutter"]["macos_supported"])

    def test_resolve_repository_commit_uses_scoped_contents_token(self):
        app = self.make()
        future = (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat()
        calls = []
        def request(method, path, token, payload=None):
            calls.append((method, path, token, payload))
            if method == "POST":
                return {"token": "contents-token", "expires_at": future,
                        "permissions": {"contents": "read"}}
            return {"sha": "b" * 40}
        app._app_jwt = lambda: "app-jwt"
        app._request = request
        result = app.resolve_repository_commit(
            "phakphum12345/generated-A4-pdf", "b" * 40
        )
        self.assertEqual(result, {"commit_sha": "b" * 40})
        self.assertIn("/commits/" + "b" * 40, calls[1][1])

    def test_resolve_repository_commit_rejects_malformed_sha_before_network(self):
        app = self.make()
        app._request = lambda *args, **kwargs: self.fail("network must not be called")
        with self.assertRaisesRegex(GitHubAppError, "40 hexadecimal"):
            app.resolve_repository_commit("phakphum12345/generated-A4-pdf", "not-a-sha")

    def test_repository_ref_catalog_rejects_unsupported_kind_before_network(self):
        app = self.make()
        app._request = lambda *args, **kwargs: self.fail("network must not be called")
        with self.assertRaisesRegex(GitHubAppError, "Unsupported"):
            app.list_repository_refs("phakphum12345/generated-A4-pdf", "commits")

    def test_repository_ref_catalog_fails_closed_without_contents_permission(self):
        app = self.make()
        app._app_jwt = lambda: "app-jwt"
        app._request = lambda *args, **kwargs: {
            "token": "metadata-only",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=40)).isoformat(),
            "permissions": {"metadata": "read"},
        }
        with self.assertRaisesRegex(GitHubAppError, "Contents read"):
            app.list_repository_refs("phakphum12345/generated-A4-pdf", "tags")



if __name__ == "__main__":
    unittest.main()
