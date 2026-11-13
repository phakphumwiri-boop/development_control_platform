"""Policy and HTTP-adapter contract tests for multi-platform cloud runners."""
import json, unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError
from tools.runner_backend.cloud_api import CloudAPIProvider, ProviderError
from tools.runner_backend.manager import PLATFORM_PROFILES, RunnerManager, RunnerPolicyError, RunnerRequest
from tools.runner_backend.provider import RunnerInstance

class FakeProvider:
    def __init__(self): self.calls = []
    def provision(self, payload):
        self.calls.append(("provision", payload))
        return RunnerInstance("runner-123", "provisioning", labels=tuple(payload["labels"]))
    def status(self, provider_id): self.calls.append(("status", provider_id)); return RunnerInstance(provider_id, "online")
    def terminate(self, provider_id): self.calls.append(("terminate", provider_id)); return RunnerInstance(provider_id, "terminated")

class CloudRunnerBackendTests(unittest.TestCase):
    def setUp(self):
        self.provider = FakeProvider()
        self.manager = RunnerManager(self.provider, {"phakphum12345/generated-A4-pdf"})
        self.request = RunnerRequest("phakphum12345/generated-A4-pdf", 12345, "a"*40)

    def test_all_os_profiles_are_ephemeral_and_provider_side_token_only(self):
        for os_name, profile in PLATFORM_PROFILES.items():
            with self.subTest(target_os=os_name):
                result = self.manager.provision(RunnerRequest(self.request.repository, 12345, "a"*40, target_os=os_name))
                payload = self.provider.calls[-1][1]
                self.assertEqual(result.state, "provisioning")
                self.assertEqual(payload["target_os"], os_name)
                self.assertEqual(payload["image"], profile["image"])
                self.assertEqual(payload["labels"], list(profile["labels"]))
                self.assertTrue(payload["ephemeral"])
                self.assertEqual(payload["network_policy"], "restricted-egress")
                self.assertEqual(payload["registration_token_handling"], "provider-side-only")

    def test_legacy_macos_method_remains_compatible(self):
        self.manager.provision_macos(self.request)
        self.assertEqual(self.provider.calls[-1][1]["target_os"], "macos")

    def test_unregistered_repository_rejected_before_provider_call(self):
        with self.assertRaises(RunnerPolicyError):
            self.manager.provision(RunnerRequest("attacker/repo", 12345, "a"*40, target_os="linux"))
        self.assertEqual(self.provider.calls, [])

    def test_unapproved_image_and_os_rejected(self):
        for req in (RunnerRequest(self.request.repository,12345,"a"*40,image="bad",target_os="linux"),
                    RunnerRequest(self.request.repository,12345,"a"*40,target_os="freebsd"),
                    RunnerRequest(self.request.repository,12345,"a"*40,target_os="windows",image="macos-15-arm64")):
            with self.subTest(request=req), self.assertRaises(RunnerPolicyError): req.validate({self.request.repository})

    def test_runtime_and_boolean_values_rejected(self):
        for req in (RunnerRequest(self.request.repository,12345,"a"*40,max_runtime_minutes=999),
                    RunnerRequest(self.request.repository,True,"a"*40),
                    RunnerRequest(self.request.repository,123,"a"*40,max_runtime_minutes=True)):
            with self.subTest(request=req), self.assertRaises(RunnerPolicyError): req.validate({self.request.repository})

    def test_status_and_terminate_delegate(self):
        self.assertEqual(self.manager.status("runner-123").state, "online")
        self.assertEqual(self.manager.terminate("runner-123").state, "terminated")

class CloudAPIProviderTests(unittest.TestCase):
    TOKEN = "test-secret-token"
    def make_provider(self, **kwargs): return CloudAPIProvider(base_url="https://gateway.example.test", token=self.TOKEN, **kwargs)
    @staticmethod
    def response(payload):
        r=MagicMock(); r.__enter__.return_value=r; r.headers={"Content-Type":"application/json"}
        r.read.return_value=payload if isinstance(payload,bytes) else json.dumps(payload).encode()
        return r

    @patch("tools.runner_backend.cloud_api.urlopen")
    def test_provision_auth_and_json(self, urlopen):
        urlopen.return_value=self.response({"id":"req-1","state":"provisioning","labels":["dcp-cloud-linux"]})
        result=self.make_provider().provision({"target_os":"linux"})
        request=urlopen.call_args.args[0]
        self.assertEqual(request.full_url,"https://gateway.example.test/v1/runners")
        self.assertEqual(request.unredirected_hdrs.get("Authorization"),f"Bearer {self.TOKEN}")
        self.assertEqual(json.loads(request.data),{"target_os":"linux"})
        self.assertEqual(result.state,"provisioning")

    @patch("tools.runner_backend.cloud_api.urllib.request.urlopen")
    def test_status_and_terminate_quote_provider_id(self,urlopen):
        urlopen.return_value=self.response({"id":"a/b","state":"online"})
        p=self.make_provider(); p.status("a/b")
        self.assertEqual(urlopen.call_args.args[0].full_url,"https://gateway.example.test/v1/runners/a%2Fb")
        p.terminate("a/b")
        self.assertEqual(urlopen.call_args.args[0].method,"DELETE")

    def test_rejects_unsafe_origins_and_missing_token(self):
        for url in ("http://gateway.example.test","https://user:pass@gateway.example.test","https://gateway.example.test/path",
                    "https://gateway.example.test/?token=x","https://gateway.example.test/#fragment","https://",
                    "https://gateway.example.test:65536"):
            with self.subTest(url=url), self.assertRaises(ProviderError): CloudAPIProvider(base_url=url,token=self.TOKEN)
        with self.assertRaises(ProviderError): CloudAPIProvider(base_url="https://gateway.example.test",token="")

    @patch("tools.runner_backend.cloud_api.urllib.request.urlopen")
    def test_provider_errors_do_not_leak_secrets(self,urlopen):
        urlopen.side_effect=URLError("https://gateway.example.test/private?token=do-not-leak"+self.TOKEN)
        with self.assertRaises(ProviderError) as caught: self.make_provider().provision({})
        self.assertNotIn(self.TOKEN,str(caught.exception)); self.assertNotIn("do-not-leak",str(caught.exception))

    @patch("tools.runner_backend.cloud_api.urllib.request.urlopen")
    @patch("tools.runner_backend.cloud_api.urlopen")
    def test_provider_transport_rejects_redirects_and_invalid_json_media_type(self, urlopen):
        from urllib.error import HTTPError
        urlopen.side_effect = HTTPError(
            "https://gateway.example.test/v1/runners", 302, "redirect", {}, None
        )
        with self.assertRaises(ProviderError):
            self.make_provider().provision({})
        self.assertEqual(urlopen.call_count, 1)

        response = self.response({"id": "runner-1", "state": "online"})
        response.headers = {"Content-Type": "text/plain"}
        urlopen.side_effect = None
        urlopen.return_value = response
        with self.assertRaises(ProviderError):
            self.make_provider().provision({})

    def test_rejects_invalid_provider_token_and_unbounded_timeout(self):
        for token in ("bad\\r\\nheader", "x" * 8193):
            with self.assertRaises(ProviderError):
                CloudAPIProvider(base_url="https://gateway.example.test", token=token)
        with self.assertRaises(ProviderError):
            self.make_provider(timeout=31)

    def test_rejects_oversized_and_malformed_responses(self,urlopen):
        urlopen.return_value=self.response(b"x"*65537)
        with self.assertRaises(ProviderError): self.make_provider().provision({})
        for invalid in ([],{"id":"","state":"online"},{"id":"id","state":"online","labels":"bad"}):
            urlopen.return_value=self.response(invalid)
            with self.assertRaises(ProviderError): self.make_provider().provision({})

if __name__ == "__main__": unittest.main()
