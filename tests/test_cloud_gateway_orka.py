"""Mocked Orka API tests; never contact an Orka cluster."""
import base64,json,unittest
from unittest.mock import MagicMock,patch
from urllib.error import HTTPError
from tools.cloud_gateway.orka import OrkaProvider,OrkaError
from tools.runner_backend.manager import PLATFORM_PROFILES
def request():
 p=PLATFORM_PROFILES["macos"]; return {"repository":"phakphum12345/generated-A4-pdf","workflow_run_id":123,"commit_sha":"a"*40,"target_os":"macos","image":p["image"],"labels":list(p["labels"]),"ephemeral":True,"max_runtime_minutes":30,"network_policy":"restricted-egress","registration_token_handling":"provider-side-only"}
def response(data):
 r=MagicMock(); r.__enter__.return_value=r; r.headers={"Content-Type":"application/json"}; r.read.return_value=json.dumps(data).encode(); return r
class SecretReader:
 def get_secret(self,name): return "mock-bearer"
class OrkaTests(unittest.TestCase):
 def make(self,checker=None,bootstrap=True): return OrkaProvider("https://orka.example.test","dcp","macos15-arm64",SecretReader(),runner_online_checker=checker,runner_userdata_factory=(lambda name,payload: base64.b64encode(b"#!/bin/sh\\necho bootstrap\\n").decode()) if bootstrap else None)
 def test_rejects_non_https_or_untrusted_configuration(self):
  with self.assertRaises(ValueError): OrkaProvider("http://orka.example.test","dcp","macos",SecretReader())
  with self.assertRaises(ValueError): OrkaProvider("https://@orka.example.test","dcp","macos",SecretReader())
  with self.assertRaises(ValueError): OrkaProvider("https://:pass@orka.example.test","dcp","macos",SecretReader())
  with self.assertRaises(ValueError): OrkaProvider("https://orka.example.test","../admin","macos",SecretReader())
 def test_provision_posts_pinned_vm_config_and_nonsecret_metadata(self):
  provider=self.make()
  def create(req,timeout):
   body=json.loads(req.data); return response({"name":body["name"],"status":"Running"})
  with patch("tools.cloud_gateway.orka.urlopen",side_effect=create) as call: result=provider.provision(request())
  req=call.call_args.args[0]; body=json.loads(req.data)
  self.assertEqual(req.get_method(),"POST"); self.assertEqual(req.get_header("Authorization"),"Bearer mock-bearer"); self.assertTrue(any(k.lower()=="authorization" for k in req.unredirected_hdrs))
  self.assertEqual(body["vmConfig"],"macos15-arm64"); self.assertEqual(base64.b64decode(body["userdata"]),b"#!/bin/sh\\necho bootstrap\\n"); self.assertNotIn("token",json.dumps(body["customMetadata"]).lower())
  self.assertEqual(result.state,"provisioning")
 def test_provision_fails_closed_without_userdata_factory(self):
  p=self.make(bootstrap=False)
  with patch("tools.cloud_gateway.orka.urlopen") as call:
   with self.assertRaises(OrkaError): p.provision(request())
  call.assert_not_called()
 def test_userdata_factory_output_must_be_bounded_base64(self):
  p=self.make()
  p.runner_userdata_factory=lambda *args:"not base64!"
  with patch("tools.cloud_gateway.orka.urlopen") as call:
   with self.assertRaises(OrkaError): p.provision(request())
  call.assert_not_called()
 def test_rejects_linux_and_non_ephemeral_payloads(self):
  p=self.make(); bad=request(); bad["target_os"]="linux"
  with self.assertRaises(OrkaError): p.provision(bad)
  bad=request(); bad["ephemeral"]=False
  with self.assertRaises(OrkaError): p.provision(bad)
 def test_running_vm_is_not_online_without_github_runner_evidence(self):
  p=self.make(); name="dcp-123-"+"a"*8
  with patch("tools.cloud_gateway.orka.urlopen",return_value=response({"status":"Running","name":name})): result=p.status(name)
  self.assertEqual(result.state,"provisioning")
 def test_online_requires_runner_checker(self):
  p=self.make(lambda *args:True); name="dcp-123-"+"a"*8
  with patch("tools.cloud_gateway.orka.urlopen",return_value=response({"status":"Running","name":name,"customMetadata":{"repository":"phakphum12345/generated-A4-pdf","target-os":"macos"}})): self.assertEqual(p.status(name).state,"online")
 def test_delete_acceptance_is_terminating_and_404_confirms_gone(self):
  p=self.make(); name="dcp-123-"+"a"*8
  with patch("tools.cloud_gateway.orka.urlopen",return_value=response({"status":"Terminating"})): self.assertEqual(p.terminate(name).state,"terminating")
  with patch("tools.cloud_gateway.orka.urlopen",side_effect=HTTPError("url",404,"missing",{},None)): self.assertEqual(p.status(name).state,"terminated")
 def test_failed_orka_vm_is_deleted_before_terminal_state(self):
  p=self.make(); name="dcp-123-"+"a"*8
  with patch("tools.cloud_gateway.orka.urlopen",return_value=response({"status":"Failed","name":name})):
   result=p.status(name)
  self.assertEqual(result.state,"terminating")
 def test_readiness_fails_closed_without_protected_guest_bootstrap(self):
  p=self.make(lambda *args:True)
  readiness=p.readiness("macos")
  self.assertFalse(readiness["ready"])
  self.assertIn("User Data exposure controls",readiness["message"])
 def test_provider_errors_do_not_echo_credentials(self):
  p=self.make()
  with patch("tools.cloud_gateway.orka.urlopen",side_effect=HTTPError("url",401,"denied",{},None)):
   with self.assertRaises(OrkaError) as caught: p.provision(request())
  self.assertNotIn("mock-bearer",str(caught.exception))
 def test_lists_images_and_vm_configs_using_documented_read_only_endpoints(self):
  p=self.make()
  with patch("tools.cloud_gateway.orka.urlopen",side_effect=[response({"items":[{"name":"ventura-arm64","type":"arm64"}]}),response({"items":[{"name":"macos15-arm64","image":"ventura-arm64"}]})]) as call:
   self.assertEqual(p.list_images()[0]["name"],"ventura-arm64")
   self.assertEqual(p.list_vm_configs()[0]["name"],"macos15-arm64")
  self.assertTrue(call.call_args_list[0].args[0].full_url.endswith("/api/v1/namespaces/dcp/images"))
  self.assertTrue(call.call_args_list[1].args[0].full_url.endswith("/api/v1/namespaces/dcp/vmconfigs"))
 def test_vm_config_creation_requires_approval_and_never_overwrites(self):
  p=self.make(); config={"name":"dcp-macos15-test","image":"ventura-arm64","cpu":4,"memory":16}
  with self.assertRaises(OrkaError): p.create_vm_config(config)
  with patch("tools.cloud_gateway.orka.urlopen",return_value=response({"items":[{"name":"dcp-macos15-test"}]})):
   with self.assertRaises(OrkaError): p.create_vm_config(config,approved=True)
 def test_vm_config_creation_posts_only_allowlisted_schema_after_approval(self):
  p=self.make(); config={"name":"dcp-macos15-test","image":"ventura-arm64","cpu":4,"memory":16}
  with patch("tools.cloud_gateway.orka.urlopen",side_effect=[response({"items":[]}),response(config)]) as call:
   result=p.create_vm_config(config,approved=True)
  self.assertEqual(result["name"],config["name"])
  req=call.call_args_list[1].args[0]
  self.assertEqual(req.get_method(),"POST")
  self.assertEqual(json.loads(req.data),config)
 def test_vm_config_rejects_untrusted_fields_and_invalid_resources(self):
  p=self.make()
  with self.assertRaises(OrkaError): p.create_vm_config({"name":"x","image":"y","cpu":2,"memory":8,"customMetadata":{"token":"x"}},approved=True)
 def test_vm_config_rejects_fractional_cpu(self):
  p=self.make()
  with self.assertRaises(OrkaError):
   p.create_vm_config({"name":"dcp-macos15-fractional","image":"ventura-arm64","cpu":2.5,"memory":8},approved=True)
if __name__=="__main__": unittest.main()
