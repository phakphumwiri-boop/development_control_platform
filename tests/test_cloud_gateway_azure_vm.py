"""Mock-only Azure VM provisioner tests. No ARM resources are created."""
import unittest
from tools.cloud_gateway.azure_vm import AzureVMProvider,AzureProvisionError
from tools.runner_backend.manager import PLATFORM_PROFILES
SUB="00000000-0000-0000-0000-000000000000"
IMAGES={"linux":{"publisher":"Canonical","offer":"ubuntu-24_04-lts","sku":"server","version":"24.04.202501150"},"windows":{"publisher":"MicrosoftWindowsServer","offer":"WindowsServer","sku":"2025-datacenter-g2","version":"20348.1.250101"}}
class FakeArm:
 subscription_id=SUB; resource_group="dcp"
 def __init__(self):
  self.calls=[]; self.nic_exists=True; self.nic_delete_pending=False; self.fail_vm_put=False
  self.get_result={"properties":{"provisioningState":"Succeeded"},"tags":{"repository":"phakphum12345/generated-A4-pdf","target-os":"linux"}}
 def resource_url(self,provider,kind,name,version): return f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/dcp/providers/{provider}/{kind}/{name}?api-version={version}"
 def resource_id(self,provider,kind,name): return f"/subscriptions/{SUB}/resourceGroups/dcp/providers/{provider}/{kind}/{name}"
 def request(self,method,url,payload=None,allow_missing=False):
  self.calls.append((method,url,payload))
  if self.fail_vm_put and method=="PUT" and "Microsoft.Compute/virtualMachines/" in url: raise RuntimeError("simulated VM create uncertainty")
  if "Microsoft.Network/networkInterfaces/" in url:
   if method=="GET": return {"properties":{"provisioningState":"Succeeded"}} if self.nic_exists else None
   if method=="DELETE":
    if not self.nic_delete_pending:
     self.nic_exists=False
    return {}
  return self.get_result if method=="GET" else {}
class FakeNetworkPolicy:
 def __init__(self,allow=True): self.allow=allow; self.calls=[]
 def verify_nic(self,nic_id,nsg_id,subnet_id):
  self.calls.append((nic_id,nsg_id,subnet_id))
  return self.allow

def bootstrap(vm,os_name,payload):
 os_profile={"computerName":vm,"adminUsername":"dcpadmin"}
 if os_name=="linux": os_profile["linuxConfiguration"]={"disablePasswordAuthentication":True}
 else: os_profile["adminPassword"]="test-only-password"
 return {"os_profile":os_profile,"extension":{"name":"dcp-bootstrap","properties":{"publisher":"Microsoft.Azure.Extensions","type":"CustomScript","typeHandlerVersion":"2.1","settings":{},"protectedSettings":{"script":"base64-one-time-bootstrap"}}}}
def payload(os_name):
 p=PLATFORM_PROFILES[os_name]; return {"repository":"phakphum12345/generated-A4-pdf","workflow_run_id":123,"commit_sha":"a"*40,"target_os":os_name,"image":p["image"],"labels":list(p["labels"]),"ephemeral":True,"max_runtime_minutes":30,"network_policy":"restricted-egress","registration_token_handling":"provider-side-only"}
class AzureVMTests(unittest.TestCase):
 def make(self,checker=None,network="default"):
  if network=="default": network=FakeNetworkPolicy()
  arm=FakeArm(); p=AzureVMProvider(arm,"eastus",f"/subscriptions/{SUB}/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/vnet/subnets/runners",f"/subscriptions/{SUB}/resourceGroups/net/providers/Microsoft.Network/networkSecurityGroups/runner-nsg",{"linux":"Standard_D2s_v5","windows":"Standard_D4s_v5"},IMAGES,bootstrap,checker,network); return p,arm
 def test_requires_existing_subnet_nsg_and_both_vm_sizes(self):
  with self.assertRaises(ValueError): AzureVMProvider(FakeArm(),"eastus","bad","bad",{"linux":"D2"},IMAGES,bootstrap)
 def test_rejects_latest_image_version(self):
  with self.assertRaises(ValueError): AzureVMProvider(FakeArm(),"eastus",f"/subscriptions/{SUB}/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/vnet/subnets/runners",f"/subscriptions/{SUB}/resourceGroups/net/providers/Microsoft.Network/networkSecurityGroups/nsg",{"linux":"D2","windows":"D4"},{**IMAGES,"linux":{**IMAGES["linux"],"version":"latest"}},bootstrap)
 def test_provision_uses_ephemeral_disk_private_nic_and_tags(self):
  for os_name in ("linux","windows"):
   p,arm=self.make(); result=p.provision(payload(os_name)); self.assertEqual(result.state,"provisioning")
   nic=arm.calls[0][2]; vm=arm.calls[1][2]; self.assertNotIn("publicIPAddress",str(nic))
   self.assertEqual(vm["storageProfile"]["osDisk"]["diffDiskSettings"]["option"],"Local")
   self.assertEqual(vm["networkProfile"]["networkInterfaces"][0]["id"],f"/subscriptions/{SUB}/resourceGroups/dcp/providers/Microsoft.Network/networkInterfaces/{arm.calls[0][1].split('/')[-1].split('?')[0]}")
   self.assertNotIn("identity",vm); self.assertEqual(vm["tags"]["managed-by"],"dcp-cloud-runner")
   self.assertIn("protectedSettings",vm["resources"][0]["properties"])
 def test_effective_egress_deny_prevents_vm_create_and_cleans_nic(self):
  policy=FakeNetworkPolicy(False)
  p,arm=self.make(network=policy)
  with self.assertRaises(AzureProvisionError): p.provision(payload("linux"))
  self.assertEqual(len(policy.calls),1)
  self.assertFalse(any(call[0]=="PUT" and "Microsoft.Compute/virtualMachines/" in call[1] for call in arm.calls))
  self.assertTrue(any(call[0]=="DELETE" and "networkInterfaces/" in call[1] for call in arm.calls))
 def test_partial_vm_create_failure_retains_provider_id_for_reconciliation(self):
  p,arm=self.make(); arm.fail_vm_put=True
  with self.assertRaises(AzureProvisionError) as caught: p.provision(payload("linux"))
  self.assertRegex(caught.exception.provider_id,r"^dcp-[0-9]+-[a-f0-9]{8}$")
 def test_rejects_mac_os_and_public_network_policy(self):
  p,_=self.make()
  with self.assertRaises(AzureProvisionError): p.provision(payload("macos"))
  bad=payload("linux"); bad["network_policy"]="public"
  with self.assertRaises(AzureProvisionError): p.provision(bad)
 def test_vm_running_is_not_runner_online_without_checker(self):
  p,_=self.make(); vm=p.provision(payload("linux")); self.assertEqual(p.status(vm.provider_id).state,"provisioning")
 def test_runner_online_requires_independent_checker(self):
  p,_=self.make(lambda *args:True); vm=p.provision(payload("linux")); self.assertEqual(p.status(vm.provider_id).state,"online")
 def test_termination_waits_for_missing_vm_and_nic_before_terminal_state(self):
  p,arm=self.make(); vm=p.provision(payload("linux")); p.terminate(vm.provider_id)
  arm.get_result=None
  arm.nic_delete_pending=True
  self.assertEqual(p.status(vm.provider_id).state,"terminating")
  self.assertTrue(any(call[0]=="DELETE" and "networkInterfaces/" in call[1] for call in arm.calls))
  arm.nic_delete_pending=False
  arm.nic_exists=False
  self.assertEqual(p.status(vm.provider_id).state,"terminated")
 def test_missing_nic_is_already_clean(self):
  p,arm=self.make(); vm=p.provision(payload("linux")); p.terminate(vm.provider_id)
  arm.get_result=None; arm.nic_exists=False
  self.assertEqual(p.status(vm.provider_id).state,"terminated")
  self.assertFalse(any(call[0]=="DELETE" and "networkInterfaces/" in call[1] for call in arm.calls))
 def test_failed_vm_is_deleted_before_runner_cleanup_can_begin(self):
  p,arm=self.make(); vm=p.provision(payload("linux"))
  arm.get_result={"properties":{"provisioningState":"Failed"},"tags":{"repository":"phakphum12345/generated-A4-pdf","target-os":"linux"}}
  self.assertEqual(p.status(vm.provider_id).state,"terminating")
  self.assertTrue(any(call[0]=="DELETE" and "Microsoft.Compute/virtualMachines/" in call[1] for call in arm.calls))
 def test_readiness_requires_bootstrap_online_and_network_policy(self):
  p,_=self.make(network=None)
  self.assertFalse(p.readiness("linux")["ready"])
  p,_=self.make(lambda _:True,network=None)
  self.assertFalse(p.readiness("linux")["ready"])
  p,_=self.make(lambda *args:True)
  self.assertTrue(p.readiness("linux")["ready"])
  self.assertFalse(p.readiness("macos")["ready"])
 def test_missing_protected_bootstrap_is_rejected(self):
  p,_=self.make(); p.bootstrap_factory=lambda *a:{"os_profile":{},"extension":{"properties":{"settings":{}}}}
  with self.assertRaises(AzureProvisionError): p.provision(payload("linux"))
if __name__=="__main__": unittest.main()
