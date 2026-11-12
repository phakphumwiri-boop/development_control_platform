"""Mock-only tests for ARM effective NSG and route verification."""
import unittest
from tools.cloud_gateway.azure_network_policy import (
    AzureEffectiveNetworkPolicyVerifier, EffectiveNetworkPolicyError
)

SUB="00000000-0000-0000-0000-000000000000"
NIC=f"/subscriptions/{SUB}/resourceGroups/dcp/providers/Microsoft.Network/networkInterfaces/dcpnic12345678"
NSG=f"/subscriptions/{SUB}/resourceGroups/net/providers/Microsoft.Network/networkSecurityGroups/runner-nsg"
SUBNET=f"/subscriptions/{SUB}/resourceGroups/net/providers/Microsoft.Network/virtualNetworks/vnet/subnets/runners"
FW="10.20.0.4"

def nsg_body(access="Allow", include_rules=True):
    rules=[] if not include_rules else [{
        "name":"allow-runner-https","direction":"Outbound","access":access,
        "protocol":"Tcp","destinationPortRange":"443","destinationAddressPrefix":"198.51.100.0/24",
        "priority":100
    }]
    return {"value":[{
        "association":{"networkInterface":{"id":NIC},"subnet":{"id":SUBNET}},
        "networkSecurityGroup":{"id":NSG},
        "effectiveSecurityRules":rules
    }]}

def route_body(next_hop=FW, state="Active"):
    return {"value":[{
        "addressPrefix":"0.0.0.0/0","nextHopType":"VirtualAppliance",
        "nextHopIp":next_hop,"state":state
    }]}

class FakeArm:
    subscription_id=SUB
    def __init__(self,nsg=None,routes=None,responses=None):
        self.nsg=nsg if nsg is not None else nsg_body()
        self.routes=routes if routes is not None else route_body()
        self.responses=list(responses or [])
        self.calls=[]
    def resource_url(self,provider,kind,name,version):
        return f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/dcp/providers/{provider}/{kind}/{name}?api-version={version}"
    def request(self,method,url,payload=None,allow_missing=False):
        self.calls.append((method,url,payload))
        if method=="GET" and "networkInterfaces/" in url:
            return {"properties":{"provisioningState":"Succeeded"}}
        return {}

    def request_with_metadata(self,method,url,payload=None):
        self.calls.append((method,url,payload))
        if self.responses:
            return self.responses.pop(0)
        if "effectiveNetworkSecurityGroups" in url:
            return 200,{},self.nsg
        if "effectiveRouteTable" in url:
            return 200,{},self.routes
        raise AssertionError("unexpected ARM request")

class VerifierTests(unittest.TestCase):
    def make(self,arm=None,**kwargs):
        return AzureEffectiveNetworkPolicyVerifier(
            arm or FakeArm(),NSG,
            [{"protocol":"Tcp","port":443,"destination":"198.51.100.0/24"}],
            FW,**kwargs
        )
    def test_allows_explicit_outbound_allow_and_firewall_route(self):
        arm=FakeArm()
        self.assertTrue(self.make(arm).verify_nic(NIC,NSG,SUBNET))
        self.assertEqual(len(arm.calls),3)
        self.assertEqual([x[0] for x in arm.calls],["GET","POST","POST"])
    def test_denies_effective_outbound_deny(self):
        with self.assertRaises(EffectiveNetworkPolicyError):
            self.make(FakeArm(nsg=nsg_body("Deny"))).verify_nic(NIC,NSG,SUBNET)
    def test_denies_default_allow_without_explicit_allow_rule(self):
        with self.assertRaises(EffectiveNetworkPolicyError):
            self.make(FakeArm(nsg=nsg_body(include_rules=False))).verify_nic(NIC,NSG,SUBNET)
        default_rule=nsg_body()
        default_rule["value"][0]["effectiveSecurityRules"][0]["priority"]=65001
        with self.assertRaises(EffectiveNetworkPolicyError):
            self.make(FakeArm(nsg=default_rule)).verify_nic(NIC,NSG,SUBNET)
    def test_missing_nsg_or_route_data_fails_closed(self):
        for arm in (FakeArm(nsg={}),FakeArm(routes={})):
            with self.assertRaises(EffectiveNetworkPolicyError):
                self.make(arm).verify_nic(NIC,NSG,SUBNET)
    def test_wrong_next_hop_and_inactive_route_fail_closed(self):
        for routes in (route_body("10.20.0.9"),route_body(state="Invalid")):
            with self.assertRaises(EffectiveNetworkPolicyError):
                self.make(FakeArm(routes=routes)).verify_nic(NIC,NSG,SUBNET)
    def test_nic_and_nsg_scope_must_match(self):
        bad=NIC.replace("dcpnic12345678","othernic")
        with self.assertRaises(EffectiveNetworkPolicyError):
            self.make().verify_nic(bad,NSG,SUBNET)
        with self.assertRaises(EffectiveNetworkPolicyError):
            self.make().verify_nic(NIC,NSG+"-other",SUBNET)
    def test_202_accepted_is_polled_until_effective_result_is_returned(self):
        location="https://management.azure.com/subscriptions/"+SUB+"/resourceGroups/dcp/providers/Microsoft.Network/networkInterfaces/nic/operationResults/op?api-version=2025-05-01"
        arm=FakeArm(responses=[
            (202,{"Location":location,"Retry-After":"0"},{}),
            (200,{},nsg_body()),
            (200,{},route_body())
        ])
        self.assertTrue(self.make(arm).verify_nic(NIC,NSG,SUBNET))
        self.assertEqual([x[0] for x in arm.calls],["GET","POST","GET","POST"])
    def test_202_without_location_or_with_untrusted_location_is_rejected(self):
        for headers in ({},{"Location":"https://attacker.example/operation"}):
            arm=FakeArm(responses=[(202,headers,{})])
            with self.assertRaises(EffectiveNetworkPolicyError):
                self.make(arm).verify_nic(NIC,NSG,SUBNET)
    def test_stale_or_unknown_async_operation_times_out_closed(self):
        location="https://management.azure.com/subscriptions/"+SUB+"/resourceGroups/dcp/providers/Microsoft.Network/networkInterfaces/nic/operationResults/op?api-version=2025-05-01"
        ticks=[0]
        def clock(): return ticks[0]
        def sleep(seconds): ticks[0]+=max(1,seconds)
        arm=FakeArm(responses=[
            (202,{"Location":location,"Retry-After":"1"},{}),
            (202,{"Location":location,"Retry-After":"1"},{}),
            (202,{"Location":location,"Retry-After":"1"},{})
        ])
        verifier=self.make(arm,timeout_seconds=2,poll_interval=1,clock=clock,sleep=sleep)
        with self.assertRaises(EffectiveNetworkPolicyError):
            verifier.verify_nic(NIC,NSG,SUBNET)
    def test_malformed_effective_rule_fails_closed(self):
        body=nsg_body()
        body["value"][0]["effectiveSecurityRules"]=[{"direction":"Outbound","access":"Allow"}]
        with self.assertRaises(EffectiveNetworkPolicyError):
            self.make(FakeArm(nsg=body)).verify_nic(NIC,NSG,SUBNET)

if __name__=="__main__":
    unittest.main()
