"""Gateway policy, budget, lifecycle, idempotency, and HTTP contract tests."""
import json,tempfile,threading,unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
from tools.cloud_gateway.policy import GatewaySettings,PolicyDenied,PROFILES,validate_runner_request
from tools.cloud_gateway.service import GatewayService
from tools.cloud_gateway.server import make_handler
from tools.cloud_gateway.store import LifecycleConflict,RunnerStore
from tools.runner_backend.provider import RunnerInstance

REPO="phakphum12345/generated-A4-pdf"
def payload(os_name="linux"):
 p=PROFILES[os_name]
 return {"repository":REPO,"workflow_run_id":12,"commit_sha":"a"*40,"target_os":os_name,"image":p["image"],"labels":p["labels"],"ephemeral":True,"max_runtime_minutes":30,"network_policy":"restricted-egress","registration_token_handling":"provider-side-only"}
def settings(**kw):
 d=dict(provisioning_enabled=True,owner_approved=True,allowed_repositories=(REPO,),budget_limit_usd=20,current_spend_usd=0,projected_run_cost_usd=2,max_concurrent_runners=2,max_runtime_minutes=180,api_token="test-secret"); d.update(kw); return GatewaySettings(**d)
class FakeProvider:
 def __init__(self): self.calls=[]
 def provision(self,p): self.calls.append(("create",p)); return RunnerInstance("provider-1","provisioning","runner-1",tuple(p["labels"]),"accepted")
 def status(self,r): self.calls.append(("status",r)); return RunnerInstance(r,"online","runner-1",(),"online")
 def terminate(self,r): self.calls.append(("delete",r)); return RunnerInstance(r,"terminated",detail="destroyed")
class PolicyTests(unittest.TestCase):
 def test_defaults_deny_live_provisioning(self):
  with self.assertRaises(PolicyDenied) as e: GatewaySettings().authorize_provisioning(0)
  self.assertEqual(e.exception.status_code,503)
 def test_three_os_profiles_are_pinned(self):
  for os_name in PROFILES: self.assertEqual(validate_runner_request(payload(os_name),settings())["target_os"],os_name)
  bad=payload(); bad["image"]="custom"; self.assertRaises(PolicyDenied,validate_runner_request,bad,settings())
 def test_allowlist_unknown_fields_and_ephemeral_guards(self):
  bad=payload(); bad["repository"]="other/repo"; self.assertRaises(PolicyDenied,validate_runner_request,bad,settings())
  bad=payload(); bad["extra"]=1; self.assertRaises(PolicyDenied,validate_runner_request,bad,settings())
  bad=payload(); bad["ephemeral"]=False; self.assertRaises(PolicyDenied,validate_runner_request,bad,settings())
 def test_budget_approval_circuit_and_concurrency(self):
  for s,count,code in [(settings(owner_approved=False),0,403),(settings(circuit_breaker_tripped=True),0,503),(settings(budget_limit_usd=0),0,503),(settings(current_spend_usd=19),0,429),(settings(max_concurrent_runners=1),1,429)]:
   with self.subTest(code=code),self.assertRaises(PolicyDenied) as e: s.authorize_provisioning(count)
   self.assertEqual(e.exception.status_code,code)
 def test_repository_dot_segments_are_rejected(self):
  for repository in ("../repo","owner/..",". /repo"):
   with self.subTest(repository=repository):
    invalid_settings=settings(allowed_repositories=(repository,))
    with self.assertRaises(ValueError):
     invalid_settings.validate_configuration()
    bad=payload(); bad["repository"]=repository
    with self.assertRaises(PolicyDenied):
     validate_runner_request(bad,settings())
 def test_dynamic_repository_authorizer_replaces_static_allowlist(self):
  dynamic_settings=settings(allowed_repositories=())
  self.assertEqual(
   validate_runner_request(payload(),dynamic_settings,lambda repository: repository==REPO)["repository"],
   REPO,
  )
  legacy_restricted=settings(allowed_repositories=("another/repo",))
  self.assertEqual(validate_runner_request(payload(),legacy_restricted,lambda repository: repository==REPO)["repository"],REPO)
  with self.assertRaises(PolicyDenied) as denied:
   validate_runner_request(payload(),dynamic_settings,lambda repository: False)
  self.assertEqual(denied.exception.status_code,403)
  with self.assertRaises(PolicyDenied) as unavailable:
   validate_runner_request(payload(),dynamic_settings,lambda repository: (_ for _ in ()).throw(RuntimeError("offline")))
  self.assertEqual(unavailable.exception.status_code,503)
 def test_runtime_network_and_token_policy(self):
  for key,value in [("max_runtime_minutes",181),("network_policy","public"),("registration_token_handling","client")]:
   bad=payload(); bad[key]=value
   with self.subTest(key=key),self.assertRaises(PolicyDenied): validate_runner_request(bad,settings())
class LifecycleTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.store=RunnerStore(str(Path(self.tmp.name)/"db.sqlite")); self.provider=FakeProvider(); self.service=GatewayService(settings(),self.store,self.provider)
 def tearDown(self): self.tmp.cleanup()
 def test_create_online_terminate(self):
  row,new=self.service.create(payload(),"idem-key-001"); self.assertTrue(new); self.assertEqual(row["state"],"provisioning")
  self.assertEqual(self.service.get(row["id"])["state"],"online")
  self.assertEqual(self.service.terminate(row["id"])["state"],"terminated")
  self.assertEqual([x[0] for x in self.provider.calls],["create","status","delete"])
  self.assertGreaterEqual(len(self.store.audit_events(row["id"])),3)
 def test_service_revalidates_dynamic_installation_membership(self):
  service=GatewayService(
   settings(allowed_repositories=()),self.store,self.provider,
   repository_authorizer=lambda repository: repository==REPO,
  )
  row,created=service.create(payload(),"idem-key-dynamic")
  self.assertTrue(created)
  self.assertEqual(row["state"],"provisioning")
  self.assertEqual(len(self.provider.calls),1)
 def test_replay_and_conflict(self):
  a,new=self.service.create(payload(),"idem-key-002"); b,replay=self.service.create(payload(),"idem-key-002")
  self.assertTrue(new); self.assertFalse(replay); self.assertEqual(a["id"],b["id"]); self.assertEqual(len(self.provider.calls),1)
  with self.assertRaises(LifecycleConflict): self.service.create(payload("windows"),"idem-key-002")
 def test_disabled_never_invokes_provider(self):
  service=GatewayService(GatewaySettings(allowed_repositories=(REPO,)),self.store,self.provider)
  with self.assertRaises(PolicyDenied): service.create(payload(),"idem-key-003")
  self.assertEqual(self.provider.calls,[])
 def test_provider_failure_recorded_without_exception_text(self):
  class Broken(FakeProvider):
   def provision(self,p): raise RuntimeError("sensitive endpoint token")
  service=GatewayService(settings(),self.store,Broken())
  with self.assertRaises(RuntimeError): service.create(payload(),"idem-key-004")
  row=self.store.get_by_key("idem-key-004"); self.assertEqual(row["state"],"failed")
  self.assertNotIn("sensitive endpoint token",json.dumps(self.store.audit_events(row["id"])))
class HTTPTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); p=FakeProvider(); svc=GatewayService(settings(),RunnerStore(str(Path(self.tmp.name)/"http.sqlite")),p)
  self.server=ThreadingHTTPServer(("127.0.0.1",0),make_handler(svc,"test-secret")); self.thread=threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start(); self.url=f"http://127.0.0.1:{self.server.server_port}"
 def tearDown(self): self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2); self.tmp.cleanup()
 def test_auth_and_health(self):
  with urlopen(self.url+"/healthz") as r: self.assertEqual(r.status,200)
  req=Request(self.url+"/v1/runners",data=json.dumps(payload()).encode(),method="POST",headers={"Idempotency-Key":"http-key-001"})
  with self.assertRaises(HTTPError) as e: urlopen(req)
  try:
   self.assertEqual(e.exception.code,401)
  finally:
   e.exception.close()
 def test_authenticated_post_and_replay(self):
  req=Request(self.url+"/v1/runners",data=json.dumps(payload()).encode(),method="POST",headers={"Authorization":"Bearer test-secret","Idempotency-Key":"http-key-002"})
  with urlopen(req) as r: self.assertEqual(r.status,202); first=json.loads(r.read())
  with urlopen(req) as r: self.assertEqual(r.status,200); second=json.loads(r.read())
  self.assertEqual(first["id"],second["id"])
if __name__=="__main__": unittest.main()
