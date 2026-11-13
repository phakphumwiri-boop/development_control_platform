"""MacStadium Orka adapter. Runner-online evidence is checked separately from VM state."""
from __future__ import annotations
import json,re,uuid
from urllib.error import HTTPError,URLError
from urllib.parse import quote,urlparse
from urllib.request import Request
from tools.cloud_gateway.safe_http import open_no_redirect, read_bounded, require_json_content_type
from tools.runner_backend.provider import RunnerInstance


def urlopen(request, timeout=20):
 return open_no_redirect(request, timeout=timeout)

class OrkaError(RuntimeError): pass
class OrkaProvider:
 budget_provider="orka"
 requires_runner_cleanup=True
 requires_budget_guard=True
 def __init__(self,base_url,namespace,vm_config,secret_reader,secret_name="orka-api-token",runner_online_checker=None,runner_userdata_factory=None,timeout=20):
  parsed=urlparse(base_url)
  if parsed.scheme!="https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.path not in ("","/") or parsed.query or parsed.fragment: raise ValueError("Orka endpoint must be an HTTPS origin")
  if not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?",namespace): raise ValueError("Invalid Orka namespace")
  if not re.fullmatch(r"[A-Za-z0-9_.-]{1,63}",vm_config): raise ValueError("Invalid approved Orka VM config")
  if not re.fullmatch(r"[A-Za-z0-9-]{1,127}",secret_name): raise ValueError("Invalid Key Vault secret name")
  if isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or not 1<=timeout<=30: raise ValueError("Orka timeout must be 1..30 seconds")
  self.base=base_url.rstrip("/"); self.namespace=namespace; self.vm_config=vm_config
  self.secret_reader=secret_reader; self.secret_name=secret_name; self.online=runner_online_checker; self.runner_userdata_factory=runner_userdata_factory; self.timeout=timeout
 def _request(self,method,path,payload=None,allow_missing=False):
  token=self.secret_reader.get_secret(self.secret_name)
  if not isinstance(token,str) or not token or len(token)>8192 or "\\r" in token or "\\n" in token: raise OrkaError("Orka API credential is invalid")
  body=None if payload is None else json.dumps(payload,separators=(",",":")).encode()
  req=Request(self.base+path,data=body,method=method,headers={"Accept":"application/json","Content-Type":"application/json","User-Agent":"DCP-Orka-Adapter/1.0"})
  req.add_unredirected_header("Authorization","Bearer "+token)
  try:
   with urlopen(req,timeout=self.timeout) as response:
    raw=read_bounded(response,65536)
    if raw: require_json_content_type(response)
  except HTTPError as exc:
   try:
    if allow_missing and exc.code==404: return None
    raise OrkaError("Orka API request failed with HTTP "+str(exc.code)) from exc
   finally:
    exc.close()
  except (URLError,TimeoutError) as exc: raise OrkaError("Orka API request failed: "+type(exc).__name__) from exc
  except ValueError as exc:
   if "size limit" in str(exc): raise OrkaError("Orka response exceeded size limit") from exc
   raise OrkaError("Orka API response failed validation") from exc
  if not raw: return {}
  try: data=json.loads(raw.decode("utf-8"))
  except (UnicodeDecodeError,json.JSONDecodeError) as exc: raise OrkaError("Orka returned malformed JSON") from exc
  if not isinstance(data,dict): raise OrkaError("Orka returned an invalid response shape")
  return data
 def _namespace_path(self,resource):
  return "/api/v1/namespaces/"+quote(self.namespace,safe="")+"/"+resource
 def _list_items(self,resource):
  data=self._request("GET",self._namespace_path(resource))
  items=data.get("items")
  if not isinstance(items,list) or any(not isinstance(item,dict) for item in items):
   raise OrkaError("Orka returned an invalid "+resource+" inventory")
  return items
 def list_images(self):
  """Read-only inventory; does not create or modify Orka resources."""
  return self._list_items("images")
 def list_vm_configs(self):
  """Read-only VM-config inventory; does not create or modify resources."""
  return self._list_items("vmconfigs")
 def create_vm_config(self,config,*,approved=False):
  """Create a VM config only after an explicit caller-side approval.

  This creates configuration metadata, not a VM. Existing names are rejected
  to avoid accidental replacement or ambiguity.
  """
  if approved is not True:
   raise OrkaError("VM config creation requires explicit approval")
  if not isinstance(config,dict):
   raise OrkaError("VM config must be an object")
  allowed={"cpu","displayDPI","displayHeight","displayWidth","gpuPassthrough","image","iso","legacyIO","memory","name","netBoost","nodeName","scheduler","systemSerial","tag","tagRequired","vncConsole"}
  if set(config)-allowed:
   raise OrkaError("VM config contains unsupported fields")
  name=config.get("name"); image=config.get("image")
  if not isinstance(name,str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,63}",name):
   raise OrkaError("Invalid VM config name")
  if not isinstance(image,str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,127}",image):
   raise OrkaError("Invalid VM image name")
  cpu=config.get("cpu")
  if isinstance(cpu,bool) or not isinstance(cpu,int) or cpu<=0:
   raise OrkaError("VM config cpu must be a positive integer")
  memory=config.get("memory")
  if isinstance(memory,bool) or not isinstance(memory,(int,float)) or memory<=0:
   raise OrkaError("VM config memory must be positive")
  existing=self.list_vm_configs()
  if any(item.get("name")==name for item in existing):
   raise OrkaError("VM config already exists; refusing to overwrite")
  result=self._request("POST",self._namespace_path("vmconfigs"),config)
  if result.get("name")!=name:
   raise OrkaError("Orka did not confirm the created VM config")
  return result
 def readiness(self,os_name):
  if os_name!="macos": return {"ready":False,"message":"Orka supports only the approved macOS profile"}
  if self.online is None: return {"ready":False,"message":"Independent GitHub runner-online verification is not configured"}
  return {"ready":False,"message":"Orka User Data exposure controls and provider-specific cost guard are not verified; macOS runner remains disabled"}
 def provision(self,payload):
  if payload.get("target_os")!="macos" or payload.get("image")!="macos-15-arm64": raise OrkaError("Orka adapter accepts only the approved macOS 15 ARM64 profile")
  if payload.get("ephemeral") is not True or payload.get("network_policy")!="restricted-egress": raise OrkaError("Orka request violates ephemeral network policy")
  name="dcp-"+str(payload["workflow_run_id"])+"-"+uuid.uuid4().hex[:8]
  metadata={"managed-by":"dcp-cloud-runner","repository":payload["repository"],"workflow-run-id":str(payload["workflow_run_id"]),"commit-sha":payload["commit_sha"],"target-os":"macos"}
  body={"name":name,"vmConfig":self.vm_config,"shouldGenerateName":False,"customMetadata":metadata}
  if self.runner_userdata_factory is None:
   raise OrkaError("Orka first-boot User Data bootstrap is not configured")
  try:
   userdata=self.runner_userdata_factory(name,payload)
  except Exception as exc:
   raise OrkaError("Orka runner bootstrap payload could not be prepared") from exc
  if not isinstance(userdata,str) or not userdata or len(userdata)>90000 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}",userdata):
   raise OrkaError("Orka runner bootstrap must return a bounded Base64 User Data script")
  body["userdata"]=userdata
  path="/api/v1/namespaces/"+quote(self.namespace,safe="")+"/vms/"+quote(name,safe="")
  collection="/api/v1/namespaces/"+quote(self.namespace,safe="")+"/vms"
  try:
   data=self._request("POST",collection,body)
  except Exception as original:
   if self._rollback_partial_vm(path):
    error=OrkaError("Orka provisioning failed; VM cleanup is pending")
    error.provider_id=name
    raise error from original
   raise
  vm_name=data.get("name")
  if not isinstance(vm_name,str) or vm_name!=name:
   if self._rollback_partial_vm(path):
    error=OrkaError("Orka did not confirm VM identity; cleanup is pending")
    error.provider_id=name
    raise error
   raise OrkaError("Orka did not confirm the requested VM identity")
  return RunnerInstance(vm_name,"provisioning",vm_name,tuple(payload["labels"]),"VM accepted; runner registration pending")
 def _rollback_partial_vm(self,path):
  try:
   existing=self._request("GET",path,allow_missing=True)
   if existing is None: return False
   self._request("DELETE",path,allow_missing=True)
   return self._request("GET",path,allow_missing=True) is not None
  except Exception:
   return True
 def status(self,provider_id):
  if not isinstance(provider_id,str) or not re.fullmatch(r"dcp-[0-9]+-[a-f0-9]{8}",provider_id): raise OrkaError("Invalid DCP Orka VM identifier")
  path="/api/v1/namespaces/"+quote(self.namespace,safe="")+"/vms/"+quote(provider_id,safe="")
  data=self._request("GET",path,allow_missing=True)
  if data is None: return RunnerInstance(provider_id,"terminated")
  vm_status=str(data.get("status","")).lower()
  if vm_status in ("failed","error","crashed"):
   self._request("DELETE",path,allow_missing=True)
   state="terminating"
  elif vm_status in ("deleting","terminating"): state="terminating"
  elif vm_status in ("running","ready") and self.online:
   metadata=data.get("customMetadata",{})
   repository=metadata.get("repository") if isinstance(metadata,dict) else None
   try: online=self.online(provider_id,repository,"macos") is True
   except Exception: online=False
   state="online" if online else "provisioning"
  else: state="provisioning"
  return RunnerInstance(provider_id,state,provider_id)
 def terminate(self,provider_id):
  if not isinstance(provider_id,str) or not re.fullmatch(r"dcp-[0-9]+-[a-f0-9]{8}",provider_id): raise OrkaError("Invalid DCP Orka VM identifier")
  path="/api/v1/namespaces/"+quote(self.namespace,safe="")+"/vms/"+quote(provider_id,safe="")
  result=self._request("DELETE",path,allow_missing=True)
  if result is None: return RunnerInstance(provider_id,"terminated")
  return RunnerInstance(provider_id,"terminating")
