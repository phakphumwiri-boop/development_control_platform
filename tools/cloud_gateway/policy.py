"""Fail-closed policy and budget controls."""
from __future__ import annotations
import hashlib, json, math, os, re
from dataclasses import dataclass
from typing import Mapping
PROFILES={"linux":{"image":"ubuntu-24.04-x64","labels":["self-hosted","Linux","X64","dcp-cloud-linux"],"provider":"azure"},"windows":{"image":"windows-2025-x64","labels":["self-hosted","Windows","X64","dcp-cloud-windows"],"provider":"azure"},"macos":{"image":"macos-15-arm64","labels":["self-hosted","macOS","ARM64","dcp-cloud-macos"],"provider":"orka"}}
FIELDS={"repository","workflow_run_id","commit_sha","target_os","image","labels","ephemeral","max_runtime_minutes","network_policy","registration_token_handling"}
REPO=re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"); SHA=re.compile(r"^[0-9a-f]{40}$")
def valid_repository_name(value):
 if not isinstance(value,str) or not REPO.fullmatch(value): return False
 owner,name=value.split("/",1)
 return owner not in (".","..") and name not in (".","..")
class PolicyDenied(ValueError):
 def __init__(self,message,status_code=403): super().__init__(message); self.status_code=status_code
@dataclass(frozen=True)
class GatewaySettings:
 provisioning_enabled:bool=False; owner_approved:bool=False; allowed_repositories:tuple[str,...]=()
 budget_limit_usd:float=0; current_spend_usd:float=0; projected_run_cost_usd:float=0
 circuit_breaker_tripped:bool=False; max_concurrent_runners:int=1; max_runtime_minutes:int=180; api_token:str=""
 @classmethod
 def from_env(cls,env:Mapping[str,str]|None=None):
  e=os.environ if env is None else env
  def flag(k): return e.get(k,"false").lower()=="true"
  def amount(k):
   try: n=float(e.get(k,"0"))
   except ValueError as x: raise ValueError(k+" must be numeric") from x
   if not math.isfinite(n) or n<0: raise ValueError(k+" must be finite and non-negative")
   return n
  return cls(flag("DCP_GATEWAY_PROVISIONING_ENABLED"),flag("DCP_GATEWAY_OWNER_APPROVED"),tuple(x.strip() for x in e.get("DCP_GATEWAY_ALLOWED_REPOSITORIES","").split(",") if x.strip()),amount("DCP_GATEWAY_BUDGET_LIMIT_USD"),amount("DCP_GATEWAY_CURRENT_SPEND_USD"),amount("DCP_GATEWAY_PROJECTED_RUN_COST_USD"),flag("DCP_GATEWAY_CIRCUIT_BREAKER"),int(e.get("DCP_GATEWAY_MAX_CONCURRENT","1")),int(e.get("DCP_GATEWAY_MAX_RUNTIME_MINUTES","180")),e.get("DCP_GATEWAY_API_TOKEN",""))
 def validate_configuration(self):
  if any(not valid_repository_name(x) for x in self.allowed_repositories) or len(set(self.allowed_repositories))!=len(self.allowed_repositories): raise ValueError("Invalid or duplicate repository allowlist")
  if not 1<=self.max_concurrent_runners<=100: raise ValueError("Concurrency must be 1..100")
  if not 5<=self.max_runtime_minutes<=180: raise ValueError("Runtime must be 5..180 minutes")
  for value in (self.budget_limit_usd,self.current_spend_usd,self.projected_run_cost_usd):
   if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value<0: raise ValueError("Budget values must be finite non-negative numbers")
 def authorize_provisioning(self,active_count,dynamic_repository_authorization=False):
  self.validate_configuration()
  if not self.provisioning_enabled: raise PolicyDenied("Live provisioning is disabled",503)
  if not self.owner_approved: raise PolicyDenied("Owner approval is required",403)
  if not self.allowed_repositories and not dynamic_repository_authorization: raise PolicyDenied("Repository authorization is not configured",403)
  if self.circuit_breaker_tripped: raise PolicyDenied("Budget circuit breaker is tripped",503)
  if self.budget_limit_usd<=0: raise PolicyDenied("Positive approved budget ceiling required",503)
  if self.current_spend_usd+self.projected_run_cost_usd>self.budget_limit_usd: raise PolicyDenied("Projected spend exceeds budget ceiling",429)
  if active_count>=self.max_concurrent_runners: raise PolicyDenied("Concurrency limit reached",429)
def validate_runner_request(payload,settings,repository_authorizer=None):
 if not isinstance(payload,dict) or set(payload)!=FIELDS: raise PolicyDenied("Request fields do not match contract",400)
 repo=payload["repository"]
 if not valid_repository_name(repo): raise PolicyDenied("Invalid owner/name repository",400)
 if callable(repository_authorizer):
  try:
   allowed=repository_authorizer(repo)
  except Exception:
   raise PolicyDenied("Repository installation membership could not be verified",503)
  if allowed is not True: raise PolicyDenied("Repository is not accessible to the DCP GitHub App installation",403)
 elif repo not in settings.allowed_repositories:
  raise PolicyDenied("Repository is not allowlisted and dynamic installation authorization is unavailable",403)
 run=payload["workflow_run_id"]
 if isinstance(run,bool) or not isinstance(run,int) or run<1: raise PolicyDenied("workflow_run_id must be positive",400)
 if not isinstance(payload["commit_sha"],str) or not SHA.fullmatch(payload["commit_sha"]): raise PolicyDenied("commit_sha must be lowercase 40-character SHA",400)
 os_name=payload["target_os"]
 if not isinstance(os_name,str) or os_name not in PROFILES: raise PolicyDenied("Unsupported target OS",400)
 profile=PROFILES[os_name]
 if payload["image"]!=profile["image"] or payload["labels"]!=profile["labels"]: raise PolicyDenied("Image and labels must match server profile",400)
 if payload["ephemeral"] is not True: raise PolicyDenied("Only ephemeral runners are allowed",400)
 runtime=payload["max_runtime_minutes"]
 if isinstance(runtime,bool) or not isinstance(runtime,int) or not 5<=runtime<=min(180,settings.max_runtime_minutes): raise PolicyDenied("Runtime is outside approved bound",400)
 if payload["network_policy"]!="restricted-egress" or payload["registration_token_handling"]!="provider-side-only": raise PolicyDenied("Network or token policy violation",400)
 return dict(payload)
def idempotency_fingerprint(payload):
 return hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
