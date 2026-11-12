"""Minimal Azure Managed Identity token client; no client secrets are supported."""
from __future__ import annotations
import json, os
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

class IdentityError(RuntimeError): pass

class ManagedIdentityCredential:
 def __init__(self,env=None,timeout=3):
  self.env=os.environ if env is None else env; self.timeout=timeout
 def get_token(self,resource):
  endpoint=self.env.get("IDENTITY_ENDPOINT")
  if endpoint:
   try:
    parsed=urlparse(endpoint)
    _=parsed.port
   except ValueError as exc:
    raise IdentityError("Untrusted managed identity endpoint configuration") from exc
   if (parsed.scheme!="http" or parsed.hostname not in ("localhost","127.0.0.1","::1")
       or parsed.username is not None or parsed.password is not None or parsed.fragment
       or not self.env.get("IDENTITY_HEADER")):
    raise IdentityError("Untrusted managed identity endpoint configuration")
   params={"api-version":"2019-08-01","resource":resource}
   if self.env.get("AZURE_CLIENT_ID"): params["client_id"]=self.env["AZURE_CLIENT_ID"]
   url=endpoint+("&" if "?" in endpoint else "?")+urlencode(params)
   headers={"Metadata":"true"}
   identity_header=self.env["IDENTITY_HEADER"]
  elif self.env.get("DCP_AZURE_USE_IMDS","false").lower()=="true":
   params={"api-version":"2018-02-01","resource":resource}
   if self.env.get("AZURE_CLIENT_ID"): params["client_id"]=self.env["AZURE_CLIENT_ID"]
   url="http://169.254.169.254/metadata/identity/oauth2/token?"+urlencode(params)
   headers={"Metadata":"true"}
   identity_header=None
  else:
   raise IdentityError("Managed identity endpoint is unavailable; refusing client-secret fallback")
  try:
   req=Request(url,headers=headers)
   if identity_header: req.add_unredirected_header("X-IDENTITY-HEADER",identity_header)
   with urlopen(req,timeout=self.timeout) as response: data=json.loads(response.read(65537).decode("utf-8"))
  except Exception as exc:
   raise IdentityError("Managed identity token request failed: "+type(exc).__name__) from exc
  token=data.get("access_token") if isinstance(data,dict) else None
  if not isinstance(token,str) or not token: raise IdentityError("Managed identity returned no access token")
  return token
