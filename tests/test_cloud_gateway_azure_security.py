"""Mock-only tests for Managed Identity, Key Vault, and Azure budget reads."""
import json,unittest,time
from datetime import datetime,timedelta,timezone
from unittest.mock import patch,MagicMock
from tools.cloud_gateway.azure_identity import ManagedIdentityCredential,IdentityError
from tools.cloud_gateway.key_vault import KeyVaultSecretReader
from tools.cloud_gateway.azure_budget import AzureBudgetReader,BudgetSnapshot,BudgetReadError
from tools.cloud_gateway.azure_vm import AzureArmClient
class CredentialTests(unittest.TestCase):
 def test_no_secret_fallback_when_identity_missing(self):
  with self.assertRaises(IdentityError): ManagedIdentityCredential(env={}).get_token("https://vault.azure.net")
 def test_identity_endpoint_uses_local_header_and_resource(self):
  env={"IDENTITY_ENDPOINT":"http://localhost:42356/msi/token","IDENTITY_HEADER":"header-value"}
  response=MagicMock(); response.__enter__.return_value=response; response.headers={"Content-Type":"application/json"}; response.read.return_value=json.dumps({"access_token":"opaque-token","token_type":"Bearer","expires_on":str(int(time.time())+3600)}).encode()
  with patch("tools.cloud_gateway.azure_identity.urlopen",return_value=response) as call:
   self.assertEqual(ManagedIdentityCredential(env).get_token("https://vault.azure.net"),"opaque-token")
  req=call.call_args.args[0]; self.assertEqual(req.get_header("X-identity-header"),"header-value"); self.assertTrue(any(k.lower()=="x-identity-header" for k in req.unredirected_hdrs)); self.assertIn("resource=https%3A%2F%2Fvault.azure.net",req.full_url)
 def test_untrusted_identity_endpoint_rejected(self):
  env={"IDENTITY_ENDPOINT":"https://attacker.example/token","IDENTITY_HEADER":"x"}
  with self.assertRaises(IdentityError): ManagedIdentityCredential(env).get_token("resource")
class AzureArmHeaderTests(unittest.TestCase):
 def test_arm_bearer_token_is_unredirected(self):
  credential=MagicMock(); credential.get_token.return_value="arm-token"
  response=MagicMock(); response.__enter__.return_value=response; response.read.return_value=b"{}"; response.status=200; response.headers={}
  with patch("tools.cloud_gateway.azure_vm.urlopen",return_value=response) as call:
   AzureArmClient("00000000-0000-0000-0000-000000000000","dcp",credential).request("GET","https://management.azure.com/subscriptions/test")
  req=call.call_args.args[0]
  self.assertEqual(req.get_header("Authorization"),"Bearer arm-token")
  self.assertTrue(any(k.lower()=="authorization" for k in req.unredirected_hdrs))

class KeyVaultTests(unittest.TestCase):
 def test_rejects_non_azure_vault_origin(self):
  with self.assertRaises(ValueError): KeyVaultSecretReader("https://example.com")
 def test_secret_read_uses_managed_identity_and_never_logs_value(self):
  credential=MagicMock(); credential.get_token.return_value="access"
  response=MagicMock(); response.__enter__.return_value=response; response.headers={"Content-Type":"application/json"}; response.read.return_value=b'{"value":"secret-value"}'
  with patch("tools.cloud_gateway.key_vault.urlopen",return_value=response) as call:
   value=KeyVaultSecretReader("https://demo.vault.azure.net",credential).get_secret("orka-token")
  self.assertEqual(value,"secret-value"); req=call.call_args.args[0]; self.assertIn("/secrets/orka-token?api-version=7.4",req.full_url); self.assertTrue(any(k.lower()=="authorization" for k in req.unredirected_hdrs))
 def test_invalid_secret_name_rejected(self):
  reader=KeyVaultSecretReader("https://demo.vault.azure.net",MagicMock())
  with self.assertRaises(ValueError): reader.get_secret("../leak")
def active_period():
 now=datetime.now(timezone.utc)
 return {"startDate":(now-timedelta(days=1)).isoformat(),"endDate":(now+timedelta(days=30)).isoformat()}

class BudgetTests(unittest.TestCase):
 def test_budget_permit_checks_current_forecast_and_currency(self):
  self.assertTrue(BudgetSnapshot(100,20,70,"USD").permits(10))
  self.assertFalse(BudgetSnapshot(100,95,None,"USD").permits(10))
  self.assertFalse(BudgetSnapshot(100,20,95,"USD").permits(10))
  self.assertFalse(BudgetSnapshot(100,20,None,"THB").permits(1))
 def test_budget_reader_is_read_only_and_parses_budget(self):
  credential=MagicMock(); credential.get_token.return_value="arm-token"
  response=MagicMock(); response.__enter__.return_value=response
  response.read.return_value=json.dumps({"properties":{"category":"Cost","timePeriod":active_period(),"amount":50,"currentSpend":{"amount":12,"unit":"USD"},"forecastSpend":{"amount":35,"unit":"USD"}}}).encode()
  with patch("tools.cloud_gateway.azure_budget.urlopen",return_value=response) as call:
   snapshot=AzureBudgetReader("00000000-0000-0000-0000-000000000000","dcp-monthly",credential).read()
  self.assertEqual(snapshot.current_spend,12); self.assertTrue(snapshot.permits(3))
  req=call.call_args.args[0]; self.assertEqual(req.get_method(),"GET"); self.assertTrue(any(k.lower()=="authorization" for k in req.unredirected_hdrs))
 def test_budget_snapshot_rejects_nonfinite_and_negative_values(self):
  for values in ((float("nan"),1,1,"USD"),(100,-1,1,"USD"),(100,1,float("inf"),"USD"),(100,20,10,"USD")):
   with self.assertRaises(ValueError): BudgetSnapshot(*values)
 def test_missing_or_mismatched_forecast_fails_closed(self):
  credential=MagicMock(); credential.get_token.return_value="token"
  for forecast in (None,{"amount":20,"unit":"THB"}):
   response=MagicMock(); response.__enter__.return_value=response
   body={"properties":{"timePeriod":active_period(),"amount":50,"currentSpend":{"amount":12,"unit":"USD"}}}
   if forecast is not None: body["properties"]["forecastSpend"]=forecast
   response.read.return_value=json.dumps(body).encode()
   with patch("tools.cloud_gateway.azure_budget.urlopen",return_value=response):
    with self.assertRaises(BudgetReadError): AzureBudgetReader("00000000-0000-0000-0000-000000000000","dcp-budget",credential).read()
 def test_usage_budget_is_not_accepted_as_currency_budget(self):
  credential=MagicMock(); credential.get_token.return_value="token"
  response=MagicMock(); response.__enter__.return_value=response
  body={"properties":{"category":"Usage","timePeriod":active_period(),"amount":50,"currentSpend":{"amount":12,"unit":"USD"},"forecastSpend":{"amount":35,"unit":"USD"}}}
  response.read.return_value=json.dumps(body).encode()
  with patch("tools.cloud_gateway.azure_budget.urlopen",return_value=response):
   with self.assertRaises(BudgetReadError): AzureBudgetReader("00000000-0000-0000-0000-000000000000","dcp-budget",credential).read()
 def test_budget_reader_rejects_expired_budget_period(self):
  credential=MagicMock(); credential.get_token.return_value="token"
  old={"startDate":"2020-01-01T00:00:00+00:00","endDate":"2021-01-01T00:00:00+00:00"}
  response=MagicMock(); response.__enter__.return_value=response
  response.read.return_value=json.dumps({"properties":{"category":"Cost","timePeriod":old,"amount":50,"currentSpend":{"amount":12,"unit":"USD"},"forecastSpend":{"amount":35,"unit":"USD"}}}).encode()
  with patch("tools.cloud_gateway.azure_budget.urlopen",return_value=response):
   with self.assertRaises(BudgetReadError): AzureBudgetReader("00000000-0000-0000-0000-000000000000","dcp-budget",credential).read()
 def test_invalid_budget_data_fails_closed(self):
  credential=MagicMock(); credential.get_token.return_value="token"
  response=MagicMock(); response.__enter__.return_value=response; response.read.return_value=b'{}'
  with patch("tools.cloud_gateway.azure_budget.urlopen",return_value=response):
   with self.assertRaises(BudgetReadError): AzureBudgetReader("00000000-0000-0000-0000-000000000000","dcp-budget",credential).read()
if __name__=="__main__": unittest.main()
