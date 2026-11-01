"""Actual local account bootstrap, sign-in and RBAC enforcement."""
import json,unittest
from pathlib import Path
import test_integrations as support
from test_app import LocalClient
class AccountHTTPTests(unittest.TestCase):
 setUp=support.IntegrationHTTPTests.setUp
 tearDown=support.IntegrationHTTPTests.tearDown
 def bootstrap(self):
  s,v=self.admin.request('/api/account/bootstrap',{'username':'testadmin','password':'Synthetic-Test-Password-42','role_id':'administrator','subject':''});self.assertEqual(s,200);self.admin.csrf=self.admin.request('/api/account/context')[1]['csrf_token']
 def login(self,name='testadmin',password='Synthetic-Test-Password-42'):
  c=LocalClient(self.base);s,v=c.request('/api/account/context');self.assertEqual(s,200);c.csrf=v['csrf_token'];self.assertEqual(c.request('/api/account/login',{'username':name,'password':password})[0],200);c.csrf=c.request('/api/account/context')[1]['csrf_token'];return c
 def test_bootstrap_closes_demo_switching_rotates_sessions_and_requires_login(self):
  old=LocalClient(self.base).login('lab-001');self.bootstrap()
  self.assertEqual(old.request('/api/state')[0],401)
  self.assertEqual(self.admin.request('/api/session',{'identity':'lab-001'})[0],403)
  self.assertEqual(self.admin.request('/api/account/bootstrap',{'username':'another','password':'Synthetic-Test-Password-42','role_id':'administrator','subject':''})[0],403)
  c=self.login();self.assertEqual(c.request('/api/accounts')[0],200)
  self.assertEqual(c.request('/api/state')[1]['session']['access_profile'],'administrator')
  self.assertEqual(c.request('/api/accounts/users',{'username':'invalidtype','password':'Synthetic-Test-Password-42','role_id':[],'subject':''})[0],400)
  with support.patch.dict('os.environ',{'SEDRA_OIDC_CONFIG':'not-read'}):
   with self.assertRaises(ValueError):support.AppState(self.tmp.name)
  self.assertNotIn('Synthetic-Test-Password-42',json.dumps(c.request('/api/audit')[1]))
  raw=Path(self.tmp.name,'accounts.sqlite').read_bytes();self.assertNotIn(b'Synthetic-Test-Password-42',raw)
 def test_user_cannot_manage_accounts_or_read_audit_and_role_changes_apply_immediately(self):
  self.bootstrap();s,_=self.admin.request('/api/accounts/users',{'username':'testuser','password':'Synthetic-Test-Password-42','role_id':'user','subject':'lab-001'});self.assertEqual(s,200)
  u=self.login('testuser');self.assertEqual(u.request('/api/accounts')[0],403);self.assertEqual(u.request('/api/audit')[0],403)
  self.assertEqual(u.request('/api/accounts/roles',{'name':'Escalation','base':'administrator'})[0],403)
  self.assertEqual(u.request('/api/ueba?subject=lab-002')[0],403)
  listing=self.admin.request('/api/accounts')[1];target=next(x for x in listing['users'] if x['username']=='testuser')
  self.assertEqual(self.admin.request('/api/accounts/users',{'action':'update','id':target['id'],'role_id':'analyst','subject':'','active':True})[0],200)
  self.assertEqual(u.request('/api/audit')[0],200);self.assertEqual(u.request('/api/accounts')[0],403)
  self.admin.request('/api/accounts/users',{'action':'update','id':target['id'],'role_id':'analyst','subject':'','active':False})
  self.assertEqual(u.request('/api/state')[0],401)
 def test_last_admin_custom_role_and_login_throttle(self):
  self.bootstrap();v=self.admin.request('/api/accounts')[1];uid=v['users'][0]['id']
  self.assertEqual(self.admin.request('/api/accounts/users',{'action':'update','id':uid,'role_id':'user','subject':'lab-001','active':True})[0],400)
  self.assertEqual(self.admin.request('/api/accounts/roles',{'name':'SOC Reviewer','base':'analyst'})[0],200)
  self.assertEqual(self.admin.request('/api/accounts/roles',{'name':'SOC Reviewer','base':'user'})[0],400)
  c=LocalClient(self.base);v=c.request('/api/account/context')[1];c.csrf=v['csrf_token']
  self.assertEqual(c.request('/api/account/login',{'username':'testadmin','password':'wrong'},token=False)[0],403)
  for _ in range(5):self.assertEqual(c.request('/api/account/login',{'username':'testadmin','password':'wrong'})[0],403)
  self.assertIn('limited',c.request('/api/account/login',{'username':'testadmin','password':'Synthetic-Test-Password-42'})[1]['error'])
