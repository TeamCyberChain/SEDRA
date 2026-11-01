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
 def create(self,name,role='user',subject='lab-001'):
  self.assertEqual(self.admin.request('/api/accounts/users',{'username':name,'password':'Synthetic-Test-Password-42','role_id':role,'subject':subject})[0],200)
  return next(u for u in self.admin.request('/api/accounts')[1]['users'] if u['username']==name)
 def test_user_state_and_exports_exclude_other_actors_and_population_evaluation(self):
  self.bootstrap();self.create('scopeduser');c=self.login('scopeduser')
  self.app.gateway.evaluate('lab-002','other-private-request','FİN: A1B2C3D',0)
  self.app.audit('lab-002','document_read',{'doc_id':'araz-plan','classification':'controlled_excerpt'})
  status,state=c.request('/api/state');self.assertEqual(status,200)
  self.assertEqual([s['subject_id'] for s in state['subjects']],['lab-001'])
  self.assertEqual(state['demo_identities'],['lab-001']);self.assertEqual(state['evaluation'],{})
  self.assertFalse(state['alerts']['available']);self.assertFalse(state['behavior_cases']['available'])
  for key in ('requests','events','receiver'):self.assertTrue(all(x['subject_id']=='lab-001' for x in state[key]))
  self.assertNotIn('other-private-request',json.dumps(state))
  for path in ('/api/accounts','/api/audit','/api/integrations/keys','/api/alerts','/api/ueba/cases','/api/ueba?subject=lab-002'):
   self.assertEqual(c.request(path)[0],403,path)
  for path,body in (('/api/endpoint/action',{'action':'start'}),('/api/catalog/labels',{}),('/api/accounts/password',{'id':'other','password':'Synthetic-Test-Password-42'}),('/api/ueba/cases/action',{})):
   self.assertEqual(c.request(path,body)[0],403,path)
  self.assertEqual(c.request('/api/ueba?subject=lab-001')[0],200)
 def test_password_reset_revokes_all_sessions_and_is_not_logged(self):
  self.bootstrap();target=self.create('resetuser');first=self.login('resetuser');second=self.login('resetuser')
  body={'id':target['id'],'password':'New-Synthetic-Password-65'}
  self.assertEqual(first.request('/api/accounts/password',body)[0],403)
  self.assertEqual(self.admin.request('/api/accounts/password',body,token=False)[0],403)
  self.assertEqual(self.admin.request('/api/accounts/password',body|{'password':'short'})[0],400)
  self.assertEqual(self.admin.request('/api/accounts/password',body)[0],200)
  for c in (first,second):self.assertEqual(c.request('/api/state')[0],401)
  self.assertEqual(self.login('resetuser','New-Synthetic-Password-65').request('/api/state')[0],200)
  c=LocalClient(self.base);c.csrf=c.request('/api/account/context')[1]['csrf_token']
  self.assertEqual(c.request('/api/account/login',{'username':'resetuser','password':'Synthetic-Test-Password-42'})[0],403)
  audit=json.dumps(self.admin.request('/api/audit')[1]);self.assertIn('account_password_reset',audit);self.assertNotIn(body['password'],audit)
  self.assertNotIn(body['password'].encode(),Path(self.tmp.name,'accounts.sqlite').read_bytes())
 def test_disable_and_reenable_does_not_resurrect_old_session(self):
  self.bootstrap();u=self.create('disableduser');c=self.login('disableduser')
  body={'action':'update','id':u['id'],'role_id':'user','subject':'lab-001','active':False}
  self.assertEqual(self.admin.request('/api/accounts/users',body)[0],200)
  # Do not touch the old session between disabling and enabling.
  self.assertEqual(self.admin.request('/api/accounts/users',body|{'active':True})[0],200)
  self.assertEqual(c.request('/api/state')[0],401)
  self.assertEqual(self.login('disableduser').request('/api/state')[0],200)
 def test_password_reset_racing_with_login_cannot_issue_a_new_version_session(self):
  self.bootstrap();u=self.create('racinguser');owner=next(x for x in self.admin.request('/api/accounts')[1]['users'] if x['username']=='testadmin')
  actor=self.app.accounts.claims(owner['id']);original=self.app.accounts.claims;reset=[]
  def concurrent_claims(uid):
   if uid==u['id'] and not reset:
    reset.append(True);self.app.accounts.reset_password({'id':uid,'password':'New-Synthetic-Password-65'},actor)
   return original(uid)
  c=LocalClient(self.base);c.csrf=c.request('/api/account/context')[1]['csrf_token']
  with support.patch.object(self.app.accounts,'claims',side_effect=concurrent_claims):
   self.assertEqual(c.request('/api/account/login',{'username':'racinguser','password':'Synthetic-Test-Password-42'})[0],403)
  self.assertEqual(c.request('/api/state')[0],401)
  self.assertEqual(self.login('racinguser','New-Synthetic-Password-65').request('/api/state')[0],200)
 def test_delegated_account_actions_cannot_escalate_or_touch_privileged_users(self):
  self.bootstrap();perms=['accounts.read','accounts.create','accounts.update','accounts.reset_password']
  self.assertEqual(self.admin.request('/api/accounts/roles',{'name':'Account Operator','base':'analyst','permissions':perms})[0],200)
  listing=self.admin.request('/api/accounts')[1];role=next(r for r in listing['roles'] if r['name']=='Account Operator');owner=listing['users'][0]
  operator=self.create('operator',role['id'],'');c=self.login('operator');target=self.create('standardtarget')
  self.assertEqual(c.request('/api/accounts')[0],200)
  self.assertEqual(c.request('/api/accounts/roles',{'name':'Escalation','base':'administrator'})[0],403)
  body={'username':'childuser','password':'Synthetic-Test-Password-42','role_id':'user','subject':'lab-001'}
  self.assertEqual(c.request('/api/accounts/users',body)[0],200)
  for rid in ('administrator',role['id']):self.assertEqual(c.request('/api/accounts/users',body|{'username':'notcreated','role_id':rid})[0],403)
  for t in (owner,operator):
   self.assertEqual(c.request('/api/accounts/users',{'action':'update','id':t['id'],'role_id':'analyst','subject':'','active':False})[0],403)
   self.assertEqual(c.request('/api/accounts/password',{'id':t['id'],'password':'New-Synthetic-Password-65'})[0],403)
  self.assertEqual(c.request('/api/accounts/users',{'action':'update','id':target['id'],'role_id':'administrator','subject':'','active':True})[0],403)
  self.assertEqual(c.request('/api/accounts/password',{'id':target['id'],'password':'New-Synthetic-Password-65'})[0],200)
  self.assertEqual(c.request('/api/accounts/users',{'action':'update','id':target['id'],'role_id':'analyst','subject':'','active':True})[0],200)
  self.assertEqual(self.admin.request('/api/accounts/roles',{'action':'update','id':role['id'],'name':'Account Operator','permissions':['accounts.read']})[0],200)
  self.assertEqual(c.request('/api/accounts')[0],200)
  self.assertEqual(c.request('/api/accounts/users',body|{'username':'revokedaction'})[0],403)
  self.assertEqual(self.admin.request('/api/accounts/roles',{'action':'update','id':role['id'],'name':'Account Operator','permissions':[]})[0],200)
  self.assertEqual(c.request('/api/accounts')[0],403)
 def test_role_permissions_schema_and_builtin_immutability(self):
  self.bootstrap()
  for perms in (['unknown'],['accounts.create'],['accounts.read','accounts.read'],'accounts.read',[{}]):
   self.assertEqual(self.admin.request('/api/accounts/roles',{'name':'Invalid Role','base':'analyst','permissions':perms})[0],400)
  for base in ('user','administrator'):
   self.assertEqual(self.admin.request('/api/accounts/roles',{'name':'Invalid Role','base':base,'permissions':['accounts.read']})[0],400)
  for role in ('administrator','analyst','user'):
   self.assertEqual(self.admin.request('/api/accounts/roles',{'action':'update','id':role,'name':'Changed Role','permissions':[]})[0],400)
 def test_legacy_database_migration_preserves_password_and_role(self):
  import sqlite3
  from sedra.accounts import Accounts
  path=Path(self.tmp.name,'legacy.sqlite');salt='12'*16
  digest=self.app.accounts.password('Synthetic-Test-Password-42',salt)
  with sqlite3.connect(path) as c:
   c.executescript('CREATE TABLE roles(id TEXT PRIMARY KEY,name TEXT UNIQUE,base TEXT NOT NULL); CREATE TABLE users(id TEXT PRIMARY KEY,username TEXT UNIQUE,role_id TEXT,subject TEXT,salt TEXT,hash TEXT,active INTEGER);')
   c.execute('INSERT INTO roles VALUES(?,?,?)',('administrator','Administrator','administrator'))
   c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',('legacy','legacyadmin','administrator',None,salt,digest,1))
  c.close()
  migrated=Accounts(path);self.assertEqual(migrated.login({'username':'legacyadmin','password':'Synthetic-Test-Password-42'}),'legacy')
  self.assertEqual(migrated.claims('legacy')['auth_version'],0);self.assertIn('accounts.reset_password',migrated.claims('legacy')['permissions'])
