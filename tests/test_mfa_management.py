"""Reauthentication, delegated MFA recovery and atomic self replacement."""
import json,time,unittest
from unittest.mock import patch
import test_accounts as account_support
from test_app import LocalClient
from sedra.mfa import totp

class MFAManagementHTTPTests(unittest.TestCase):
 setUp=account_support.AccountHTTPTests.setUp
 tearDown=account_support.AccountHTTPTests.tearDown
 bootstrap=account_support.AccountHTTPTests.bootstrap
 complete_mfa=account_support.AccountHTTPTests.complete_mfa
 login=account_support.AccountHTTPTests.login
 create=account_support.AccountHTTPTests.create
 def auth(self,name='testadmin'):
  return {'password':'Synthetic-Test-Password-42','code':self.recovery[name].pop()}
 def body(self,u,action):return {'id':u['id'],'expected_version':u['auth_version'],'action':action,'reason':'access_recovery'}
 def test_remove_revokes_factor_recovery_full_and_pending_sessions_without_disabling_mfa(self):
  self.bootstrap();u=self.create('targetuser');client=self.login('targetuser')
  u=next(u for u in self.admin.request('/api/accounts')[1]['users'] if u['username']=='targetuser');old_codes=self.recovery['targetuser'][:]
  self.assertEqual(client.request('/api/accounts/mfa',self.body(u,'remove')|{'password':'unused','code':'unused'})[0],403)
  pending=LocalClient(self.base);pending.csrf=pending.request('/api/account/context')[1]['csrf_token'];pending.request('/api/account/login',{'username':'targetuser','password':'Synthetic-Test-Password-42'});pending.csrf=pending.request('/api/account/context')[1]['csrf_token']
  operator_auth=self.auth();self.assertEqual(self.admin.request('/api/accounts/mfa',self.body(u,'remove')|operator_auth)[0],200)
  self.assertEqual(client.request('/api/state')[0],401)
  self.assertEqual(pending.request('/api/account/mfa/verify',{'code':old_codes[0]})[0],403)
  self.assertFalse(self.app.accounts.mfa.status(u['id'])['enrolled']);self.assertEqual(self.app.accounts.mfa.status(u['id'])['recovery_codes_remaining'],0)
  restored=self.login('targetuser');self.assertEqual(restored.request('/api/state')[0],200)
  with self.assertRaises(PermissionError):self.app.accounts.mfa.verify(u['id'],self.app.accounts.claims(u['id'])['auth_version'],old_codes[0])
  audit=json.dumps(self.admin.request('/api/audit')[1]);self.assertIn('account_mfa_remove',audit)
  for secret in [operator_auth['password'],operator_auth['code'],*old_codes]:self.assertNotIn(secret,audit)
 def test_csrf_schema_self_reset_and_stale_directory_revision_are_denied(self):
  self.bootstrap();u=self.create('targetuser');owner=next(u for u in self.admin.request('/api/accounts')[1]['users'] if u['username']=='testadmin')
  body=self.body(u,'enroll')|self.auth();self.assertEqual(self.admin.request('/api/accounts/mfa',body,token=False)[0],403)
  self.assertEqual(self.admin.request('/api/accounts/mfa',body|{'unexpected':1})[0],400)
  self.assertEqual(self.admin.request('/api/accounts/mfa',self.body(owner,'remove')|self.auth())[0],403)
  self.assertTrue(self.app.accounts.mfa.status(owner['id'])['enrolled'])
  self.assertEqual(self.admin.request('/api/accounts/mfa',self.body(u,'enroll')|{'expected_version':999}|self.auth())[0],400)
  self.assertEqual(self.admin.request('/api/accounts/mfa',self.body(u,'enroll')|{'password':'wrong','code':'wrong-code'})[0],403)
 def test_explicit_delegation_cannot_reset_privileged_accounts_and_revocation_applies(self):
  self.bootstrap();rid=self.app.accounts.create_role({'name':'MFA Operator','base':'analyst','permissions':['accounts.read','accounts.reset_mfa']})
  operator=self.create('operator',rid,'');c=self.login('operator');target=self.create('targetuser')
  self.assertEqual(c.request('/api/accounts/mfa',self.body(target,'enroll')|self.auth('operator'))[0],200)
  owner=next(u for u in self.admin.request('/api/accounts')[1]['users'] if u['username']=='testadmin')
  self.assertEqual(c.request('/api/accounts/mfa',self.body(owner,'remove')|self.auth('operator'))[0],403)
  self.app.accounts.create_role({'action':'update','id':rid,'name':'MFA Operator','permissions':['accounts.read']})
  self.assertEqual(c.request('/api/accounts/mfa',self.body(target,'enroll')|self.auth('operator'))[0],403)
 def test_self_replacement_keeps_old_factor_until_verified_then_revokes_old_sessions(self):
  self.bootstrap();other=self.login();uid=self.admin.request('/api/account/context')[1]['account']['account_id'];old=self.app.accounts.mfa.seed(uid);old_code=self.recovery['testadmin'][0]
  s,setup=self.admin.request('/api/account/mfa/replace/start',self.auth());self.assertEqual(s,200)
  self.assertEqual(self.app.accounts.mfa.seed(uid),old)
  for path in ('/api/state','/api/portal/status'):self.assertNotIn(setup['secret'],json.dumps(self.admin.request(path)[1]))
  self.assertEqual(self.admin.request('/api/account/mfa/replace/confirm',{'code':'not-a-code'})[0],403)
  self.assertEqual(self.app.accounts.mfa.seed(uid),old)
  s,result=self.admin.request('/api/account/mfa/replace/confirm',{'code':totp(setup['secret'])});self.assertEqual(s,200);self.assertEqual(len(result['recovery_codes']),10)
  self.admin.csrf=self.admin.request('/api/account/context')[1]['csrf_token'];self.assertEqual(self.admin.request('/api/state')[0],200);self.assertEqual(other.request('/api/state')[0],401)
  self.assertEqual(self.app.accounts.mfa.seed(uid),setup['secret'])
  with self.assertRaises(PermissionError):self.app.accounts.mfa.verify(uid,self.app.accounts.claims(uid)['auth_version'],old_code)
  audit=json.dumps(self.admin.request('/api/audit')[1]);self.assertIn('mfa_replaced',audit)
  for secret in [old,setup['secret'],*result['recovery_codes']]:self.assertNotIn(secret,audit)
 def test_expired_replacement_preserves_current_authenticator(self):
  self.bootstrap();uid=self.admin.request('/api/account/context')[1]['account']['account_id'];old=self.app.accounts.mfa.seed(uid)
  self.assertEqual(self.admin.request('/api/account/mfa/replace/start',self.auth())[0],200)
  pending=next(s for s in self.app.sessions.values() if s.get('mfa_replacement'));pending['mfa_replacement']['started']=time.time()-301
  self.assertEqual(self.admin.request('/api/account/mfa/replace/confirm',{'code':'123456'})[0],403)
  self.assertEqual(self.app.accounts.mfa.seed(uid),old);self.assertEqual(self.admin.request('/api/state')[0],200)
 def test_factor_reset_racing_with_verified_claims_cannot_upgrade_authentication_version(self):
  self.bootstrap();uid=self.admin.request('/api/account/context')[1]['account']['account_id'];version=self.app.accounts.claims(uid)['auth_version'];original=self.app.accounts.claims
  def changed_claims(target):
   with self.app.accounts.db() as c:c.execute('UPDATE users SET auth_version=auth_version+1 WHERE id=?',(target,))
   return original(target)
  with patch.object(self.app.accounts,'claims',side_effect=changed_claims):
   with self.assertRaises(PermissionError):self.app.accounts.mfa.verify(uid,version,self.recovery['testadmin'].pop())
