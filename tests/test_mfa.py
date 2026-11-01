"""Mandatory second-factor gates, RFC vectors, replay and recovery behavior."""
import base64,concurrent.futures,json,tempfile,time,unittest
from pathlib import Path
from sedra.accounts import Accounts
from sedra.mfa import totp
from test_app import LocalClient
import test_integrations as support

class MFACryptoTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.a=Accounts(Path(self.tmp.name)/'accounts.sqlite');self.uid=self.a.create_user({'username':'fictional','password':'Fictional-Password-42','role_id':'user','subject':'lab-001'},{'lab-001'})
 def tearDown(self):self.tmp.cleanup()
 def test_rfc6238_sha1_vectors(self):
  seed=base64.b32encode(b'12345678901234567890').decode()
  for at,want in [(59,'94287082'),(1111111109,'07081804'),(1111111111,'14050471'),(1234567890,'89005924'),(2000000000,'69279037'),(20000000000,'65353130')]:self.assertEqual(totp(seed,at,8),want)
 def enroll(self,now=1234567890):
  e=self.a.mfa.enrollment('fictional');r=self.a.mfa.verify(self.uid,0,totp(e['secret'],now),enrollment_seed=e['secret'],now=now);return e,r
 def test_seed_sealed_recovery_hashed_and_codes_one_use(self):
  e,r=self.enroll();raw=Path(self.a.path).read_bytes();self.assertNotIn(e['secret'].encode(),raw)
  self.assertEqual(len(r['recovery_codes']),10)
  for code in r['recovery_codes']:self.assertNotIn(code.encode(),raw)
  version=r['claims']['auth_version'];code=r['recovery_codes'][0]
  self.assertTrue(self.a.mfa.verify(self.uid,version,code,now=1234567920)['used_recovery'])
  with self.assertRaises(PermissionError):self.a.mfa.verify(self.uid,version,code,now=1234567921)
  self.assertEqual(self.a.mfa.status(self.uid)['recovery_codes_remaining'],9)
  self.assertEqual(Accounts(self.a.path).mfa.seed(self.uid),e['secret'])
 def test_atomic_totp_replay_prevention_and_version_binding(self):
  e,r=self.enroll();version=r['claims']['auth_version'];now=1234567920;code=totp(e['secret'],now)
  def verify(_):
   try:self.a.mfa.verify(self.uid,version,code,now=now);return True
   except PermissionError:return False
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:self.assertEqual(sum(pool.map(verify,range(2))),1)
  with self.assertRaises(PermissionError):self.a.mfa.verify(self.uid,0,totp(e['secret'],now+30),now=now+30)
 def test_attempt_throttle_and_expired_codes(self):
  e,r=self.enroll();version=r['claims']['auth_version']
  for _ in range(4):
   with self.assertRaises(PermissionError):self.a.mfa.verify(self.uid,version,'invalid-code',now=1234567891)
  with self.assertRaisesRegex(PermissionError,'limited'):self.a.mfa.verify(self.uid,version,totp(e['secret'],1234567920),now=1234567920)
  self.assertTrue(self.a.mfa.verify(self.uid,version,totp(e['secret'],1234568220),now=1234568220)['claims'])

class MFAHTTPTests(unittest.TestCase):
 setUp=support.IntegrationHTTPTests.setUp
 tearDown=support.IntegrationHTTPTests.tearDown
 def test_password_stage_cannot_read_application_and_enrollment_requires_valid_csrf_code(self):
  self.admin.request('/api/account/bootstrap',{'username':'testadmin','password':'Fictional-Password-42','role_id':'administrator','subject':''})
  self.admin.csrf=self.admin.request('/api/account/context')[1]['csrf_token']
  self.assertEqual(self.admin.request('/api/state')[0],401)
  self.assertEqual(self.admin.request('/api/account/mfa/enroll',{},token=False)[0],403)
  status,e=self.admin.request('/api/account/mfa/enroll',{});self.assertEqual(status,200)
  self.assertTrue(e['qr_data_url'].startswith('data:image/svg+xml;base64,'))
  self.assertEqual(self.admin.request('/api/account/mfa/verify',{'code':'wrong-code'})[0],403)
  status,r=self.admin.request('/api/account/mfa/verify',{'code':totp(e['secret'])});self.assertEqual(status,200)
  self.assertEqual(self.admin.request('/api/state')[0],200)
  c=LocalClient(self.base);c.csrf=c.request('/api/account/context')[1]['csrf_token']
  s,p=c.request('/api/account/login',{'username':'testadmin','password':'Fictional-Password-42'});self.assertEqual(s,200);self.assertTrue(p['mfa_required']);self.assertFalse(p['signed_in'])
  c.csrf=c.request('/api/account/context')[1]['csrf_token'];self.assertEqual(c.request('/api/state')[0],401)
  self.assertEqual(c.request('/api/account/mfa/enroll',{})[0],403)
  self.assertEqual(c.request('/api/account/mfa/verify',{'code':r['recovery_codes'][0]})[0],200)
  audit=json.dumps(self.admin.request('/api/audit')[1]);self.assertNotIn(e['secret'],audit)
  for code in r['recovery_codes']:self.assertNotIn(code,audit)
 def test_no_password_verified_session_cannot_enroll_or_use_mfa_routes(self):
  c=LocalClient(self.base);c.csrf=c.request('/api/account/context')[1]['csrf_token']
  self.assertEqual(c.request('/api/account/mfa/enroll',{})[0],403)
  self.assertEqual(c.request('/api/account/mfa/verify',{'code':'123456'})[0],403)
 def test_late_revoked_cookie_cannot_overwrite_completed_mfa_session(self):
  import urllib.request,urllib.error
  self.admin.request('/api/account/bootstrap',{'username':'testadmin','password':'Fictional-Password-42','role_id':'administrator','subject':''})
  self.admin.csrf=self.admin.request('/api/account/context')[1]['csrf_token']
  stale=urllib.request.Request(self.base+'/api/audit/context')
  for h in self.admin.opener.handlers:
   if hasattr(h,'cookiejar'):h.cookiejar.add_cookie_header(stale)
  e=self.admin.request('/api/account/mfa/enroll',{})[1]
  self.assertEqual(self.admin.request('/api/account/mfa/verify',{'code':totp(e['secret'])})[0],200)
  try:response=urllib.request.urlopen(stale,timeout=5)
  except urllib.error.HTTPError as err:response=err
  with response:
   self.assertEqual(response.status,401);self.assertIsNone(response.headers.get('Set-Cookie'))
  self.assertEqual(self.admin.request('/api/state')[0],200)
