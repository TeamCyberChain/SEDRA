"""Real loopback HTTP integration and a local RSA-signed OIDC test issuer."""
import base64,hashlib,json,secrets,tempfile,threading,time,unittest,urllib.request,urllib.parse
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
from pathlib import Path
from sedra.app import AppState,handler_for
from sedra.integrations import OIDC,AuthError,Conflict,Integrations,RateLimit
from test_app import LocalClient

class IntegrationHTTPTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.app=AppState(self.tmp.name)
  self.server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(self.app));self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
  self.base=f'http://127.0.0.1:{self.server.server_port}';self.admin=LocalClient(self.base).login('analyst')
 def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join(3);self.app.close();self.tmp.cleanup()
 def key(self,scopes,subjects=None):
  status,r=self.admin.request('/api/integrations/keys',{'name':'SOAR synthetic integration','scopes':scopes,'subjects':subjects or [],'ttl_hours':1});self.assertEqual(status,200);return r
 def machine(self,path,key=None,body=None):
  req=urllib.request.Request(self.base+path,data=json.dumps(body).encode() if body is not None else None,headers={'Authorization':'Bearer '+key if key else '',**({'Content-Type':'application/json'} if body is not None else {})})
  try:r=urllib.request.urlopen(req,timeout=5)
  except urllib.error.HTTPError as e:r=e
  with r:return r.status,json.load(r)
 def test_scope_revocation_no_cookie_fallback_and_secrets_not_listed(self):
  k=self.key(['alerts:read']);self.assertEqual(self.machine('/api/v1/alerts',k['token'])[0],200)
  self.assertEqual(self.machine('/api/v1/cases',k['token'])[0],403)
  self.assertEqual(self.machine('/api/v1/alerts')[0],401)
  listing=self.admin.request('/api/integrations/keys')[1];self.assertNotIn(k['token'],json.dumps(listing))
  raw=Path(self.tmp.name,'integrations.sqlite').read_bytes();self.assertNotIn(k['token'].encode(),raw)
  self.admin.request('/api/integrations/keys',{'action':'revoke','id':k['id']})
  self.assertEqual(self.machine('/api/v1/alerts',k['token'])[0],401)
 def test_employee_and_missing_csrf_cannot_issue_keys(self):
  employee=LocalClient(self.base).login('lab-001');b={'name':'test','scopes':['cases:read']}
  self.assertEqual(employee.request('/api/integrations/keys',b)[0],403)
  self.assertEqual(self.admin.request('/api/integrations/keys',b,token=False)[0],403)
 def test_real_http_telemetry_changes_ueba_without_client_score_and_deduplicates(self):
  k=self.key(['telemetry:write','ueba:read','cases:read'],['lab-001']);now=time.time()
  events=[{'event_id':str(i),'subject_id':'lab-001','occurred_at':now,'kind':'protected_document_access','doc_id':'araz-plan'} for i in range(6)]
  before=self.machine('/api/v1/ueba',k['token'])[1]['live_context']['score'];self.assertEqual(before,0)
  status,r=self.machine('/api/v1/telemetry',k['token'],{'events':events});self.assertEqual(status,200);self.assertEqual(r['accepted'],6)
  self.assertEqual(self.machine('/api/v1/telemetry',k['token'],{'events':events})[1]['duplicates'],6)
  rotated=self.key(['telemetry:write'],['lab-001'])
  self.assertEqual(self.machine('/api/v1/telemetry',rotated['token'],{'events':events})[1]['duplicates'],6)
  subject=self.machine('/api/v1/ueba',k['token'])[1];self.assertGreaterEqual(subject['live_context']['score'],70)
  self.assertTrue(all(e['origin']=='AUTHENTICATED_EXTERNAL_REPORT' for e in subject['ueba']['timeline']))
  cases=self.machine('/api/v1/cases',k['token'])[1];self.assertEqual(cases['counts']['total'],1)
  changes=self.machine('/api/v1/cases/changes?after=0',k['token'])[1];self.assertTrue(changes['items']);self.assertNotIn('detail',json.dumps(changes))
  cursor=changes['next_cursor'];gen=changes['generation']
  self.assertEqual(self.machine(f'/api/v1/cases/changes?after={cursor}&generation={gen}',k['token'])[1]['items'],[])
  self.app.reset();self.assertEqual(self.machine(f'/api/v1/cases/changes?after={cursor}&generation={gen}',k['token'])[0],409)
 def test_atomic_batch_rejects_conflict_subject_spoof_future_and_score(self):
  k=self.key(['telemetry:write'],['lab-001']);event={'event_id':'one','subject_id':'lab-001','occurred_at':time.time(),'kind':'protected_document_access','doc_id':'araz-plan'}
  def send(events):return self.machine('/api/v1/telemetry',k['token'],{'events':events})[0]
  self.assertEqual(send([event]),200)
  self.assertEqual(send([event|{'event_id':'two'},event|{'doc_id':'restricted-runbook'}]),409)
  self.assertEqual(len(self.app.integrations.reads('lab-001',0,time.time(),100)),1)
  self.assertEqual(send([event|{'subject_id':'lab-002'}]),403)
  self.assertEqual(send([event|{'occurred_at':time.time()+60}]),400)
  self.assertEqual(send([event|{'score':100}]),400)
 def test_soar_case_actions_are_scoped_revision_checked_and_attributed(self):
  producer=self.key(['telemetry:write'],['lab-001']);now=time.time()
  events=[{'event_id':str(i),'subject_id':'lab-001','occurred_at':now,'kind':'protected_document_access','doc_id':'araz-plan'} for i in range(6)]
  self.machine('/api/v1/telemetry',producer['token'],{'events':events})
  reader=self.key(['cases:read']);writer=self.key(['cases:write'])
  case=self.machine('/api/v1/cases',reader['token'])[1]['items'][0]
  body={'case_id':case['case_id'],'action':'ACKNOWLEDGE','expected_revision':case['revision'],'action_id':'soar-action-test-001'}
  self.assertEqual(self.machine('/api/v1/cases/action',reader['token'],body)[0],403)
  self.assertEqual(self.machine('/api/v1/cases/action',writer['token'],body)[0],200)
  self.assertTrue(self.machine('/api/v1/cases/action',writer['token'],body)[1]['idempotent_replay'])
  self.assertEqual(self.machine('/api/v1/cases/action',writer['token'],body|{'action_id':'soar-stale-action-001'})[0],409)
  detail=self.app.cases.get(case['case_id']);self.assertEqual(detail['history'][-1]['actor'],'api:'+writer['id'])
 def test_expiry_persistence_and_rate_budget(self):
  k=self.key(['cases:read']);store=self.app.integrations
  for _ in range(120):store.authorize('Bearer '+k['token'],'cases:read')
  with self.assertRaises(RateLimit):store.authorize('Bearer '+k['token'],'cases:read')
  with store.db() as c:c.execute('UPDATE integration_keys SET expires=0 WHERE id=?',(k['id'],))
  with self.assertRaises(AuthError):Integrations(store.path).authorize('Bearer '+k['token'],'cases:read')

try:
 import jwt
 from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:jwt=None
@unittest.skipUnless(jwt,'Optional requirements-sso.txt not installed')
class OIDCTests(unittest.TestCase):
 setUp=IntegrationHTTPTests.setUp
 tearDown=IntegrationHTTPTests.tearDown
 def test_real_code_pkce_signed_id_token_cookie_rotation_and_no_demo_switch(self):
  private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
  public=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()));public.update(kid='local-fixture',use='sig',alg='RS256')
  records={};app=self.app;outer=self
  class Issuer(BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_GET(self):
    q=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
    if self.path.startswith('/keys'):
     body=json.dumps({'keys':[public]}).encode();self.send_response(200);self.end_headers();self.wfile.write(body);return
    code=secrets.token_hex(8);records[code]={k:v[0] for k,v in q.items()};self.send_response(302);self.send_header('Location',q['redirect_uri'][0]+'?'+urllib.parse.urlencode({'state':q['state'][0],'code':code}));self.end_headers()
   def do_POST(self):
    q=urllib.parse.parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode());r=records.pop(q['code'][0])
    challenge=base64.urlsafe_b64encode(hashlib.sha256(q['code_verifier'][0].encode()).digest()).decode().rstrip('=')
    outer.assertEqual(challenge,r['code_challenge']);outer.assertTrue(self.headers['Authorization'].startswith('Basic '))
    token=jwt.encode({'iss':issuer_url,'aud':'sedra-client','sub':'allowed-person','nonce':r['nonce'],'iat':int(time.time()),'exp':int(time.time())+300},private,algorithm='RS256',headers={'kid':'local-fixture'})
    self.send_response(200);self.end_headers();self.wfile.write(json.dumps({'id_token':token}).encode())
  issuer=ThreadingHTTPServer(('127.0.0.1',0),Issuer);thread=threading.Thread(target=issuer.serve_forever,daemon=True);thread.start();issuer_url=f'http://127.0.0.1:{issuer.server_port}'
  config={'issuer':issuer_url,'client_id':'sedra-client','client_secret':'synthetic-local-client-secret','authorization_endpoint':issuer_url+'/authorize','token_endpoint':issuer_url+'/token','jwks_uri':issuer_url+'/keys','redirect_uri':self.base+'/auth/callback','identities':{'allowed-person':'analyst'}}
  try:
   app.oidc=OIDC(config,test_http=True);client=LocalClient(self.base)
   self.assertEqual(client.request('/api/state')[0],401)
   with client.opener.open(self.base+'/auth/login',timeout=10) as r:self.assertEqual(r.status,200)
   status,state=client.request('/api/state');self.assertEqual(status,200);self.assertEqual(state['session']['role'],'analyst')
   self.assertEqual(client.request('/api/session',{'identity':'lab-002'})[0],403)
   with self.assertRaises(AuthError):app.oidc.finish({'state':['replayed'],'code':['invalid']},'unbound')
   with self.assertRaises(ValueError):OIDC(config)
   self.assertEqual(client.request('/api/logout',{})[0],200)
   self.assertEqual(client.request('/api/state')[0],401)
  finally:issuer.shutdown();issuer.server_close();thread.join(3)
 def test_wrong_nonce_issuer_audience_signature_algorithm_and_unknown_subject_fail(self):
  key=rsa.generate_private_key(public_exponent=65537,key_size=2048);jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()));jwk.update(kid='test',alg='RS256')
  config={'issuer':'https://issuer.example','client_id':'client','client_secret':'synthetic','authorization_endpoint':'https://issuer.example/auth','token_endpoint':'https://issuer.example/token','jwks_uri':'https://issuer.example/keys','redirect_uri':'http://127.0.0.1/auth/callback','identities':{'one':'analyst'}}
  for change in ({'nonce':'wrong'},{'iss':'https://evil.example'},{'aud':'other'},{'sub':'unknown'},{'exp':1},{'_bad_signature':True},{'_bad_algorithm':True}):
   oidc=OIDC(config);url=oidc.begin('browser');q=urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
   claims={'iss':config['issuer'],'aud':'client','sub':'one','nonce':q['nonce'][0],'iat':int(time.time()),'exp':int(time.time())+300}|change
   if change.get('_bad_signature'):token=jwt.encode(claims,rsa.generate_private_key(public_exponent=65537,key_size=2048),algorithm='RS256',headers={'kid':'test'})
   elif change.get('_bad_algorithm'):token=jwt.encode(claims,'synthetic-hmac-secret-with-more-than-thirty-two-characters',algorithm='HS256',headers={'kid':'test'})
   else:token=jwt.encode(claims,key,algorithm='RS256',headers={'kid':'test'})
   oidc.fetch=lambda url,data=None: {'id_token':token} if data else {'keys':[jwk]}
   with self.assertRaises(AuthError):oidc.finish({'state':q['state'],'code':['fixture']},'browser')
