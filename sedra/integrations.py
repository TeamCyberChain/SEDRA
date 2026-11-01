"""Scoped machine identities and explicit OIDC Authorization Code + PKCE."""
import base64,hashlib,hmac,json,math,secrets,sqlite3,time,urllib.parse,urllib.request
from contextlib import contextmanager

SCOPES={'alerts:read','alerts:write','cases:read','ueba:read','cases:write','telemetry:write','browser:inspect'}
class AuthError(PermissionError):pass
class Conflict(ValueError):pass
class RateLimit(ValueError):pass

def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),allow_nan=False)
class Integrations:
 def __init__(self,path):
  self.path=str(path)
  with self.db() as c:c.executescript('''CREATE TABLE IF NOT EXISTS integration_keys(id TEXT PRIMARY KEY,name TEXT,hash TEXT,scopes TEXT,subjects TEXT,expires REAL,revoked INTEGER DEFAULT 0,created REAL,last_used REAL);
   CREATE TABLE IF NOT EXISTS integration_usage(key_id TEXT,minute INTEGER,n INTEGER,PRIMARY KEY(key_id,minute));
   CREATE TABLE IF NOT EXISTS external_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE,payload_hash TEXT,subject_id TEXT,at REAL,doc_id TEXT,key_id TEXT);''')
 @contextmanager
 def db(self):
  c=sqlite3.connect(self.path,timeout=10);c.row_factory=sqlite3.Row
  try:
   with c:yield c
  finally:c.close()
 def create(self,b,known):
  if set(b)-{'name','scopes','subjects','ttl_hours'}:raise ValueError('Unknown key fields')
  name=b.get('name');scopes=b.get('scopes');subjects=b.get('subjects',[]);ttl=b.get('ttl_hours',168)
  if not isinstance(name,str) or not 1<=len(name.strip())<=80:raise ValueError('Name required')
  if not isinstance(scopes,list) or not scopes or any(s not in SCOPES for s in scopes):raise ValueError('Explicit supported scopes required')
  if not isinstance(subjects,list) or len(subjects)>40 or any(s not in known for s in subjects):raise ValueError('Known subjects only')
  if 'telemetry:write' in scopes and not subjects:raise ValueError('Telemetry keys require explicit bound subjects')
  if 'browser:inspect' in scopes and len(set(subjects))!=1:raise ValueError('Browser inspection keys require exactly one bound subject')
  if type(ttl) not in (int,float) or not math.isfinite(ttl) or not 1<=ttl<=2160:raise ValueError('TTL must be 1–2160 hours')
  identifier=secrets.token_hex(8);token='sedra_k_'+identifier+'.'+secrets.token_urlsafe(32);now=time.time()
  with self.db() as c:c.execute('INSERT INTO integration_keys(id,name,hash,scopes,subjects,expires,created) VALUES(?,?,?,?,?,?,?)',(identifier,name.strip(),hashlib.sha256(token.encode()).hexdigest(),canonical(sorted(set(scopes))),canonical(sorted(set(subjects))),now+ttl*3600,now))
  return {'id':identifier,'token':token,'expires_at':now+ttl*3600,'display_once':True}
 def listing(self):
  with self.db() as c:return [dict(r)|{'scopes':json.loads(r['scopes']),'subjects':json.loads(r['subjects'])} for r in c.execute('SELECT id,name,scopes,subjects,expires,revoked,created,last_used FROM integration_keys ORDER BY created DESC')]
 def revoke(self,key):
  with self.db() as c:
   if c.execute('UPDATE integration_keys SET revoked=1 WHERE id=?',(key,)).rowcount!=1:raise KeyError('Key not found')
  return {'revoked':True,'id':key}
 def authorize(self,header,scope):
  if not isinstance(header,str) or not header.startswith('Bearer sedra_k_') or len(header)>200:raise AuthError('Valid bearer key required')
  token=header[7:];identifier=token[8:].split('.')[0];now=time.time()
  with self.db() as c:
   c.execute('BEGIN IMMEDIATE');r=c.execute('SELECT * FROM integration_keys WHERE id=?',(identifier,)).fetchone()
   if not r or r['revoked'] or r['expires']<=now or not hmac.compare_digest(r['hash'],hashlib.sha256(token.encode()).hexdigest()):raise AuthError('Invalid, expired or revoked key')
   if scope not in json.loads(r['scopes']):raise PermissionError('Key scope does not permit this operation')
   minute=int(now//60);c.execute('DELETE FROM integration_usage WHERE minute<?',(minute-2,))
   c.execute('INSERT INTO integration_usage VALUES(?,?,1) ON CONFLICT(key_id,minute) DO UPDATE SET n=n+1',(identifier,minute))
   if c.execute('SELECT n FROM integration_usage WHERE key_id=? AND minute=?',(identifier,minute)).fetchone()[0]>120:raise RateLimit('120 requests/minute/key limit')
   c.execute('UPDATE integration_keys SET last_used=? WHERE id=?',(now,identifier))
   return {'id':identifier,'subjects':json.loads(r['subjects'])}
 def ingest(self,b,key,documents):
  if set(b)!={'events'} or not isinstance(b['events'],list) or not 1<=len(b['events'])<=100:raise ValueError('Batch of 1–100 events required')
  now=time.time();items=[]
  for e in b['events']:
   if not isinstance(e,dict) or set(e)!={'event_id','subject_id','occurred_at','kind','doc_id'}:raise ValueError('Closed telemetry schema required')
   if not isinstance(e['event_id'],str) or not 1<=len(e['event_id'])<=100:raise ValueError('Bounded source event ID required')
   if e['subject_id'] not in key['subjects']:raise PermissionError('Subject not bound to this key')
   if e['kind']!='protected_document_access' or e['doc_id'] not in documents:raise ValueError('Known registered document access only; no client score')
   at=e['occurred_at']
   if type(at) not in (int,float) or not math.isfinite(at) or not now-1800<=at<=now:raise ValueError('Event time must be in preceding 30 minutes')
   items.append((e['subject_id']+':'+e['event_id'],hashlib.sha256(canonical(e).encode()).hexdigest(),e))
  inserted=0
  with self.db() as c:
   c.execute('BEGIN IMMEDIATE')
   for event_id,digest,e in items:
    old=c.execute('SELECT payload_hash FROM external_events WHERE event_id=?',(event_id,)).fetchone()
    if old:
     if old[0]!=digest:raise Conflict('Source event ID reused with different facts')
     continue
    c.execute('INSERT INTO external_events(event_id,payload_hash,subject_id,at,doc_id,key_id) VALUES(?,?,?,?,?,?)',(event_id,digest,e['subject_id'],e['occurred_at'],e['doc_id'],key['id']));inserted+=1
  return {'accepted':inserted,'duplicates':len(items)-inserted,'origin':'AUTHENTICATED_EXTERNAL_REPORT','observations_are_not_independent_endpoint_attestation':True}
 def reads(self,uid,lower,upper,limit):
  from datetime import datetime,timezone
  with self.db() as c:
   return [{'id':'external:'+str(r['seq']),'timestamp':datetime.fromtimestamp(r['at'],timezone.utc).isoformat(),'detail':{'doc_id':r['doc_id'],'source':'AUTHENTICATED_EXTERNAL_REPORT','classification':'controlled_excerpt'}} for r in c.execute('SELECT * FROM external_events WHERE subject_id=? AND at>=? AND at<=? ORDER BY at DESC,seq DESC LIMIT ?',(uid,lower,upper,limit))]

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
class OIDC:
 def __init__(self,config,*,test_http=False):
  self.c=config;self.pending={};self.http=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
  required={'issuer','client_id','client_secret','authorization_endpoint','token_endpoint','jwks_uri','redirect_uri','identities'}
  if set(config)!=required:raise ValueError('Explicit OIDC configuration fields required')
  for field in ('issuer','authorization_endpoint','token_endpoint','jwks_uri'):
   u=urllib.parse.urlsplit(config[field])
   if u.username or u.password or u.fragment or (u.scheme!='https' and not(test_http and u.scheme=='http' and u.hostname=='127.0.0.1')):raise ValueError('Pinned HTTPS OIDC endpoints required')
  if any(urllib.parse.urlsplit(config[f]).netloc!=urllib.parse.urlsplit(config['issuer']).netloc for f in ('authorization_endpoint','token_endpoint','jwks_uri')):raise ValueError('OIDC endpoints must share configured issuer origin')
  if urllib.parse.urlsplit(config['redirect_uri']).hostname not in ('127.0.0.1','localhost'):raise ValueError('This loopback lab requires a registered loopback callback')
  import jwt
  self.jwt=jwt
 def begin(self,binding):
  now=time.time();self.pending={k:v for k,v in self.pending.items() if v['at']>now-300}
  if len(self.pending)>=100:raise RateLimit('Too many pending logins')
  state=secrets.token_urlsafe(32);nonce=secrets.token_urlsafe(32);verifier=secrets.token_urlsafe(48)
  self.pending[state]={'binding':binding,'nonce':nonce,'verifier':verifier,'at':now}
  challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
  return self.c['authorization_endpoint']+'?'+urllib.parse.urlencode({'client_id':self.c['client_id'],'redirect_uri':self.c['redirect_uri'],'response_type':'code','scope':'openid','state':state,'nonce':nonce,'code_challenge':challenge,'code_challenge_method':'S256'})
 def fetch(self,url,data=None):
  headers={}
  if data is not None:
   headers={'Content-Type':'application/x-www-form-urlencoded','Authorization':'Basic '+base64.b64encode((self.c['client_id']+':'+self.c['client_secret']).encode()).decode()}
  with self.http.open(urllib.request.Request(url,data=data,headers=headers),timeout=10) as r:raw=r.read(100001)
  if len(raw)>100000:raise ValueError('OIDC response bound exceeded')
  return json.loads(raw)
 def finish(self,query,binding):
  if set(query)!={'state','code'} or any(len(v)!=1 for v in query.values()):raise AuthError('OIDC state and code required')
  pending=self.pending.pop(query['state'][0],None)
  if not pending or pending['binding']!=binding or time.time()-pending['at']>300:raise AuthError('Invalid or expired browser-bound login state')
  try:
   result=self.fetch(self.c['token_endpoint'],urllib.parse.urlencode({'grant_type':'authorization_code','code':query['code'][0],'redirect_uri':self.c['redirect_uri'],'code_verifier':pending['verifier']}).encode())
   token=result['id_token'];header=self.jwt.get_unverified_header(token)
   if header.get('alg')!='RS256' or not isinstance(header.get('kid'),str):raise ValueError()
   keys=self.fetch(self.c['jwks_uri'])['keys'];matches=[k for k in keys if k.get('kid')==header['kid'] and k.get('kty')=='RSA' and k.get('use','sig')=='sig' and k.get('alg','RS256')=='RS256']
   if len(matches)!=1:raise ValueError()
   public_key=self.jwt.PyJWK.from_dict(matches[0]).key
   if public_key.key_size<2048:raise ValueError()
   claims=self.jwt.decode(token,public_key,algorithms=['RS256'],audience=self.c['client_id'],issuer=self.c['issuer'],options={'require':['exp','iat','sub','iss','aud','nonce']})
   if claims['nonce']!=pending['nonce'] or not isinstance(claims['sub'],str) or claims.get('azp',self.c['client_id'])!=self.c['client_id']:raise ValueError()
   if isinstance(claims['aud'],list) and len(claims['aud'])>1 and claims.get('azp')!=self.c['client_id']:raise ValueError()
   amr=claims.get('amr',[])
   if not isinstance(amr,list) or any(not isinstance(x,str) for x in amr) or not ('mfa' in amr or {'pwd','otp'}<=set(amr)):raise ValueError()
   identity=self.c['identities'].get(claims['sub'])
   if identity not in ('analyst','lab-001','lab-002'):raise ValueError()
   return identity,claims
  except Exception:raise AuthError('OIDC validation or explicit identity binding failed') from None
