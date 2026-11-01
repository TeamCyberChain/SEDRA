"""Bounded authenticated device reports. Never independent OS attestation."""
import hashlib,json,math,re,time
from .integrations import Conflict,RateLimit,canonical

ORIGIN='AUTHENTICATED_ENDPOINT_REPORT'
DETAILS={'file_changed':{'file_fingerprint','operation'},'process_started':{'process_fingerprint','name_fingerprint'},'usb_arrival':{'device_fingerprint'},'usb_removal':{'device_fingerprint'},'usb_baseline':{'device_fingerprint'},'session_logon':{'event_fingerprint'},'session_logoff':{'event_fingerprint'},'session_reconnect':{'event_fingerprint'},'session_disconnect':{'event_fingerprint'}}
CHANNELS={'file_changed':'file','process_started':'process','usb_arrival':'usb','usb_removal':'usb','usb_baseline':'usb',**{k:'logon' for k in DETAILS if k.startswith('session_')}}
def valid_hex(value,pattern='[0-9a-f]{64}'):
 return isinstance(value,str) and re.fullmatch(pattern,value) is not None

class AgentTelemetry:
 def __init__(self,integrations):
  self.integrations=integrations
  with integrations.db() as c:
   c.executescript('''CREATE TABLE IF NOT EXISTS agent_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,device_id TEXT NOT NULL,event_id TEXT NOT NULL,digest TEXT NOT NULL,subject_id TEXT NOT NULL,at REAL NOT NULL,received REAL NOT NULL,kind TEXT NOT NULL,detail TEXT NOT NULL,UNIQUE(device_id,event_id));
    CREATE INDEX IF NOT EXISTS agent_subject_time ON agent_events(subject_id,at);''')
 def devices(self,subject=None):
  now=time.time()
  with self.integrations.db() as c:
   rows=c.execute('SELECT d.*,k.revoked,k.expires FROM agent_devices d JOIN integration_keys k ON k.id=d.key_id'+(' WHERE d.subject_id=?' if subject else '')+' ORDER BY d.created DESC',([subject] if subject else [])).fetchall()
  return [dict(r)|{'coverage':json.loads(r['coverage']),'credential_active':not r['revoked'] and r['expires']>now,'connection':'never_seen' if r['last_seen'] is None else 'fresh' if now-r['last_seen']<=60 else 'stale','origin':ORIGIN} for r in rows]
 def ingest(self,b,key,now=None):
  now=time.time() if now is None else now
  if set(b)!={'device_id','subject_id','events','coverage','dropped'}:raise ValueError('Closed endpoint report schema required')
  if not valid_hex(b['device_id'],'[0-9a-f]{32}') or not isinstance(b['subject_id'],str):raise ValueError('Enrolled device and subject required')
  if not isinstance(b['events'],list) or len(b['events'])>50:raise ValueError('At most 50 events per endpoint batch')
  cov=b['coverage']
  if not isinstance(cov,dict) or set(cov)!={'files','process','usb','session'} or any(v not in ('connected','disabled','unavailable','overflow') for v in cov.values()):raise ValueError('Bounded source coverage required')
  if type(b['dropped']) is not int or not 0<=b['dropped']<=2**31-1:raise ValueError('Bounded dropped-event counter required')
  prepared=[]
  for e in b['events']:
   if not isinstance(e,dict) or set(e)!={'event_id','occurred_at','kind','detail'}:raise ValueError('Closed endpoint event schema required')
   if not valid_hex(e['event_id'],'[0-9a-f]{32}|[0-9a-f]{64}') or not isinstance(e['kind'],str) or e['kind'] not in DETAILS:raise ValueError('Supported endpoint event ID and kind required')
   at=e['occurred_at'];detail=e['detail']
   if type(at) not in (int,float) or not math.isfinite(at) or not now-7*86400<=at<=now:raise ValueError('Event must be nonfuture and within seven days')
   if not isinstance(detail,dict) or set(detail)!=DETAILS[e['kind']]:raise ValueError('Allowlisted metadata only; no paths, names, bodies or client score')
   for field,value in detail.items():
    if field=='operation':
     if value not in ('created','changed','renamed','deleted'):raise ValueError('Supported file operation required')
    elif not valid_hex(value):raise ValueError('Pseudonymous SHA-256 metadata required')
   prepared.append((e,hashlib.sha256(canonical(e).encode()).hexdigest()))
  accepted=0
  with self.integrations.db() as c:
   c.execute('BEGIN IMMEDIATE')
   d=c.execute('SELECT * FROM agent_devices WHERE id=? AND key_id=?',(b['device_id'],key['id'])).fetchone()
   if not d or d['subject_id']!=b['subject_id'] or key['subjects']!=[d['subject_id']]:raise PermissionError('Device and subject are bound to this endpoint credential')
   c.execute('DELETE FROM agent_events WHERE received<?',(now-8*86400,))
   for e,digest in prepared:
    old=c.execute('SELECT digest FROM agent_events WHERE device_id=? AND event_id=?',(d['id'],e['event_id'])).fetchone()
    if old:
     if old[0]!=digest:raise Conflict('Endpoint event ID reused with changed facts')
     continue
    if c.execute('SELECT count(*) FROM agent_events WHERE device_id=?',(d['id'],)).fetchone()[0]>=100000:raise RateLimit('Endpoint retention capacity reached')
    c.execute('INSERT INTO agent_events(device_id,event_id,digest,subject_id,at,received,kind,detail) VALUES(?,?,?,?,?,?,?,?)',(d['id'],e['event_id'],digest,d['subject_id'],e['occurred_at'],now,e['kind'],canonical(e['detail'])));accepted+=1
   c.execute('UPDATE agent_devices SET last_seen=?,coverage=?,dropped=? WHERE id=?',(now,canonical(cov),b['dropped'],d['id']))
  return {'device_id':b['device_id'],'accepted':accepted,'duplicates':len(prepared)-accepted,'acked_event_ids':sorted({e['event_id'] for e,_ in prepared}),'origin':ORIGIN}
 def augment(self,subject,now):
  uid=subject['subject_id']
  with self.integrations.db() as c:
   rows=c.execute('SELECT * FROM agent_events WHERE subject_id=? AND at>? AND at<=? ORDER BY at DESC,seq DESC LIMIT 5001',(uid,now-1800,now)).fetchall()
  devices=self.devices(uid)
  if not devices:return subject
  events=[dict(r)|{'detail':json.loads(r['detail']),'channel':CHANNELS[r['kind']],'origin':ORIGIN} for r in rows[:5000]]
  rules=[]
  for d in devices:
   short=[e for e in events if e['device_id']==d['id'] and e['at']>now-120]
   distinct={e['detail']['file_fingerprint']:e for e in short if e['kind']=='file_changed'};files=list(distinct.values())
   def add(suffix,title,priority,items,active):
    rules.append({'rule_id':'agent_'+d['id']+'_'+suffix,'title':title,'score':priority if active else 0,'active':active,'observed':len(items),'activation':8,'window_seconds':120,'evidence_ids':['agent:'+str(e['seq']) for e in items[-12:]],'evidence_count':len(items),'note':'Authenticated device report; explicit subject binding. Temporal association is not file-writer, USB-copy or malicious-intent proof.'})
   add('files','Agent: distinct watched-file activity',75,files,len(files)>=8)
   for kind,suffix,title,priority in [('usb_arrival','usb_files','Agent: USB arrival then watched files',90),('session_logon','logon_files','Agent: logon then watched files',80),('session_reconnect','reconnect_files','Agent: reconnect then watched files',80)]:
    earlier=[e for e in short if e['kind']==kind];later=[f for f in files if any(e['at']<=f['at'] for e in earlier)]
    add(suffix,title,priority,earlier+later,len(later)>=8)
  value=max([r['score'] for r in rules]+[0]);result=dict(subject);live=dict(subject['live_context']);policy=dict(subject['policy_context']);u=dict(subject['ueba'])
  # A customer-device enrollment cannot turn a generated daily persona into
  # that employee's measured history. Retain the record, exclude its policy use.
  if subject.get('model_context',{}).get('provenance')=='synthetic_lab':
   result['model_context']=dict(subject['model_context'],applied_score=0,eligible_for_policy=False,status='synthetic_profile_excluded_for_agent',note='Generated daily context is retained for research only; enrolled endpoint policy uses observed components.')
   policy['daily_component']=0
   result['behavior_score']=max(live['score'],policy.get('quality_guard',0))
  refs={key for r in rules if r['active'] for key in r['evidence_ids']}
  projection=[{'event_id':'agent:'+str(e['seq']),'timestamp':e['at'],'channel':e['channel'],'kind':e['kind'],'origin':ORIGIN,'doc_id':None,'request_id':None,'route':None,'body_bytes':0,'detector_types':[],'detail':e['detail']|{'device_id':e['device_id']}} for e in events if 'agent:'+str(e['seq']) in refs]
  live['rules']=[*live['rules'],*rules];live['active_rule_ids']=[*live['active_rule_ids'],*[r['rule_id'] for r in rules if r['active']]];live['score']=max(live['score'],value)
  guard=80 if len(rows)>5000 else 0
  policy.update(agent_component=value,live_component=live['score'],quality_guard=max(policy.get('quality_guard',0),guard));result['behavior_score']=max(result['behavior_score'],value,guard);policy.update(effective_score=result['behavior_score'],mode='tightened' if result['behavior_score']>=70 else 'standard',active_24h_4gram_limit=.1 if result['behavior_score']>=70 else .2)
  u['rule_evidence']=[*u.get('rule_evidence',[]),*projection[-96:]];u['rule_evidence_total']=u.get('rule_evidence_total',0)+len(projection);u['rule_evidence_limit']=192;u['rule_evidence_truncated']=u.get('rule_evidence_truncated',False) or len(projection)>96
  u['coverage']=[*u['coverage'],{'channel':'Windows service agent reports','status':'fresh' if any(d['connection']=='fresh' and d['credential_active'] for d in devices) else 'stale_or_never_seen'}]
  result.update(live_context=live,policy_context=policy,ueba=u,agent_context={'origin':ORIGIN,'score':value,'devices':devices,'events':events[:60],'rules':rules,'truncated':len(rows)>5000,'note':'Explicit device-to-subject assignment; no enterprise directory attestation or process/file causal attribution'})
  return result
