"""Actual HTTP ingestion, enrolled binding, replay and policy effects."""
import hashlib,json,time,unittest
from concurrent.futures import ThreadPoolExecutor
import test_integrations as support
from test_app import LocalClient

class AgentHTTPTests(unittest.TestCase):
 setUp=support.IntegrationHTTPTests.setUp
 tearDown=support.IntegrationHTTPTests.tearDown
 def enroll(self,uid='lab-001'):
  status,k=self.admin.request('/api/integrations/keys',{'name':'Fictional test endpoint','scopes':['endpoint:write'],'subjects':[uid],'ttl_hours':1});self.assertEqual(status,200);return k
 def send(self,k,b):return support.IntegrationHTTPTests.machine(self,'/api/v1/endpoint/events',k['token'],b)
 def batch(self,k,count=8):
  return {'device_id':k['device_id'],'subject_id':k['subject_id'],'events':[{'event_id':('%032x'%i),'occurred_at':time.time()-.1,'kind':'file_changed','detail':{'file_fingerprint':hashlib.sha256(str(i).encode()).hexdigest(),'operation':'created'}} for i in range(count)],'coverage':dict.fromkeys(('files','usb','process','session'),'connected'),'dropped':0}
 def test_enrollment_binding_scope_revocation_and_employee_denial(self):
  k=self.enroll();b=self.batch(k)
  self.assertEqual(LocalClient(self.base).login('lab-001').request('/api/agents')[0],403)
  for wrong in (b|{'subject_id':'lab-002'},b|{'device_id':'f'*32}):self.assertEqual(self.send(k,wrong)[0],403)
  plain=self.admin.request('/api/integrations/keys',{'name':'Not agent','scopes':['telemetry:write'],'subjects':['lab-001']})[1]
  self.assertEqual(self.send(plain,b)[0],403)
  self.assertEqual(self.admin.request('/api/integrations/keys',{'name':'Too wide','scopes':['endpoint:write','alerts:read'],'subjects':['lab-001']})[0],400)
  self.admin.request('/api/integrations/keys',{'action':'revoke','id':k['id']});self.assertEqual(self.send(k,b)[0],401)
 def test_replay_conflict_atomic_batch_and_metadata_only(self):
  k=self.enroll();b=self.batch(k);status,r=self.send(k,b);self.assertEqual(status,200);self.assertEqual(r['accepted'],8);self.assertEqual(len(r['acked_event_ids']),8)
  r=self.send(k,b)[1];self.assertEqual(r['duplicates'],8);self.assertEqual(r['accepted'],0)
  conflict=json.loads(json.dumps(b));conflict['events'][0]['detail']['operation']='deleted'
  fresh=self.batch(k,1)['events'][0]|{'event_id':'e'*32};conflict['events'].insert(0,fresh)
  self.assertEqual(self.send(k,conflict)[0],409)
  with self.app.integrations.db() as c:self.assertEqual(c.execute('SELECT count(*) FROM agent_events').fetchone()[0],8)
  for field,value in [('path','C:/private'),('score',100),('text','SECRET')]:
   bad=self.batch(k,1);bad['events'][0]['detail'][field]=value;self.assertEqual(self.send(k,bad)[0],400)
  self.assertNotIn(k['token'],json.dumps(self.admin.request('/api/agents')[1]))
 def test_future_old_events_and_heartbeat_are_bounded(self):
  k=self.enroll()
  for at in (time.time()+30,time.time()-8*86400,float('inf')):
   b=self.batch(k,1);b['events'][0]['occurred_at']=at;self.assertEqual(self.send(k,b)[0],400)
  b=self.batch(k,0);self.assertEqual(self.send(k,b)[0],200)
  d=self.admin.request('/api/agents')[1]['items'][0];self.assertEqual(d['connection'],'fresh')
  s=self.admin.request('/api/ueba?subject=lab-001')[1];self.assertEqual(s['agent_context']['score'],0)
 def test_real_http_rule_case_policy_and_frozen_replay(self):
  from sedra.corpus import catalog
  employee=LocalClient(self.base).login('lab-001');quote=next(f['text'] for f in catalog()[0]['fragments'] if f['label']=='Context comparison excerpt')
  initial=employee.request('/api/transfer',{'request_id':'agent-before-quote','text':quote})[1];self.assertEqual(initial['decision'],'ALLOW')
  k=self.enroll();self.assertEqual(self.send(k,self.batch(k))[0],200)
  s=self.admin.request('/api/ueba?subject=lab-001')[1];self.assertEqual(s['agent_context']['score'],75);self.assertEqual(s['policy_context']['active_24h_4gram_limit'],.1)
  cases=self.admin.request('/api/ueba/cases')[1];self.assertEqual(cases['counts']['total'],1)
  detail=self.admin.request('/api/ueba/cases?id='+cases['items'][0]['case_id'])[1];self.assertTrue(any(n['origin']=='AUTHENTICATED_ENDPOINT_REPORT' for n in detail['snapshot']['nodes']))
  after=employee.request('/api/transfer',{'request_id':'agent-after-quote','text':quote})[1];self.assertEqual(after['decision'],'BLOCK');self.assertEqual(after['body_sha256'],initial['body_sha256']);self.assertEqual(after['behavior_context']['agent_context']['score'],75)
  self.assertTrue(employee.request('/api/transfer',{'request_id':'agent-before-quote','text':quote})[1]['idempotent_replay'])
  self.assertEqual(len(self.app.receiver.list()),1)
 def test_devices_do_not_combine_files_and_delayed_reports_are_not_live(self):
  a=self.enroll();b=self.enroll();self.send(a,self.batch(a,4));self.send(b,self.batch(b,4));s=self.app.live_subject(self.app.subjects['lab-001']);self.assertEqual(s['agent_context']['score'],0)
  late=self.batch(a,8)
  for e in late['events']:e['event_id']='f'+e['event_id'][1:];e['occurred_at']=time.time()-3600
  self.assertEqual(self.send(a,late)[0],200);self.assertEqual(self.app.live_subject(self.app.subjects['lab-001'])['agent_context']['score'],0)
 def test_usb_baseline_is_not_arrival_and_process_alone_has_no_score(self):
  k=self.enroll();b=self.batch(k);at=min(e['occurred_at'] for e in b['events'])-.1
  b['events'].append({'event_id':'a'*32,'occurred_at':at,'kind':'usb_baseline','detail':{'device_fingerprint':'f'*64}})
  self.send(k,b);s=self.app.live_subject(self.app.subjects['lab-001']);self.assertEqual(s['agent_context']['score'],75)
  arrival=self.batch(k,0);arrival['events']=[{'event_id':'b'*32,'occurred_at':at,'kind':'usb_arrival','detail':{'device_fingerprint':'f'*64}}]
  self.send(k,arrival);self.assertEqual(self.app.live_subject(self.app.subjects['lab-001'])['agent_context']['score'],90)
 def test_concurrent_identical_retries_have_one_set_of_events(self):
  k=self.enroll();b=self.batch(k)
  with ThreadPoolExecutor(max_workers=2) as pool:r=list(pool.map(lambda _:self.send(k,b),range(2)))
  self.assertEqual([x[0] for x in r],[200,200]);self.assertEqual(sum(x[1]['accepted'] for x in r),8)
 def test_enrollment_does_not_apply_generated_persona_as_customer_history(self):
  self.assertEqual(self.app.subjects['lab-002']['behavior_score'],100)
  k=self.enroll('lab-002');self.assertEqual(self.send(k,self.batch(k,0))[0],200)
  subject=self.app.live_subject(self.app.subjects['lab-002'])
  self.assertEqual(subject['behavior_score'],0);self.assertEqual(subject['model_context']['recorded_score'],100);self.assertFalse(subject['model_context']['eligible_for_policy'])
