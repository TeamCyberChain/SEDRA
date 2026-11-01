"""Persistent metadata collection and real HTTP authorization/redaction."""
import json,tempfile,unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from sedra.audit_log import AuditLog
import test_integrations as support
from test_app import LocalClient

class StoreTests(unittest.TestCase):
 def test_concurrent_persistence_and_keyset_pagination(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'audit.sqlite';a=AuditLog(p)
   with ThreadPoolExecutor(max_workers=8) as pool:list(pool.map(lambda n:a.append('API','analyst','http_response',{'status':200}),range(30)))
   b=AuditLog(p);first=b.page(limit=20);second=b.page(before=first['next_before'],limit=20)
   self.assertEqual(len(first['items'])+len(second['items']),30);self.assertFalse({r['seq'] for r in first['items']} & {r['seq'] for r in second['items']})
 def test_ui_closed_schema_and_bounded_rate(self):
  with tempfile.TemporaryDirectory() as d:
   a=AuditLog(Path(d)/'audit.sqlite')
   for bad in [{'event':'control','control':'other','text':'secret'},{'event':'typed secret','control':'other'},{'event':'control','control':'secret'}]:
    with self.assertRaises(ValueError):a.ui('analyst',bad)
   for _ in range(120):a.ui('analyst',{'event':'control','control':'other'})
   with self.assertRaises(ValueError):a.ui('analyst',{'event':'control','control':'other'})
   self.assertEqual(a.page(source='UI')['matching'],120)

class HTTPTests(unittest.TestCase):
 setUp=support.IntegrationHTTPTests.setUp
 tearDown=support.IntegrationHTTPTests.tearDown
 def test_real_api_redacts_and_attributes_denials(self):
  employee=LocalClient(self.base).login('lab-001')
  self.assertEqual(employee.request('/api/audit')[0],403)
  self.assertEqual(employee.request('/api/audit/ui',{'event':'control','control':'submit'})[0],200)
  self.assertEqual(employee.request('/api/audit/ui',{'event':'control','control':'submit','actor':'analyst'})[0],400)
  self.assertEqual(employee.request('/api/audit/ui',{'event':'control','control':'submit'},token=False)[0],403)
  self.admin.request('/api/portal/configure?secret=never-log-query',{'api_key':'never-log-body'})
  self.admin.request('/secret-in-path?secret=never-log-query')
  key=self.app.integrations.create({'name':'audit-test','scopes':['alerts:read']},[])
  self.assertEqual(support.IntegrationHTTPTests.machine(self,'/api/v1/alerts',key['token'])[0],200)
  status,data=self.admin.request('/api/audit');self.assertEqual(status,200)
  encoded=json.dumps(data);self.assertNotIn('never-log',encoded);self.assertNotIn('secret-in-path',encoded);self.assertNotIn(self.admin.csrf,encoded);self.assertNotIn(key['token'],encoded)
  self.assertTrue(any(r['actor']=='api:'+key['id'] for r in data['items']))
  self.assertTrue(any(r['actor']=='lab-001' and r['source']=='UI' for r in data['items']))
  self.assertTrue(any(r['metadata'].get('status')==403 for r in data['items']))
 def test_reset_preserves_audit_and_employee_cannot_read(self):
  self.admin.request('/api/audit/ui',{'event':'theme_dark','control':'other'})
  before=self.app.platform_audit.page(source='UI')['items'][0]['seq']
  self.assertEqual(self.admin.request('/api/reset',{})[0],200)
  self.assertEqual(self.app.platform_audit.page(source='UI')['items'][0]['seq'],before)
  self.assertEqual(LocalClient(self.base).login('lab-002').request('/api/audit')[0],403)
