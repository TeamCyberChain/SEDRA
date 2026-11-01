"""Aggregate correctness, scoped snapshots, retention, exports and integrity."""
import json,re,unittest
import test_integrations as support
from test_app import LocalClient
from sedra.analytics import aggregate,export_pdf
class ReportingHTTPTests(unittest.TestCase):
 setUp=support.IntegrationHTTPTests.setUp
 tearDown=support.IntegrationHTTPTests.tearDown
 def seed(self):
  self.app.gateway.evaluate('lab-001','report-one','FİN: A1B2C3D',0)
  self.app.gateway.evaluate('lab-002','report-two','FİN: A1B2C3D',0)
 def test_totals_and_live_priority_exclude_synthetic_model_and_scope_other_actors(self):
  self.seed();s,a=self.admin.request('/api/dashboards?days=7');self.assertEqual(s,200)
  self.assertEqual(a['metrics']['attempts'],2);self.assertEqual(a['metrics']['blocked'],2)
  self.assertEqual(a['metrics']['high_priority_identities'],0)
  u=LocalClient(self.base).login('lab-001');self.assertEqual(u.request('/api/dashboards')[0],403)
  s,r=u.request('/api/reports',{'template':'activity','days':7,'subject_id':'lab-001'});self.assertEqual(s,200)
  self.assertEqual(r['snapshot']['metrics']['attempts'],1);self.assertEqual(r['snapshot']['scope']['subject_id'],'lab-001')
  self.assertEqual(u.request('/api/reports',{'template':'executive','days':7,'subject_id':''})[0],403)
  self.assertEqual(u.request('/api/reports',{'template':'activity','days':7,'subject_id':'lab-002'})[0],403)
 def test_saved_report_is_immutable_authorized_and_survives_activity_reset(self):
  self.seed();s,r=self.admin.request('/api/reports',{'template':'executive','days':1,'subject_id':''});self.assertEqual(s,200)
  uid=r['id'];self.app.gateway.evaluate('lab-001','report-later','FİN: A1B2C3D',0)
  self.assertEqual(self.admin.request('/api/reports?id='+uid)[1],r)
  u=LocalClient(self.base).login('lab-001');self.assertEqual(u.request('/api/reports?id='+uid)[0],404)
  self.assertEqual(u.request('/api/reports')[1]['items'],[])
  self.app.reset();self.assertEqual(self.admin.request('/api/reports?id='+uid)[1],r)
  limited={'role':'employee','subject_id':'lab-001','principal':'analyst'}
  with self.assertRaises(KeyError):self.app.reports.get(limited,uid)
 def test_pdf_csv_integrity_and_closed_generation_schema(self):
  self.seed();r=self.admin.request('/api/reports',{'template':'security','days':30,'subject_id':''})[1]
  pdf=export_pdf(r);self.assertTrue(pdf.startswith(b'%PDF-'));self.assertTrue(pdf.rstrip().endswith(b'%%EOF'))
  self.assertGreaterEqual(len(re.findall(rb'/Type\s*/Page\b',pdf)),2)
  import urllib.request
  for kind,prefix,mime in [('pdf',b'%PDF-','application/pdf'),('csv',b'\xef\xbb\xbf','text/csv')]:
   with self.admin.opener.open(urllib.request.Request(self.base+'/api/reports?id='+r['id']+'&format='+kind),timeout=5) as response:
    self.assertEqual(response.status,200);self.assertIn(mime,response.headers['Content-Type']);self.assertTrue(response.read().startswith(prefix));self.assertEqual(response.headers['Cache-Control'],'no-store')
  from sedra.analytics import export_csv
  csv=export_csv(r).decode('utf-8-sig');self.assertIn('Snapshot SHA-256',csv);self.assertNotIn('A1B2C3D',csv)
  for metadata in ('All authorized identities','Window start UTC','Window end UTC','Interpretation','Security operations report'):self.assertIn(metadata,csv)
  self.assertEqual(self.admin.request('/api/reports',{'template':'executive','days':True,'subject_id':''})[0],400)
  self.assertEqual(self.admin.request('/api/reports',{'template':[],'days':7,'subject_id':''})[0],400)
  self.assertEqual(self.admin.request('/api/reports',{'template':'activity','days':7,'subject_id':''},token=False)[0],403)
  with self.app.reports.db() as c:c.execute('UPDATE reports SET payload=? WHERE id=?',('{}',r['id']))
  with self.assertRaises(ValueError):self.app.reports.get({'role':'analyst'},r['id'])
