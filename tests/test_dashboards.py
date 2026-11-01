"""Real HTTP layouts, ownership, concurrency and retained configuration."""
import copy,tempfile,unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import test_integrations as support
from test_app import LocalClient
from sedra.dashboards import Dashboards,DashboardConflict

def layout():
 return {'action':'create','name':'Leadership review','description':'Observed operations','days':7,'widgets':[{'id':'abcdef123456','type':'kpi','title':'Stopped by policy','width':'half','metric':'blocked'},{'id':'123456abcdef','type':'trend','title':'Recorded daily activity','width':'full'}]}

class DashboardHTTPTests(unittest.TestCase):
 setUp=support.IntegrationHTTPTests.setUp
 tearDown=support.IntegrationHTTPTests.tearDown
 def create(self):
  status,b=self.admin.request('/api/dashboards/saved',layout());self.assertEqual(status,200);return b
 def test_create_update_aggregate_catalog_and_restart_retention(self):
  b=self.create();self.assertEqual(b['revision'],1);self.assertNotIn('owner',b)
  body={k:b[k] for k in ('name','description','days','widgets')}
  body['widgets'].reverse();body['widgets'][0]['width']='half'
  status,saved=self.admin.request('/api/dashboards/saved',body|{'action':'update','id':b['id'],'expected_revision':1})
  self.assertEqual(status,200);self.assertEqual(saved['revision'],2)
  a=self.admin.request('/api/dashboards')[1];self.assertEqual(a['saved_dashboards'],[saved]);self.assertIn('trend',a['widget_catalog']);self.assertIn('blocked',a['metric_catalog'])
  store=Dashboards(Path(self.tmp.name)/'dashboards.sqlite');self.assertEqual(store.listing({'role':'analyst'}),[saved])
  self.app.reset();self.assertEqual(self.admin.request('/api/dashboards/saved')[1]['items'],[saved])
 def test_closed_schema_invalid_types_bounded_layout_and_csrf(self):
  self.assertEqual(self.admin.request('/api/dashboards/saved',layout(),token=False)[0],403)
  for mutate in [lambda b:b.update(days=True),lambda b:b.update(days=365),lambda b:b.update(query='SELECT *'),lambda b:b['widgets'][0].update(metric='raw_prompts'),lambda b:b['widgets'][0].update(type='iframe'),lambda b:b.update(widgets=b['widgets']*9),lambda b:b['widgets'].append(copy.deepcopy(b['widgets'][0])),lambda b:b.update(name='bad\nlabel')]:
   b=layout();mutate(b);self.assertEqual(self.admin.request('/api/dashboards/saved',b)[0],400)
  self.assertEqual(self.admin.request('/api/dashboards/saved')[1]['items'],[])
 def test_employee_is_denied_and_account_ownership_applies_to_mutations(self):
  b=self.create();user=LocalClient(self.base).login('lab-001')
  for path in ('/api/dashboards','/api/dashboards/saved','/api/dashboards/saved?archived=1'):self.assertEqual(user.request(path)[0],403)
  self.assertEqual(user.request('/api/dashboards/saved',layout())[0],403)
  other={'role':'analyst','principal':'local:different-admin'}
  self.assertEqual(self.app.dashboards.listing(other),[])
  with self.assertRaises(KeyError):self.app.dashboards.save(other,{'action':'archive','id':b['id'],'expected_revision':1})
  self.assertEqual(len(self.admin.request('/api/dashboards/saved')[1]['items']),1)
 def test_conflicting_writers_have_one_winner_and_no_silent_overwrite(self):
  b=self.create();body={k:b[k] for k in ('name','description','days','widgets')}|{'action':'update','id':b['id'],'expected_revision':1}
  def save(i):
   try:return self.app.dashboards.save({'role':'analyst'},body|{'name':str(i)})['revision']
   except DashboardConflict:return 'conflict'
  with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(save,range(2)))
  self.assertCountEqual(results,[2,'conflict'])
  self.assertEqual(self.admin.request('/api/dashboards/saved',body)[0],409)
 def test_archive_restore_is_recoverable_revisioned_and_survives_reset(self):
  b=self.create();action={'id':b['id'],'expected_revision':1,'action':'archive'}
  status,archived=self.admin.request('/api/dashboards/saved',action);self.assertEqual(status,200);self.assertEqual(archived['revision'],2)
  self.assertEqual(self.admin.request('/api/dashboards/saved')[1]['items'],[])
  self.app.reset();self.assertEqual(self.admin.request('/api/dashboards/saved?archived=1')[1]['items'],[archived])
  self.assertEqual(self.admin.request('/api/dashboards/saved',action)[0],409)
  status,restored=self.admin.request('/api/dashboards/saved',{'id':b['id'],'expected_revision':2,'action':'restore'});self.assertEqual(status,200);self.assertFalse(restored['archived']);self.assertEqual(restored['revision'],3)

class DashboardLimitsTests(unittest.TestCase):
 def test_capacity_and_plain_text_are_preserved_without_execution_fields(self):
  with tempfile.TemporaryDirectory() as folder:
   store=Dashboards(Path(folder)/'boards.sqlite');s={'role':'analyst','principal':'test-admin'}
   b=layout();b['name']='<img src=x onerror=alert(1)>'
   first=store.save(s,b);self.assertEqual(first['name'],b['name'])
   for _ in range(19):store.save(s,layout())
   with self.assertRaises(ValueError):store.save(s,layout())
   store.save(s,{'action':'archive','id':first['id'],'expected_revision':1});store.save(s,layout())
   with self.assertRaises(ValueError):store.save(s,{'action':'restore','id':first['id'],'expected_revision':2})
