from concurrent.futures import ThreadPoolExecutor
import copy
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock,patch
from sedra.behavior_cases import CaseStore,CaseConflict
from sedra.endpoint import EndpointSensor,augment
from sedra.ueba import assess
from sedra.policy_explain import counterfactual,replay
from sedra.gateway import Gateway
from sedra.corpus import DOCUMENTS,catalog
from sedra.app import AppState,handler_for
from test_app import LocalClient
from test_ueba import subject,NOW


def seed_endpoint(sensor,now=NOW,run='run-A',same_file=False,file_run=None):
    sensor.record('process-'+run,'process','controlled_process_observed',now-20,{'probe_run':run,'fixture':True},now=now)
    for i in range(8):sensor.record('file-'+run+'-'+str(i),'file','scoped_file_created',now-10+i/10,
        {'probe_run':file_run or run,'file_fingerprint':'same' if same_file else str(i),'fixture':True},now=now)


class EndpointQualityTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.s=EndpointSensor(self.tmp.name)
    def tearDown(self):self.s.close();self.tmp.cleanup()
    def test_repeated_same_file_does_not_count_as_eight_distinct_files(self):
        seed_endpoint(self.s,same_file=True)
        self.assertEqual(self.s.view(now=NOW)['score'],0)
    def test_unrelated_probe_run_does_not_earn_process_file_sequence(self):
        seed_endpoint(self.s,file_run='different-run')
        v=self.s.view(now=NOW);self.assertEqual(v['score'],75)
        self.assertFalse(next(r for r in v['rules'] if r['rule_id']=='endpoint_owned_process_file_sequence')['active'])
    def test_two_partial_probe_runs_are_not_one_complete_process_file_chain(self):
        for run in ('A','B'):
            self.s.record('process-'+run,'process','controlled_process_observed',NOW-20,{'probe_run':run},now=NOW)
            for i in range(4):self.s.record(run+str(i),'file','scoped_file_created',NOW-10,{'probe_run':run,'file_fingerprint':run+str(i)},now=NOW)
        self.assertEqual(self.s.view(now=NOW)['score'],75)
    def test_duplicate_source_does_not_advance_sequence_or_mutate_evidence(self):
        self.s.record('one','file','scoped_file_created',NOW-1,{'file_fingerprint':'a'},now=NOW)
        with self.s.db() as db:before=db.execute("SELECT seq FROM sqlite_sequence WHERE name='endpoint_events'").fetchone()[0]
        self.s.record('one','file','scoped_file_created',NOW-1,{'file_fingerprint':'a'},now=NOW)
        with self.s.db() as db:after=db.execute("SELECT seq FROM sqlite_sequence WHERE name='endpoint_events'").fetchone()[0]
        self.assertEqual(before,after)
    def test_finished_or_old_pid_cannot_be_reassociated_with_a_new_run(self):
        self.s.probe=Mock(pid=123);self.s.probe.poll.return_value=0;self.s.probe_run='new-run';self.s.probe_started=NOW-5
        payload={'processes':[{'pid':123,'created':'2026-10-31T13:59:40+00:00'}],'events':[],'coverage':{}}
        self.s.apply_windows(payload,now=NOW)
        self.assertFalse(any(e['channel']=='process' for e in self.s.view(now=NOW)['events']))
        self.s.probe.poll.return_value=None;self.s.apply_windows(payload,now=NOW)
        self.assertFalse(any(e['channel']=='process' for e in self.s.view(now=NOW)['events']))
        self.s.probe=None
    def test_sensor_stop_is_visible_and_freshness_is_not_an_employee_score(self):
        self.s.running=True;self.s.status.update({'last_windows_poll':NOW-40,'last_file_poll':NOW-1})
        self.assertEqual(self.s.view(now=NOW)['status']['health']['state'],'stale')
        self.s.stop();self.assertFalse(self.s.view(now=NOW)['enabled'])
        self.assertEqual(self.s.view(now=NOW)['score'],0)


class BehaviorCaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.sensor=EndpointSensor(self.tmp.name)
        self.store=CaseStore(str(Path(self.tmp.name)/'cases.sqlite'));seed_endpoint(self.sensor)
    def tearDown(self):self.sensor.close();self.tmp.cleanup()
    def current(self,now=NOW):return augment(assess(subject(),[],[],[],now),self.sensor.view(now=now))
    def first(self):return self.store.observe(self.current(),now=NOW)
    def action(self,c,action,key,**extra):return self.store.action({'case_id':c['case_id'],'action_id':key,'action':action,'expected_revision':c['revision'],**extra},now=NOW+1)
    def test_case_exists_without_any_dlp_request_and_survives_cooling(self):
        c=self.first();self.assertEqual(c['peak_score'],90)
        cooled=self.store.observe(self.current(NOW+1810),now=NOW+1810)
        self.assertEqual(cooled['status'],'OPEN');self.assertEqual(cooled['current_score'],0)
        self.assertEqual(cooled['peak_score'],90)
        detail=self.store.get(c['case_id']);self.assertEqual(detail['snapshot']['priority'],90)
        self.assertTrue(detail['integrity']['hash_chain_valid'])
    def test_poll_heartbeats_do_not_create_revisions_or_cases(self):
        before=self.first();after=self.store.observe(self.current(NOW+1),now=NOW+1)
        self.assertEqual(before['revision'],after['revision']);self.assertEqual(self.store.feed()['counts']['total'],1)
    def test_partial_sequence_expiry_retains_peak_process_file_graph(self):
        c=self.first();original=self.store.get(c['case_id'])['snapshot']
        current=self.current(NOW+101);self.assertEqual(current['live_context']['score'],75)
        row=self.store.observe(current,now=NOW+101)
        detail=self.store.get(c['case_id']);self.assertEqual(row['current_score'],75)
        self.assertEqual(detail['snapshot'],original)
        self.assertEqual(detail['snapshot']['priority'],90)
        self.assertTrue(any(e['relation']=='same_server_probe_run_and_time' for e in detail['snapshot']['edges']))
        self.assertTrue(detail['integrity']['hash_chain_valid'] and detail['integrity']['displayed_snapshot_bound'])
        again=self.store.observe(self.current(NOW+102),now=NOW+102)
        self.assertEqual(again['revision'],row['revision'])
    def test_concurrent_observation_creates_only_one_case(self):
        with ThreadPoolExecutor(3) as pool:rows=list(pool.map(lambda _:self.first(),range(3)))
        self.assertEqual(len({r['case_id'] for r in rows}),1);self.assertEqual(self.store.feed()['counts']['total'],1)
    def test_graph_binds_actual_source_ids_and_same_run_edge_with_caveat(self):
        c=self.first();snapshot=self.store.get(c['case_id'])['snapshot']
        self.assertTrue(any(e['relation']=='same_server_probe_run_and_time' for e in snapshot['edges']))
        ids={n['id'] for n in snapshot['nodes']}
        self.assertTrue(all(e['from'] in ids and e['to'] in ids for e in snapshot['edges']))
        self.assertIn('not syscall',snapshot['edges'][0]['claim'])
    def test_ack_resolve_reopen_revision_and_idempotency(self):
        c=self.first();body={'case_id':c['case_id'],'action_id':'case-ack-001','action':'ACKNOWLEDGE','expected_revision':c['revision']}
        self.store.action(body,now=NOW+1);self.assertTrue(self.store.action(body,now=NOW+2)['idempotent_replay'])
        review=self.store.get(c['case_id'])['case'];self.assertEqual(review['status'],'IN_REVIEW')
        with self.assertRaises(CaseConflict):self.store.action(body|{'action_id':'stale-case-001'})
        self.action(review,'RESOLVE','case-close-001',disposition='EXPECTED_LAB_TEST')
        closed=self.store.get(c['case_id'])['case'];self.assertEqual(closed['status'],'RESOLVED')
        self.assertEqual(self.store.observe(self.current(),now=NOW+2)['case_id'],c['case_id'])
        self.assertEqual(self.store.feed()['counts']['total'],1)
        self.action(closed,'REOPEN','case-reopen-001')
        self.assertEqual(self.store.get(c['case_id'])['case']['status'],'OPEN')
    def test_new_evidence_after_resolution_creates_new_case_without_reopening_old(self):
        c=self.first();self.action(c,'RESOLVE','resolve-new-001',disposition='BENIGN_EXPLAINED')
        seed_endpoint(self.sensor,now=NOW+2,run='run-B')
        new=self.store.observe(self.current(NOW+2),now=NOW+2)
        self.assertNotEqual(new['case_id'],c['case_id'])
        self.assertEqual(self.store.get(c['case_id'])['case']['status'],'RESOLVED')
    def test_packet_consistency_detects_edited_history_without_claiming_attestation(self):
        c=self.first();detail=self.store.get(c['case_id'],packet=True)
        self.assertTrue(detail['integrity']['displayed_snapshot_bound'])
        with self.store.db() as db:
            row=db.execute('SELECT payload_json FROM behavior_case_history WHERE case_id=? AND revision=0',(c['case_id'],)).fetchone()
            payload=json.loads(row[0]);payload['actor']='changed'
            db.execute('UPDATE behavior_case_history SET payload_json=? WHERE case_id=? AND revision=0',(json.dumps(payload),c['case_id']))
        self.assertFalse(self.store.get(c['case_id'])['integrity']['hash_chain_valid'])
    def test_restart_and_reset_generation(self):
        c=self.first();again=CaseStore(self.store.path)
        self.assertEqual(again.get(c['case_id'])['case']['peak_score'],90)
        generation=again.feed()['generation'];again.reset()
        self.assertEqual(again.feed()['counts']['total'],0);self.assertGreater(again.feed()['generation'],generation)


class PolicyExplainTests(unittest.TestCase):
    def setUp(self):self.g=Gateway(':memory:',DOCUMENTS)
    def context(self):return {'policy_context':{'daily_component':0,'quality_guard':0},'live_context':{'rules':[{'rule_id':'fixture_rule','active':True,'score':90}]}}
    def test_same_frozen_quote_replays_and_rule_ablation_changes_verdict_without_reservation(self):
        quote=next(f['text'] for f in catalog()[0]['fragments'] if f['label']=='Context comparison excerpt')
        row=self.g.evaluate('lab-001','cf-controlled-001',quote,90,behavior_context=self.context())
        before=self.g.requests();p=counterfactual(row,['fixture_rule'])
        self.assertEqual(p['original']['decision'],'BLOCK');self.assertEqual(p['hypothetical']['decision'],'ALLOW')
        self.assertEqual(self.g.requests(),before)
    def test_structured_and_restricted_hard_policy_cannot_be_removed_by_rule_exclusion(self):
        for i,text in enumerate(('FİN: A1B2C3D','SEDRA_SECRET_ABCDEFGHIJKLMNOP')):
            row=self.g.evaluate('lab-001','cf-hard-policy-'+str(i),text,90,behavior_context=self.context())
            p=counterfactual(row,['fixture_rule']);self.assertEqual(p['hypothetical']['decision'],'BLOCK')
            self.assertTrue(p['hypothetical']['hard_policy_unchanged'])
    def test_unknown_rule_and_incomplete_historical_snapshot_cannot_invent_allow(self):
        row=self.g.evaluate('lab-001','cf-unknown-001','Public text.',90,behavior_context=self.context())
        with self.assertRaises(ValueError):counterfactual(row,['not-recorded'])
        historical=copy.deepcopy(row);historical['model_profiles']['policy']='old-profile'
        self.assertFalse(counterfactual(historical,[])['supported'])
    def test_all_four_coverage_branches_and_approved_route_match_actual_admission(self):
        samples=[catalog()[0]['fragments'][0]['text'],catalog()[2]['fragments'][0]['text'],'Public text.','FİN: A1B2C3D']
        for i,text in enumerate(samples):
            for score in (0,69,70,90):
                for route in ('public_ai','approved_ai'):
                    row=self.g.evaluate('actor-'+str(i)+'-'+str(score)+route,'cf-check-001',text,score,destination=route)
                    p=replay(row,score);self.assertTrue(p['supported']);self.assertEqual(p['decision'],row['decision'])


class CaseHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.app=AppState(cls.tmp.name)
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(cls.app));cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.base=f'http://127.0.0.1:{cls.server.server_port}'
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.thread.join(3);cls.app.close();cls.tmp.cleanup()
    def setUp(self):self.app.reset();self.admin=LocalClient(self.base).login('analyst');self.employee=LocalClient(self.base).login('lab-001')
    def test_actual_scoped_file_observer_creates_case_before_any_gateway_block(self):
        folder=self.app.endpoint.folder;folder.mkdir(exist_ok=True)
        for i in range(8):(folder/f'sedra-lab-http-case-{i}.txt').write_text('Synthetic controlled fixture.')
        self.app.endpoint.collect_files()
        status,feed=self.admin.request('/api/ueba/cases');self.assertEqual(status,200)
        self.assertEqual(feed['counts']['total'],1)
        self.assertEqual(self.app.gateway.alerts_feed()['counts']['total'],0)
        self.assertEqual(self.app.gateway.requests(),[])
        self.assertEqual(self.employee.request('/api/ueba/cases')[0],403)
        key=feed['items'][0]['case_id'];self.assertEqual(self.employee.request('/api/ueba/cases?id='+key)[0],403)
        body={'case_id':key,'action_id':'http-case-ack-001','action':'ACKNOWLEDGE','expected_revision':feed['items'][0]['revision']}
        self.assertEqual(self.admin.request('/api/ueba/cases/action',body,token=False)[0],403)
        self.assertEqual(self.admin.request('/api/ueba/cases/action',body)[0],200)
        self.assertEqual(self.admin.request('/api/ueba/cases/action',body|{'action_id':'http-case-race-001'})[0],409)
    def test_http_preview_is_scoped_read_only_and_masks_values(self):
        seed_endpoint(self.app.endpoint,now=time.time())
        quote=next(f['text'] for f in catalog()[0]['fragments'] if f['label']=='Context comparison excerpt')
        row=self.employee.request('/api/transfer',{'request_id':'http-preview-case','text':quote})[1]
        excluded=[r['rule_id'] for r in row['behavior_context']['endpoint_context']['rules']]
        body={'subject_id':'lab-001','request_id':'http-preview-case','exclude_rules':excluded}
        before=len(self.app.gateway.requests());status,p=self.admin.request('/api/ueba/counterfactual',body)
        self.assertEqual(status,200);self.assertEqual(p['hypothetical']['decision'],'ALLOW')
        self.assertEqual(len(self.app.gateway.requests()),before);self.assertEqual(self.app.receiver.list(),[])
        self.assertEqual(self.employee.request('/api/ueba/counterfactual',body)[0],403)
        self.assertEqual(self.admin.request('/api/ueba/counterfactual',body|{'behavior_score':0})[0],400)
