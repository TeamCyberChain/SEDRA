from datetime import datetime,timezone
import copy
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from sedra.ueba import assess,active_baseline,LONG,DAY,INPUT_LIMIT
from sedra.app import AppState,handler_for
from sedra.corpus import catalog
from test_app import LocalClient

NOW=datetime(2026,10,31,14,tzinfo=timezone.utc).timestamp()


def subject(score=0):
    return {'subject_id':'lab-001','role':'Finance','behavior_score':score,'rule_score':score/100,
        'ml_score':0,'date':'2026-10-30','as_of':'2026-10-30T23:59:59+04:00','provenance':'synthetic_lab',
        'baseline':{'history_days':28},'model_version':'test-daily'}


def read(i,at,uid='lab-001',protected=True):
    return {'id':i,'subject_id':uid,'timestamp':datetime.fromtimestamp(at,timezone.utc).isoformat(),
        'kind':'document_read','detail':{'doc_id':'araz-plan','classification':'controlled_excerpt' if protected else 'public'}}


def request(i,at,kind='AZ_FIN_CONTEXTUAL',uid='lab-001'):
    return {'row_id':i,'subject_id':uid,'request_id':'test-request-'+str(i),'created_at':at,
        'decision':'BLOCK' if kind else 'ALLOW','state':'BLOCKED' if kind else 'FORWARDED_CONFIRMED',
        'body_bytes':13,'destination':'public_ai','detector_types':[kind] if kind else []}


class StreamingUEBATests(unittest.TestCase):
    def test_future_events_other_actors_and_window_boundaries_do_not_raise_priority(self):
        reads=[read(i,NOW+1) for i in range(6)]+[read(i+10,NOW-1,'lab-002') for i in range(6)]
        reqs=[request(i,NOW+1) for i in range(3)]
        r=assess(subject(),reads,reqs,[],NOW)
        self.assertEqual(r['behavior_score'],0);self.assertEqual(r['ueba']['timeline_total_30m'],0)
        r=assess(subject(),[read(i,NOW-120) for i in range(6)],[],[],NOW)
        self.assertEqual(r['live_context']['protected_document_reads'],0)

    def test_duplicate_request_and_multi_delivery_events_cannot_inflate_block_count(self):
        row=request(1,NOW-1)
        r=assess(subject(),[],[row,copy.deepcopy(row),copy.deepcopy(row)],[],NOW)
        self.assertEqual(r['live_context']['blocked_attempts'],1);self.assertEqual(r['behavior_score'],0)

    def test_legacy_read_trigger_is_explicit_and_decays(self):
        rows=[read(i,NOW-30) for i in range(6)]
        r=assess(subject(),rows,[],[],NOW)
        self.assertEqual(r['behavior_score'],80)
        self.assertEqual(r['live_context']['unique_protected_documents_30m'],1)
        expired=assess(subject(),rows,[],[],NOW+121)
        self.assertEqual(expired['live_context']['score'],0)

    def test_three_repeated_distinct_blocks_and_long_window_sensitive_attempts(self):
        rows=[request(i,NOW-10) for i in range(3)]
        self.assertEqual(assess(subject(),[],rows,[],NOW)['live_context']['score'],85)
        rows=[request(i,NOW-200-200*i) for i in range(4)]
        r=assess(subject(),[],rows,[],NOW)
        self.assertEqual(r['live_context']['blocked_attempts'],0)
        self.assertEqual(r['live_context']['score'],75)
        self.assertEqual(assess(subject(),[],rows,[],NOW+1801)['live_context']['score'],0)

    def test_ordered_cross_channel_sequence_has_source_ids_and_does_not_assert_origin(self):
        reads=[read(i,NOW-500-i) for i in range(3)]
        reqs=[request(i,NOW-300-i) for i in range(2)]
        r=assess(subject(),reads,reqs,[],NOW)
        rule=next(x for x in r['live_context']['rules'] if x['rule_id']=='access_then_sensitive_attempts')
        self.assertTrue(rule['active']);self.assertEqual(r['live_context']['score'],85)
        self.assertEqual(set(rule['evidence_ids']),{'audit:0','audit:1','audit:2','gateway:0','gateway:1'})
        reversed_order=assess(subject(),[read(i,NOW-1) for i in range(3)],reqs,[],NOW)
        self.assertEqual(reversed_order['live_context']['score'],0)

    def test_sequence_requires_three_reads_before_the_sensitive_attempts(self):
        reads=[read(1,NOW-600),read(2,NOW-100),read(3,NOW-90)]
        attempts=[request(1,NOW-400),request(2,NOW-300)]
        r=assess(subject(),reads,attempts,[],NOW)
        self.assertNotIn('access_then_sensitive_attempts',r['live_context']['active_rule_ids'])

    def test_type_diversity_requires_multiple_requests_and_nonempty_detector_types(self):
        rows=[request(i,NOW-300-i,'AZ_FIN_CONTEXTUAL' if i else 'PAYMENT_CARD_LUHN') for i in range(3)]
        r=assess(subject(),[],rows,[],NOW)
        self.assertEqual(r['live_context']['score'],90)
        self.assertNotIn('multiple_sensitive_types',assess(subject(),[],rows[:1],[],NOW)['live_context']['active_rule_ids'])

    def test_public_activity_and_single_new_identifier_are_not_high_priority(self):
        r=assess(subject(),[read(i,NOW-i,protected=False) for i in range(30)],
            [request(i,NOW-i,None) for i in range(20)]+[request(100,NOW-1)],[],NOW)
        self.assertEqual(r['live_context']['score'],0)
        self.assertEqual(r['live_context']['personal_baseline']['status'],'insufficient_history')
        self.assertIsNone(r['live_context']['personal_baseline']['median'])

    def test_inspection_resource_limits_are_not_sensitive_content_findings(self):
        r=assess(subject(),[],[request(i,NOW-300-i,'STRUCTURED_INSPECTION_LIMIT') for i in range(4)],[],NOW)
        self.assertEqual(r['live_context']['sensitive_attempts_30m'],0)
        self.assertEqual(r['live_context']['score'],0)

    def test_personal_baseline_excludes_current_future_and_has_support_gate(self):
        events=[{'at':NOW-day*DAY-offset*LONG} for day in range(1,8) for offset in (2,3)]
        baseline=active_baseline(events,NOW-LONG,NOW)
        poisoned=active_baseline(events+[{'at':NOW-1}]*100+[{'at':NOW+1}]*100,NOW-LONG,NOW)
        self.assertEqual(baseline,poisoned);self.assertEqual(baseline['status'],'sufficient')
        self.assertEqual(baseline['median'],1);self.assertFalse(baseline['inactive_slots_imputed'])
        self.assertEqual(active_baseline(events[:4],NOW-LONG,NOW)['status'],'insufficient_history')

    def test_established_personal_deviation_is_advisory_and_never_uses_current_bins_to_learn(self):
        past=[read(day*10+offset,NOW-day*DAY-offset*LONG) for day in range(1,8) for offset in (2,3)]
        current=[read(1000+i,NOW-250-i,protected=False) for i in range(12)]
        r=assess(subject(),past+current,[],[],NOW)
        self.assertEqual(r['live_context']['personal_baseline']['median'],1)
        self.assertIn('personal_activity_deviation',r['live_context']['active_rule_ids'])
        self.assertEqual(r['behavior_score'],60);self.assertEqual(r['policy_context']['mode'],'standard')

    def test_large_reversed_sequence_keeps_bounded_evidence_and_does_not_invent_causality(self):
        reads=[read(i,NOW-100) for i in range(2000)]
        attempts=[request(i,NOW-200) for i in range(2000)]
        r=assess(subject(),reads,attempts,[],NOW)
        self.assertNotIn('access_then_sensitive_attempts',r['live_context']['active_rule_ids'])
        self.assertEqual(len(r['ueba']['timeline']),60)
        self.assertTrue(all(len(rule['evidence_ids'])<=12 for rule in r['live_context']['rules']))

    def test_stale_future_and_low_support_daily_snapshot_never_enforces_as_fresh(self):
        r=assess(subject(100),[],[],[],NOW+10*DAY)
        self.assertEqual((r['model_context']['status'],r['behavior_score']),('stale',0))
        s=subject(100);s['as_of']='2026-11-01T23:59:59+04:00'
        self.assertEqual(assess(s,[],[],[],NOW)['model_context']['status'],'future_snapshot')
        s=subject(100);s['baseline']['history_days']=2
        self.assertEqual(assess(s,[],[],[],NOW)['behavior_score'],0)

    def test_input_saturation_is_separate_quality_guard_not_behavior_score(self):
        r=assess(subject(),[],[],[],NOW,truncated=True)
        self.assertEqual(r['behavior_score'],80);self.assertEqual(r['live_context']['score'],0)
        self.assertEqual(r['policy_context']['quality_guard'],80)
        self.assertEqual(r['live_context']['personal_baseline']['status'],'input_bound_reached')

    def test_score_is_max_not_sum_and_labels_do_not_change_it(self):
        reads=[read(i,NOW-2) for i in range(6)]
        a=assess(subject(60),reads,[],[],NOW)
        s=subject(60)|{'label':1,'scenario':'pretend severe'}
        b=assess(s,reads,[],[],NOW)
        self.assertEqual(a['policy_context'],b['policy_context']);self.assertEqual(a['behavior_score'],80)
        self.assertEqual(a['live_context'],b['live_context'])


class UEBAHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.app=AppState(cls.tmp.name)
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(cls.app))
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.base=f'http://127.0.0.1:{cls.server.server_port}'
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(3);cls.app.close();cls.tmp.cleanup()
    def setUp(self):
        self.app.reset();self.employee=LocalClient(self.base).login('lab-001');self.admin=LocalClient(self.base).login('analyst')
    def test_fake_duplicate_audit_and_future_document_rows_do_not_change_effective_context(self):
        for _ in range(3):self.app.audit('lab-001','transfer_blocked',{'request_id':'unbacked-audit-id'})
        future=datetime.fromtimestamp(time.time()+60,timezone.utc).isoformat()
        with self.app.db() as db:
            for i in range(6):db.execute('INSERT INTO audit(timestamp,subject_id,kind,detail) VALUES(?,?,?,?)',
                (future,'lab-001','document_read',json.dumps({'classification':'controlled_excerpt','doc_id':'araz-plan'})))
        r=self.employee.request('/api/ueba?subject=lab-001')[1]
        self.assertEqual(r['live_context']['score'],0)
        self.assertEqual(r['live_context']['blocked_attempts'],0)
    def test_scopes_no_new_endpoint_ingestion_and_masked_evidence(self):
        self.assertEqual(self.employee.request('/api/ueba?subject=lab-002')[0],403)
        self.assertEqual(self.admin.request('/api/ueba?subject=lab-002')[0],200)
        self.employee.request('/api/transfer',{'request_id':'ueba-mask-0001','text':'FİN: A1B2C3D'})
        status,r=self.employee.request('/api/ueba?subject=lab-001')
        self.assertEqual(status,200);self.assertNotIn('A1B2C3D',json.dumps(r))
        self.assertEqual(r['ueba']['coverage'][-1]['status'],'not_connected')
    def test_real_sequence_changes_controlled_quote_and_frozen_context_survives_replay(self):
        quote=next(f['text'] for f in catalog()[0]['fragments'] if f['label']=='Context comparison excerpt')
        before=self.employee.request('/api/transfer',{'request_id':'ueba-before-context','text':quote})[1]
        self.assertEqual(before['decision'],'ALLOW')
        for i in range(3):self.employee.request('/api/document?id=araz-plan')
        for i in range(2):self.employee.request('/api/transfer',{'request_id':f'ueba-sensitive-{i}','text':'FİN: A1B2C3D'})
        r=self.employee.request('/api/ueba?subject=lab-001')[1]
        self.assertEqual(r['live_context']['protected_document_reads'],3)
        self.assertEqual(r['live_context']['blocked_attempts'],2)
        self.assertIn('access_then_sensitive_attempts',r['live_context']['active_rule_ids'])
        after=self.employee.request('/api/transfer',{'request_id':'ueba-after-context','text':quote})[1]
        self.assertEqual(after['decision'],'BLOCK');self.assertEqual(before['body_sha256'],after['body_sha256'])
        replay=self.employee.request('/api/transfer',{'request_id':'ueba-before-context','text':quote})[1]
        self.assertEqual(replay['behavior_context'],before['behavior_context'])
        self.assertEqual(len(self.app.receiver.list()),1)
        with patch('sedra.app.time.time',return_value=time.time()+1801):
            cooled=self.app.live_subject(self.app.subjects['lab-001'])
        self.assertEqual(cooled['live_context']['score'],0)
    def test_request_ledger_drives_blocks_even_if_secondary_audit_event_is_missing(self):
        for i in range(3):self.app.gateway.evaluate('lab-001',f'ledger-only-{i}','FİN: A1B2C3D',0)
        with self.app.db() as db:db.execute('DELETE FROM audit')
        r=self.app.live_subject(self.app.subjects['lab-001'])
        self.assertEqual(r['live_context']['blocked_attempts'],3);self.assertEqual(r['live_context']['score'],85)
