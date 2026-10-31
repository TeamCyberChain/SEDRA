"""Alert transactionality, delivery semantics, durable triage and HTTP scopes."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from hashlib import sha256
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
from sadd.alerts import AlertConflict
from sadd.app import AppState,handler_for
from sadd.corpus import DOCUMENTS
from sadd.gateway import Gateway
from tests.test_app import LocalClient


class AlertDurabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'gateway.sqlite'
        self.g=Gateway(self.path,DOCUMENTS)

    def tearDown(self):self.temp.cleanup()

    def block(self,key='alert-block-001',text='FİN: A1B2C3D'):
        return self.g.evaluate('lab-001',key,text,0,now=1000)

    def first(self):return self.g.alerts_feed(now=1001)['items'][0]

    def action(self,alert,action,operation='workflow-001',**extra):
        return self.g.update_alert({'alert_id':alert['alert_id'],'action_id':operation,'action':action,
            'expected_revision':alert['revision'],**extra},now=1002)['alert']

    def test_block_creates_one_masked_alert_with_frozen_priority(self):
        request=self.block();alert=self.first()
        self.assertEqual(request['alert_ids'],[alert['alert_id']])
        self.assertEqual(alert['severity'],'high')
        self.assertEqual(alert['outcome'],'Prevented by policy')
        self.assertEqual(alert['body_sha256'],sha256('FİN: A1B2C3D'.encode()).hexdigest())
        detail=self.g.alert_detail(alert['alert_id'],now=1001)
        self.assertNotIn('A1B2C3D',json.dumps(detail))
        self.assertEqual(detail['request']['decision'],'BLOCK')

    def test_concurrent_idempotent_retries_cannot_duplicate_alert(self):
        with ThreadPoolExecutor(6) as pool:
            results=list(pool.map(lambda _:self.block(),range(12)))
        self.assertEqual(self.g.alerts_feed(now=1001)['counts']['total'],1)
        self.assertTrue(all(r['alert_ids']==results[0]['alert_ids'] for r in results))

    def test_alert_insert_failure_rolls_back_entire_admission(self):
        with closing(sqlite3.connect(self.path)) as con, con:
            con.execute("CREATE TRIGGER reject_alert BEFORE INSERT ON security_alerts BEGIN SELECT RAISE(ABORT,'injected alert failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.block()
        self.assertEqual(self.g.requests(now=1001),[])

    def test_allow_and_unused_expiry_create_no_security_alert(self):
        result=self.g.evaluate('lab-001','unused-001','An ordinary public question.',0,now=1000)
        self.assertEqual(result['decision'],'ALLOW')
        self.g.expire_unused(now=1031)
        self.assertEqual(self.g.alerts_feed(now=1032)['counts']['total'],0)

    def test_unknown_delivery_is_distinct_and_reconciliation_updates_outcome_without_resend(self):
        self.g.evaluate('lab-001','uncertain-001','An ordinary public question.',0,now=1000)
        self.g.claim_send('uncertain-001','lab-001',now=1001)
        first=self.g.mark_unknown('uncertain-001','lab-001',now=1002)
        self.g.mark_unknown('uncertain-001','lab-001',now=1003)
        alert=self.first()
        self.assertEqual(alert['kind'],'DELIVERY_UNKNOWN')
        self.assertEqual(alert['decision'],'ALLOW')
        self.assertEqual(alert['severity'],'medium')
        self.assertEqual(len(first['alert_ids']),1)
        self.g.reconcile('uncertain-001','lab-001',True,now=1004)
        detail=self.g.alert_detail(alert['alert_id'],now=1005)
        self.assertEqual(detail['alert']['outcome'],'Delivery confirmed')
        self.assertFalse(detail['alert']['delivery_uncertain'])
        self.assertEqual(detail['alert']['status'],'OPEN')
        self.assertEqual(self.g.alerts_feed(now=1005)['counts']['total'],1)
        self.assertEqual(sum(h['new_state']=='SENDING' for h in detail['request']['history']),1)

    def test_stale_send_expiry_also_generates_exactly_one_uncertainty_alert(self):
        self.g.evaluate('lab-001','stale-send-001','A public question.',0,now=1000)
        self.g.claim_send('stale-send-001','lab-001',now=1001)
        self.g.expire_unused(now=1032);self.g.expire_unused(now=1033)
        feed=self.g.alerts_feed(now=1034)
        self.assertEqual(feed['counts']['total'],1)
        self.assertEqual(feed['items'][0]['kind'],'DELIVERY_UNKNOWN')

    def test_review_resolution_reopen_and_audit_do_not_change_enforcement(self):
        self.block();initial=self.first()
        read=self.action(initial,'READ','read-event-001')
        review=self.action(read,'ACKNOWLEDGE','ack-event-001')
        closed=self.action(review,'RESOLVE','resolve-event-001',disposition='EXPECTED_TEST')
        reopened=self.action(closed,'REOPEN','reopen-event-001')
        self.assertEqual([initial['status'],review['status'],closed['status'],reopened['status']],['OPEN','IN_REVIEW','RESOLVED','OPEN'])
        self.assertEqual(self.g.alert_detail(initial['alert_id'],now=1003)['request']['state'],'BLOCKED')
        self.assertEqual(len(self.g.alert_detail(initial['alert_id'],now=1003)['history']),4)
        self.assertEqual(self.g.alerts_feed(now=1003)['counts']['unread'],0)

    def test_action_idempotence_and_payload_binding_survive_later_workflow_changes(self):
        self.block();initial=self.first()
        body={'alert_id':initial['alert_id'],'action_id':'dedup-action-001','action':'ACKNOWLEDGE','expected_revision':0}
        first=self.g.update_alert(body,now=1001)
        self.action(first['alert'],'RESOLVE','resolve-later-001',disposition='CONFIRMED_POLICY_EVENT')
        replay=self.g.update_alert(body,now=1003)
        self.assertTrue(replay['idempotent_replay'])
        self.assertEqual(replay['alert']['status'],'RESOLVED')
        with self.assertRaises(ValueError):self.g.update_alert(body|{'action':'READ'},now=1003)
        self.assertEqual(len(self.g.alert_detail(initial['alert_id'],now=1003)['history']),2)

    def test_two_analyst_updates_at_same_revision_cannot_overwrite_each_other(self):
        self.block();initial=self.first()
        def update(i):
            try:self.action(initial,'ACKNOWLEDGE',f'race-action-{i}');return True
            except AlertConflict:return False
        with ThreadPoolExecutor(2) as pool:self.assertEqual(sum(pool.map(update,range(2))),1)
        self.assertEqual(len(self.g.alert_detail(initial['alert_id'],now=1003)['history']),1)

    def test_frozen_rule_priority_is_not_changed_by_client_workflow_input(self):
        self.block(text='password: SynTh3t!c9');alert=self.first()
        self.assertEqual(alert['severity'],'critical')
        with self.assertRaises(ValueError):
            self.g.update_alert({'alert_id':alert['alert_id'],'action_id':'bad-update-001','action':'READ','expected_revision':0,'severity':'low'})
        with self.assertRaises(ValueError):self.action(alert,'RESOLVE')
        with self.assertRaises(ValueError):self.action(alert,'RESOLVE',disposition='DELETE_EVIDENCE')

    def test_restart_and_historical_backfill_do_not_duplicate_or_reopen_alerts(self):
        self.block();initial=self.first()
        closed=self.action(initial,'RESOLVE','closed-before-restart',disposition='EXPECTED_TEST')
        reopened_gateway=Gateway(self.path,DOCUMENTS)
        self.assertEqual(reopened_gateway.alerts_feed()['counts']['total'],1)
        self.assertEqual(reopened_gateway.alert_detail(closed['alert_id'])['alert']['status'],'RESOLVED')
        # Simulate the old ledger before alert tables had any records.
        with closing(sqlite3.connect(self.path)) as con, con:
            con.execute('DELETE FROM security_alert_actions');con.execute('DELETE FROM security_alerts')
        backfilled=Gateway(self.path,DOCUMENTS).alerts_feed()
        self.assertEqual(backfilled['counts']['total'],1)
        self.assertTrue(backfilled['items'][0]['imported_from_ledger'])
        self.assertEqual(backfilled['items'][0]['occurred_at'],1000)

    def test_bounded_feed_has_exact_global_counts_and_reset_keeps_monotonic_watermark(self):
        for i in range(5):self.block(f'alert-page-{i}')
        feed=self.g.alerts_feed(now=1001,limit=2)
        self.assertEqual(feed['counts']['total'],5);self.assertEqual(len(feed['items']),2);self.assertTrue(feed['truncated'])
        older=self.g.alerts_feed(now=1001,limit=2,before=feed['items'][-1]['seq'])
        self.assertEqual(len(older['items']),2)
        self.assertTrue(set(a['alert_id'] for a in feed['items']).isdisjoint(a['alert_id'] for a in older['items']))
        watermark=feed['watermark']
        self.g.reset_demo();self.assertEqual(self.g.alerts_feed(now=1002)['counts']['total'],0)
        self.block('after-reset-001')
        self.assertGreater(self.g.alerts_feed(now=1003)['watermark'],watermark)


class AlertHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.app=AppState(cls.temp.name)
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(cls.app))
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.base=f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(3);cls.app.close();cls.temp.cleanup()

    def setUp(self):
        self.app.reset()
        self.employee=LocalClient(self.base).login('lab-001');self.admin=LocalClient(self.base).login('analyst')
        status,result=self.employee.request('/api/transfer',{'request_id':'http-alert-001','text':'FİN: A1B2C3D'})
        self.assertEqual(status,200);self.alert_id=result['alert_ids'][0]

    def test_analyst_only_feed_details_mutations_and_csrf(self):
        self.assertEqual(self.employee.request('/api/alerts')[0],403)
        self.assertEqual(self.employee.request('/api/alerts?id='+self.alert_id)[0],403)
        self.assertFalse(self.employee.request('/api/state')[1]['alerts']['available'])
        body={'alert_id':self.alert_id,'action_id':'http-read-001','action':'READ','expected_revision':0}
        self.assertEqual(self.employee.request('/api/alerts/action',body)[0],403)
        self.assertEqual(self.admin.request('/api/alerts/action',body,token=False)[0],403)
        self.assertEqual(self.admin.request('/api/alerts/action',body)[0],200)
        self.assertEqual(self.admin.request('/api/alerts/action',body)[1]['idempotent_replay'],True)

    def test_http_lifecycle_conflicts_and_masked_evidence(self):
        status,detail=self.admin.request('/api/alerts?id='+self.alert_id)
        self.assertEqual(status,200);self.assertNotIn('A1B2C3D',json.dumps(detail))
        ack={'alert_id':self.alert_id,'action_id':'http-ack-001','action':'ACKNOWLEDGE','expected_revision':0}
        self.assertEqual(self.admin.request('/api/alerts/action',ack)[1]['alert']['status'],'IN_REVIEW')
        self.assertEqual(self.admin.request('/api/alerts/action',ack|{'action_id':'stale-action-001'})[0],409)
        close={'alert_id':self.alert_id,'action_id':'http-resolve-001','action':'RESOLVE','expected_revision':1,'disposition':'EXPECTED_TEST'}
        self.assertEqual(self.admin.request('/api/alerts/action',close)[1]['alert']['status'],'RESOLVED')
        self.assertEqual(self.app.receiver.list(),[])
        self.assertEqual(self.admin.request('/api/alerts?id='+self.alert_id)[1]['request']['state'],'BLOCKED')

    def test_portal_block_creates_same_queue_alert_without_provider_contact(self):
        self.app.portal.route='local'
        with patch.object(self.app.portal.local_provider,'generate') as model:
            status,result=self.employee.request('/api/portal/chat',{'request_id':'portal-alert-001','text':'FİN: A1B2C3D'})
        model.assert_not_called();self.assertEqual(status,200);self.assertFalse(result['provider_contacted'])
        self.assertEqual(len(result['request']['alert_ids']),1)
        feed=self.admin.request('/api/alerts')[1]
        self.assertEqual(feed['counts']['total'],2)
        self.assertEqual(feed['items'][0]['destination'],'local_ai')
