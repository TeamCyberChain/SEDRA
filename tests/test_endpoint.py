from datetime import datetime,timezone
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from sadd.endpoint import EndpointSensor,augment,ORIGIN
from test_ueba import subject,NOW
from sadd.ueba import assess
from sadd.app import AppState


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.s=EndpointSensor(self.tmp.name)
    def tearDown(self):self.s.close();self.tmp.cleanup()
    def record(self,i,channel='file',kind='scoped_file_created',at=None,origin=ORIGIN):
        return self.s.record('fixture-'+str(i),channel,kind,NOW-10 if at is None else at,{'fixture':True,'file_fingerprint':str(i),'probe_run':'fixture-run'},origin=origin,now=NOW)
    def test_source_identity_deduplicates_and_future_invalid_timestamps_are_rejected(self):
        self.assertTrue(self.record(1));self.assertFalse(self.record(1))
        self.assertFalse(self.record(2,at=NOW+10))
        self.assertFalse(self.record(3,at='bad'))
        self.assertEqual(len(self.s.view(now=NOW)['events']),1)
    def test_synthetic_fixture_origin_never_changes_real_endpoint_score(self):
        for i in range(10):self.record(i,origin='SYNTHETIC_TEST')
        self.record(11,'process','controlled_process_observed',NOW-20,'SYNTHETIC_TEST')
        v=self.s.view(now=NOW);self.assertEqual(v['score'],0)
        self.assertTrue(all(e['origin']=='SYNTHETIC_TEST' for e in v['events']))
    def test_actual_file_metadata_poll_is_scoped_and_does_not_read_contents(self):
        self.s.folder.mkdir();outside=Path(self.tmp.name)/'private.txt';outside.write_text('outside')
        (self.s.folder/'unrelated.txt').write_text('ignore')
        (self.s.folder/'sedra-lab-test.txt').write_text('owned synthetic')
        with patch.object(Path,'read_text',side_effect=AssertionError('contents must not be read')):
            self.s.collect_files();self.s.collect_files()
        v=self.s.view();self.assertEqual(len(v['events']),1)
        self.assertNotIn('owned synthetic',json.dumps(v));self.assertNotIn('private.txt',json.dumps(v))
        self.assertEqual(v['events'][0]['detail']['bytes'],15)
    def test_owned_process_and_eight_later_changes_raise90_then_decay(self):
        self.record(100,'process','controlled_process_observed',NOW-20)
        for i in range(8):self.record(i)
        v=self.s.view(now=NOW);self.assertEqual(v['score'],90)
        self.assertTrue(next(r for r in v['rules'] if r['rule_id']=='endpoint_owned_process_file_sequence')['active'])
        self.assertEqual(self.s.view(now=NOW+121)['score'],0)
    def test_logon_snapshots_are_not_authentication_events_or_risk(self):
        self.record(100,'logon','current_session_snapshot',NOW-20)
        for i in range(8):self.record(i)
        v=self.s.view(now=NOW)
        self.assertFalse(next(r for r in v['rules'] if r['rule_id']=='endpoint_logon_then_writes')['active'])
    def test_usb_first_scan_and_restart_are_presence_not_fresh_insertions(self):
        payload={'usb_devices':['fake-hash-unit-fixture'],'events':[],'coverage':{}}
        self.s.apply_windows(payload,now=NOW)
        self.assertEqual(self.s.view(now=NOW)['events'][0]['kind'],'usb_presence_baseline')
        self.s.apply_windows(payload,now=NOW+5)
        self.assertEqual(len(self.s.view(now=NOW+5)['events']),1)
        self.s.apply_windows({'usb_devices':[],'events':[],'coverage':{}},now=NOW+10)
        self.s.apply_windows(payload,now=NOW+15)
        self.assertIn('usb_arrival_observed',[e['kind'] for e in self.s.view(now=NOW+15)['events']])
    def test_unavailable_usb_query_is_not_evidence_that_a_device_was_removed(self):
        self.s.apply_windows({'usb_devices':['unit-device'],'coverage':{'usb':'connected_presence_polling_no_contents_read'}},now=NOW)
        self.s.apply_windows({'usb_devices':[],'coverage':{'usb':'unavailable'}},now=NOW+5)
        self.assertNotIn('usb_removal_observed',[e['kind'] for e in self.s.view(now=NOW+5)['events']])
    def test_endpoint_events_are_not_exposed_as_another_subject(self):
        self.record(1)
        v=self.s.view('lab-002',now=NOW);self.assertFalse(v['mapped']);self.assertEqual(v['events'],[])
    def test_augment_changes_policy_without_training_daily_model(self):
        original=assess(subject(),[],[],[],NOW)
        self.record(100,'process','controlled_process_observed',NOW-20)
        for i in range(8):self.record(i)
        modified=augment(original,self.s.view(now=NOW))
        self.assertEqual(modified['behavior_score'],90)
        self.assertEqual(modified['policy_context']['active_24h_4gram_limit'],.1)
        self.assertEqual(modified['model_context'],original['model_context'])
        self.assertEqual(original['behavior_score'],0)
    def test_restart_retains_dedup_salt_and_events(self):
        self.record(1);other=EndpointSensor(self.tmp.name)
        self.assertEqual(other.salt,self.s.salt)
        self.assertEqual(len(other.view(now=NOW)['events']),1)
        other.close()


class EndpointScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.tmp=tempfile.TemporaryDirectory();cls.app=AppState(cls.tmp.name)
    @classmethod
    def tearDownClass(cls):cls.app.close();cls.tmp.cleanup()
    def test_employee_cannot_start_sensor_or_submit_arbitrary_event_fields(self):
        employee=self.app.new_session('lab-001')[1];admin=self.app.new_session('analyst')[1]
        with self.assertRaises(PermissionError):self.app.endpoint_action(employee,{'action':'start'})
        with self.assertRaises(ValueError):self.app.endpoint_action(admin,{'action':'ingest','kind':'usb_connected'})
        with self.assertRaises(ValueError):self.app.endpoint_action(admin,{'action':'probe','target':'C:\\'})
