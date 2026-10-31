"""Governed labels affect durable admission, with scoped, revisioned changes."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import tempfile
import unittest

from sadd.app import AppState, handler_for
from sadd.corpus import DOCUMENTS
from sadd.gateway import Gateway
from http.server import ThreadingHTTPServer
import threading
from tests.test_app import LocalClient


class GovernedLabelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'gateway.sqlite'
        self.gateway = Gateway(self.path, DOCUMENTS)
        self.text = ' '.join(DOCUMENTS[0]['text'].split()[:18])

    def tearDown(self):
        self.temp.cleanup()

    def body(self, **overrides):
        return {'doc_id': 'araz-plan', 'expected_revision': 0, 'sensitivity': 'restricted',
                'owner': 'Research', 'business_tags': ['research', 'demo-synthetic'],
                'change_reason': 'DEMO_VALIDATION', **overrides}

    def evaluate(self, key, text=None):
        return self.gateway.evaluate(subject_id='lab-001', request_id=key,
            text=self.text if text is None else text, behavior_score=0)

    def test_restricted_label_blocks_new_admission_and_preserves_replay_snapshot(self):
        before = self.evaluate('labels-before')
        self.assertEqual(before['decision'], 'ALLOW')
        self.gateway.update_labels(self.body())
        after = self.evaluate('labels-after')
        self.assertEqual(after['decision'], 'BLOCK')
        self.assertIn('GOVERNED_RESTRICTED_LABEL', after['reason_codes'])
        self.assertEqual(after['security_tags']['sensitivity'], 'restricted')
        replay = self.evaluate('labels-before')
        self.assertEqual(replay['decision'], 'ALLOW')
        self.assertEqual(replay['matched_documents'][0]['label_snapshot']['revision'], 0)
        self.assertEqual(after['matched_documents'][0]['label_snapshot']['revision'], 1)

    def test_metadata_and_history_persist_without_changing_source_manifest(self):
        original = self.gateway.catalog_labels()['araz-plan']['source_sha256']
        self.gateway.update_labels(self.body())
        reopened = Gateway(self.path, DOCUMENTS)
        self.assertEqual(reopened.catalog_labels()['araz-plan']['source_sha256'], original)
        self.assertEqual(reopened.catalog_labels()['araz-plan']['revision'], 1)
        self.assertEqual(reopened.label_history()[0]['before']['sensitivity'], 'confidential')
        reopened.reset_demo()
        self.assertEqual(reopened.catalog_labels()['araz-plan']['revision'], 1)

    def test_floors_and_public_exclusions_cannot_be_weakened(self):
        for doc_id, sensitivity in [('restricted-runbook','public'), ('araz-plan','public'), ('public-note','restricted')]:
            with self.assertRaises(ValueError):
                self.gateway.update_labels(self.body(doc_id=doc_id, sensitivity=sensitivity))

    def test_only_one_concurrent_update_can_commit_same_revision(self):
        def update(_):
            try:
                self.gateway.update_labels(self.body())
                return True
            except ValueError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(update, range(2))), 1)
        self.assertEqual(len(self.gateway.label_history()), 1)

    def test_closed_schema_rejects_untrusted_tags_and_fields(self):
        for change in [{'business_tags':['<script>alert(1)</script>']}, {'expected_revision':True},
                       {'sensitivity':'safe'}, {'owner':'unrecognized'}, {'decision':'ALLOW'},
                       {'business_tags':['research','research']}]:
            with self.assertRaises(ValueError):
                self.gateway.update_labels(self.body(**change))

    def test_unmatched_is_unclassified_and_structured_values_stay_masked(self):
        clean = self.evaluate('labels-clean', 'What is seventeen plus twenty-five?')
        self.assertEqual(clean['security_tags']['sensitivity'], 'unclassified')
        secret = 'SADD_SECRET_A1B2C3D4E5F6G7H8'
        blocked = self.evaluate('labels-secret', secret)
        self.assertEqual(blocked['decision'], 'BLOCK')
        self.assertIn('SYNTHETIC_SECRET', blocked['security_tags']['detector_tags'])
        self.assertNotIn(secret, json.dumps(blocked))

    def test_analyst_can_restore_controlled_floor_without_weakening_fixed_restricted(self):
        self.gateway.update_labels(self.body())
        self.gateway.update_labels(self.body(expected_revision=1, sensitivity='confidential'))
        result = self.evaluate('labels-restored')
        self.assertNotIn('GOVERNED_RESTRICTED_LABEL', result['reason_codes'])
        self.assertEqual(self.gateway.catalog_labels()['araz-plan']['revision'], 2)


class LabelHTTPTests(unittest.TestCase):
    def test_authorization_csrf_revision_and_employee_catalog_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            app = AppState(directory)
            server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(app))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f'http://127.0.0.1:{server.server_port}'
                employee, analyst = LocalClient(base).login('lab-001'), LocalClient(base).login('analyst')
                body = {'doc_id':'araz-plan','expected_revision':0,'sensitivity':'restricted',
                    'owner':'Research','business_tags':['research'],'change_reason':'POLICY_REVIEW'}
                self.assertEqual(employee.request('/api/catalog/labels', body)[0], 403)
                self.assertEqual(analyst.request('/api/catalog/labels', body, token=False)[0], 403)
                self.assertEqual(analyst.request('/api/catalog/labels', body)[0], 200)
                self.assertEqual(analyst.request('/api/catalog/labels', body)[0], 400)
                status, view = employee.request('/api/state')
                self.assertEqual(status, 200)
                self.assertEqual(view['label_history'], [])
                self.assertEqual(view['documents'][0]['metadata']['sensitivity'], 'restricted')
            finally:
                server.shutdown()
                server.server_close()
                thread.join(3)
                app.close()
