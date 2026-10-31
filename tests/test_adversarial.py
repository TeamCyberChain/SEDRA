"""Explicit review regressions, false-positive controls and long-window policy."""
import base64
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from audit_bypasses import cases
from sadd.corpus import DOCUMENTS, catalog
from sadd.gateway import Gateway, WINDOW_SECONDS
from sadd.mosaic import FragmentMatcher, normalize_text
from sadd.content_security import structured_findings, text_views
from sadd.app import AppState

class ReviewRegressionTests(unittest.TestCase):
    def test_bulk_az_casing_retains_locale_without_quadratic_prefix_slices(self):
        self.assertEqual(normalize_text('I'*60000,'az'),'ı'*60000)

    def test_concurrent_token_only_exposure_reserves_atomically(self):
        doc={'id':'tokens','title':'Synthetic','version':'1','language':'en',
             'classification':'controlled_excerpt','text':' '.join(f'distinct{i}' for i in range(80))}
        with tempfile.TemporaryDirectory() as tmp:
            g=Gateway(Path(tmp)/'token-race.sqlite',[doc])
            def submit(offset):
                text=' filler '.join(f'distinct{i}' for i in range(offset,offset+10))
                return g.evaluate('same-actor',str(offset),text,0,now=1000)
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes=list(pool.map(submit,(0,30)))
            self.assertCountEqual([r['decision'] for r in outcomes],['ALLOW','BLOCK'])
            self.assertTrue(all(r['matched_documents'][0]['eligible_match_count']==0 for r in outcomes))

    def test_all_review_bypasses_block_and_public_control_allows(self):
        with tempfile.TemporaryDirectory() as tmp:
            g = Gateway(Path(tmp)/'review.sqlite', DOCUMENTS)
            for i, (name, text) in enumerate(cases().items()):
                with self.subTest(name=name):
                    result = g.evaluate(f'actor-{i}', 'review-request', text, 0)
                    self.assertEqual(result['decision'], 'ALLOW' if name=='benign_public' else 'BLOCK')

    def test_benign_and_invalid_structures_are_not_secrets(self):
        benign = [
            'Please explain how AWS access keys work.',
            'Card number: 4111 1111 1111 1112', # invalid Luhn
            'Bank account: AZ22NABZ00000000137010001944', # invalid MOD97
            'The order identifier is 4111111111111111.', # unlabelled number
            '-----BEGIN PUBLIC KEY-----\n'+'A'*80+'\n-----END PUBLIC KEY-----',
            'api_key: example_documentation',
            base64.b64encode(b'Welcome to the public security workshop').decode(),
            'The runbook is available to all members of the public.',
            'The team works on restricted access and new training materials.',
            'Bu açıq təqdimat Bakı şəhərində keçiriləcək. İŞIQ və IŞIQ fərqlidir.',
            'Please explain behavior priority in UEBA.',
            'The content rule explains a public laboratory marker.',
            'This marker authenticates no real service and grants no access.',
        ]
        with tempfile.TemporaryDirectory() as tmp:
            g = Gateway(Path(tmp)/'controls.sqlite', DOCUMENTS)
            for i, text in enumerate(benign):
                with self.subTest(text=text[:50]):
                    self.assertEqual(g.evaluate(f'benign-{i}', 'control-request', text, 0)['decision'], 'ALLOW')

    def test_base64_is_bounded_one_level_and_does_not_decode_binary(self):
        self.assertEqual(len(text_views(base64.b64encode(bytes(range(256))).decode())),1)
        nested = base64.b64encode(base64.b64encode(b'SADD_SECRET_ABCDEFGHIJKLMNOP')).decode()
        self.assertEqual(structured_findings(nested), [])
        self.assertLessEqual(len(text_views(' '.join([base64.b64encode(b'hello public world').decode()]*20))),9)

    def test_distinctive_two_word_drip_is_counted_without_fabricated_fourgrams(self):
        doc = {'id':'d','version':'1','title':'Synthetic','classification':'controlled_excerpt',
               'language':'en','text':' '.join(f'unique{i}' for i in range(80))}
        with tempfile.TemporaryDirectory() as tmp:
            g = Gateway(Path(tmp)/'drip.sqlite', [doc])
            results = [g.evaluate('alice',str(i),f'unique{i*2} unique{i*2+1}',0,now=1000+i)
                       for i in range(12)]
            self.assertIn('BLOCK', [r['decision'] for r in results])
            evidence = results[-1]['matched_documents'][0]
            self.assertEqual(evidence['eligible_match_count'],0)
            self.assertGreater(evidence['token_evaluation_coverage']['prospective']['count'],0)

    def test_daily_drip_hits_30_day_limit_after_24_hour_budget_resets(self):
        doc = {'id':'d','version':'1','title':'Synthetic','classification':'controlled_excerpt',
               'language':'en','text':' '.join(f'unique{i}' for i in range(80))}
        with tempfile.TemporaryDirectory() as tmp:
            g = Gateway(Path(tmp)/'long.sqlite', [doc])
            results = []
            for i in range(5):
                now = 1000000 + i*(WINDOW_SECONDS+10)
                text = ' '.join(f'unique{j}' for j in range(i*8,i*8+8))
                r = g.evaluate('alice',str(i),text,0,now=now)
                results.append(r)
                if r['decision']=='ALLOW':
                    g.claim_send(str(i),'alice',now=now+1)
                    g.confirm_forwarded(str(i),'alice',now=now+2)
            self.assertEqual(results[0]['decision'],'ALLOW')
            self.assertIn('CUMULATIVE_30D_DISCLOSURE_LIMIT',results[-1]['reason_codes'])
            self.assertLess(results[-1]['matched_documents'][0]['prospective_coverage'],.20)

    def test_real_document_reads_change_same_subject_same_text_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = AppState(Path(tmp)/'live')
            try:
                session = app.new_session('lab-001')[1]
                quote = catalog()[0]['fragments'][-1]['text']
                initial = app.transfer(session,{'request_id':'before-live-signal','text':quote})
                self.assertEqual(initial['decision'],'ALLOW')
                for _ in range(6):
                    app.audit('lab-001','document_read',{'doc_id':'araz-plan','classification':'controlled_excerpt'})
                changed = app.transfer(session,{'request_id':'after-live-signal','text':quote})
                self.assertEqual(changed['decision'],'BLOCK')
                self.assertEqual(changed['behavior_context']['live_context']['protected_document_reads'],6)
                self.assertLess(initial['behavior_context']['behavior_score'],70)
                # Recorded context is frozen, even after live activity changes.
                historical = app.request_view(app.gateway.get_request('before-live-signal','lab-001'))
                self.assertEqual(historical['behavior_context'], initial['behavior_context'])
                self.assertEqual(len(app.receiver.list()),1)
            finally:
                app.close()

if __name__=='__main__':
    unittest.main()
