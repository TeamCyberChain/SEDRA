"""Actual isolated HTTP checks, including the already-installed local model."""
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
import json
import re
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
from sedra.app import AppState, handler_for
from test_app import LocalClient


def main():
    with tempfile.TemporaryDirectory(prefix='sedra-smoke-') as directory:
        app = AppState(directory)
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(app))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f'http://127.0.0.1:{server.server_port}'
            admin = LocalClient(base).login('analyst')
            employee = LocalClient(base).login('lab-001')
            def call(client, path, body=None):
                status, data = client.request(path, body)
                assert status == 200, (path, status, data)
                return data
            initial = call(admin, '/api/state')
            doc = initial['documents'][0]
            text = doc['fragments'][0]['text']
            before = call(employee, '/api/transfer', {'request_id':'sedra-before-label','text':text})
            assert before['state'] == 'FORWARDED_CONFIRMED'
            control = {'doc_id':doc['id'], 'expected_revision':0, 'sensitivity':'restricted',
                'owner':'Research', 'business_tags':['research','demo-synthetic'], 'change_reason':'DEMO_VALIDATION'}
            assert employee.request('/api/catalog/labels', control)[0] == 403
            call(admin, '/api/catalog/labels', control)
            assert admin.request('/api/catalog/labels', control)[0] == 400
            after = call(employee, '/api/transfer', {'request_id':'sedra-after-label','text':text})
            assert after['decision'] == 'BLOCK' and 'GOVERNED_RESTRICTED_LABEL' in after['reason_codes']
            count = len(app.receiver.list())
            replay = call(employee, '/api/transfer', {'request_id':'sedra-before-label','text':text})
            assert replay['idempotent_replay'] and replay['decision'] == 'ALLOW'
            assert len(app.receiver.list()) == count
            structured = call(employee, '/api/transfer', {'request_id':'sedra-card-label','text':'Synthetic test card: 4111 1111 1111 1111'})
            assert structured['decision'] == 'BLOCK'
            assert 'PAYMENT_CARD_LUHN' in structured['security_tags']['detector_tags']
            call(admin, '/api/portal/configure', {'provider':'local'})
            answer = call(employee, '/api/portal/chat', {'request_id':'sedra-real-local-answer','text':'Compute 17 + 25. Reply with only the integer.'})
            assert answer['ai'] and re.search(r'\b42\b', answer['ai']['answer'])
            assert answer['ai']['external_data_transfer'] is False
            blocked_ai = call(employee, '/api/portal/chat', {'request_id':'sedra-model-label-block','text':text})
            assert blocked_ai['provider_contacted'] is False and blocked_ai['ai'] is None
            call(admin, '/api/catalog/labels', {**control, 'expected_revision':1, 'sensitivity':'confidential'})
            restored = call(employee, '/api/transfer', {'request_id':'sedra-restored-label','text':text})
            assert restored['state'] == 'FORWARDED_CONFIRMED'
            unknown = call(employee, '/api/transfer', {'request_id':'sedra-ack-loss','text':'A public workshop invitation.', 'simulate_ack_loss':True})
            assert unknown['state'] == 'DELIVERY_UNKNOWN'
            receipts_before = len(app.receiver.list())
            reconciled = call(employee, '/api/reconcile', {'request_id':'sedra-ack-loss'})
            assert reconciled['state'] == 'FORWARDED_CONFIRMED'
            assert len(app.receiver.list()) == receipts_before
            final = call(admin, '/api/state')
            assert [d['metadata']['source_sha256'] for d in initial['documents']] == [d['metadata']['source_sha256'] for d in final['documents']]
            report = {'executed_at_utc':datetime.now(timezone.utc).isoformat(), 'product':'SEDRA',
                'scope':'Isolated temporary HTTP app; synthetic corpus; real managed local Qwen inference; no cloud calls',
                'successful':True, 'same_body_sha256':before['body_sha256']==after['body_sha256'],
                'before_label':{'decision':before['decision'],'state':before['state'],'tags':before['security_tags']},
                'after_label':{'decision':after['decision'],'state':after['state'],'tags':after['security_tags'],'reasons':after['reason_codes']},
                'old_request_replay_preserved':replay['decision']=='ALLOW', 'no_resend_on_replay':True,
                'structured_card_tags':structured['security_tags'],
                'real_local_ai':answer['ai'], 'ai_blocked_before_inference':not blocked_ai['provider_contacted'],
                'restored_to_registered_floor':restored['state'], 'employee_label_change_http':403, 'stale_revision_http':400,
                'reconciliation':{'before':unknown['state'],'after':reconciled['state'], 'receipt_count_before':receipts_before,'receipt_count_after':len(app.receiver.list())},
                'source_hashes_unchanged':True, 'label_revisions':[h['revision'] for h in final['label_history']],
                'counts':final['counts'], 'benchmark_claim':'No CERT efficacy measurement is implied.'}
            (ROOT/'artifacts/sedra_live_smoke.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
            print(json.dumps({'successful':True,'counts':final['counts'],'answer':answer['ai']['answer'],
                'label_changed_decision':'ALLOW -> BLOCK','reconcile_no_resend':True},indent=2))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)
            app.close()


if __name__ == '__main__':
    main()
