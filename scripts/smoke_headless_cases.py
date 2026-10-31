"""Real-clock loopback proof of finite UEBA expiry with no console/subject reads."""
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
import json
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
from sedra.app import AppState, handler_for
from test_app import LocalClient


def main():
    report = {'executed_at_utc': datetime.now(timezone.utc).isoformat(),
              'scope': 'Isolated actual loopback HTTP and real clock; authenticated synthetic access reports, not OS observations; no main ledger or provider access',
              'console_or_subject_endpoint_reads': 0}
    with tempfile.TemporaryDirectory() as directory:
        app = AppState(directory)
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(app))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        admin = LocalClient(f'http://127.0.0.1:{server.server_port}').login('analyst')
        key = None
        try:
            status, key = admin.request('/api/integrations/keys', {
                'name': 'Isolated expiry smoke', 'scopes': ['telemetry:write', 'cases:read'],
                'subjects': ['lab-001'], 'ttl_hours': 1})
            assert status == 200
            http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

            def request(path, body=None):
                data = json.dumps(body).encode() if body is not None else None
                req = urllib.request.Request(admin.base + path, data=data,
                    headers={'Authorization': 'Bearer ' + key['token'], 'Content-Type': 'application/json'})
                with http.open(req, timeout=10) as response:
                    assert response.status == 200
                    return json.load(response)

            source_at = time.time() - 116
            events = [{'event_id': 'expiry-smoke-' + str(i), 'subject_id': 'lab-001',
                       'occurred_at': source_at, 'kind': 'protected_document_access',
                       'doc_id': 'araz-plan'} for i in range(6)]
            ingestion = request('/api/v1/telemetry', {'events': events})
            baseline = request('/api/v1/cases')['items'][0]
            first = request('/api/v1/cases/changes?after=0')
            assert baseline['current_score'] == 80
            assert ingestion['origin'] == 'AUTHENTICATED_EXTERNAL_REPORT'
            # The explicitly synthetic source time places expiry a few seconds away.
            # Wall time advances normally; no application clock is patched.
            time.sleep(max(0, source_at + 120.2 - time.time()))
            path = f"/api/v1/cases/changes?after={first['next_cursor']}&generation={first['generation']}"
            page = request(path)
            quiet = request('/api/v1/cases')['items'][0]
            replay = request(path)
            next_page = request(f"/api/v1/cases/changes?after={page['next_cursor']}&generation={page['generation']}")
            report.update({'source_origin': ingestion['origin'], 'source_age_at_final_read_seconds': round(time.time()-source_at,3),
                'before': {'current_score': baseline['current_score'], 'peak_score': baseline['peak_score']},
                'after': {'current_score': quiet['current_score'], 'peak_score': quiet['peak_score'], 'status': quiet['status']},
                'expiry_feed': page, 'replayed_items': len(replay['items']), 'next_poll_items': len(next_page['items'])})
            assert quiet['current_score'] == 0 and quiet['peak_score'] == 80 and quiet['status'] == 'OPEN'
            assert len(page['items']) == 1 and page['items'][0]['action'] == 'SIGNAL_STATE' and page['items'][0]['priority'] == 0
            assert replay['items'] == page['items'] and next_page['items'] == []
            assert page['signal_refresh']['status'] == 'current'
            report['successful'] = True
        finally:
            if key and key.get('id'):
                status, revoked = admin.request('/api/integrations/keys', {'action': 'revoke', 'id': key['id']})
                report['key_revoked'] = status == 200 and revoked['revoked']
            server.shutdown()
            server.server_close()
            thread.join(5)
            app.close()
    (ROOT / 'artifacts' / 'ueba_headless_http_smoke_v1.json').write_text(
        json.dumps(report, indent=2), encoding='utf-8', newline='\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
