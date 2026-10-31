"""Run an authorized loopback-only UEBA/API demonstration. Never saves the key."""
from pathlib import Path
from http.cookiejar import CookieJar
from datetime import datetime, timezone
import argparse
import json
import sys
import time
import urllib.request
import urllib.error

BASE = 'http://127.0.0.1:8765'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parents[1] / 'work' / 'api-endpoint-smoke')
args = parser.parse_args()
if sys.platform != 'win32':
    parser.error('This live probe requires the supported Windows lab; use scripts/verify.py for portable regression tests')
OUT = args.output.resolve()
admin = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(CookieJar()))
machine = urllib.request.build_opener(urllib.request.ProxyHandler({}))
csrf = None

def call(path, body=None, *, bearer=None, browser=False):
    global csrf
    headers = {}
    if bearer:
        headers['Authorization'] = 'Bearer ' + bearer
    if browser and body is not None and csrf:
        headers['X-CSRF-Token'] = csrf
    if body is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(BASE + path, headers=headers, data=None if body is None else json.dumps(body).encode())
    try:
        response = (admin if browser else machine).open(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status, value = response.status, json.load(response)
    if browser and status == 200 and 'session' in value:
        csrf = value['session']['csrf_token']
    return status, value

def checked(path, body=None, **kwargs):
    status, value = call(path, body, **kwargs)
    if status != 200:
        raise RuntimeError(f'{path.split("?")[0]} returned HTTP {status}')
    return value

def projection(value):
    ep = value['endpoint_context']
    return {'behavior_score': value['behavior_score'], 'endpoint_score': ep['score'],
            'origin': ep['origin'], 'events_total_30m': ep['events_total_30m'],
            'active_rules': [{k: r[k] for k in ('rule_id','score','observed','note')} for r in ep['rules'] if r['active']]}

result = {'started_at_utc': datetime.now(timezone.utc).isoformat(), 'base_url': BASE,
          'test_scope': 'Owned local child process and ten synthetic files in the named endpoint-lab folder. Real OS observations; no compromise, physical USB or new logon claimed.',
          'key_scopes': ['cases:read','ueba:read'], 'key_ttl_hours': 1}
key = None
try:
    checked('/api/state', browser=True)
    key = checked('/api/integrations/keys', {'name':'Live UEBA API demo - read only','scopes':result['key_scopes'],'subjects':[],'ttl_hours':1}, browser=True)
    result['key_id'] = key['id']
    token = key['token']  # Process memory only; never written or printed.
    result['without_key_http'] = call('/api/v1/cases')[0]
    result['read_key_write_http'] = call('/api/v1/cases/action', {}, bearer=token)[0]
    result['baseline'] = projection(checked('/api/v1/ueba?subject=lab-001', bearer=token))
    page = checked('/api/v1/cases/changes?after=0', bearer=token)
    while len(page['items']) == 100:
        page = checked(f"/api/v1/cases/changes?after={page['next_cursor']}&generation={page['generation']}", bearer=token)
    cursor, generation = page['next_cursor'], page['generation']
    result['baseline_cursor'] = cursor
    result['generation'] = generation
    print(json.dumps({'stage':'KEY_READY','key_id':key['id'],'scopes':result['key_scopes'],'without_key_http':result['without_key_http'],'read_key_write_http':result['read_key_write_http'],'baseline':result['baseline']}), flush=True)
    probe = checked('/api/endpoint/action', {'action':'probe'}, browser=True)
    result['probe_started'] = probe['started']
    print(json.dumps({'stage':'REAL_ENDPOINT_PROBE_STARTED','scope':probe['scope']}), flush=True)
    started = time.monotonic()
    while time.monotonic() - started < 35:
        live = checked('/api/v1/ueba?subject=lab-001', bearer=token)
        if live['endpoint_context']['score'] >= 90 and time.monotonic() - started >= 18:
            break
        time.sleep(2)
    result['observed'] = projection(live)
    result['probe_event_origins'] = sorted({e['origin'] for e in live['endpoint_context']['events'] if e.get('detail',{}).get('probe_run') == probe['probe_run']})
    path = f'/api/v1/cases/changes?after={cursor}&generation={generation}'
    status, first = call(path, bearer=token)
    result['change_feed_http'] = status
    result['change_feed_response'] = first
    second = checked(path, bearer=token)
    old_ids = {(generation,e['cursor']) for e in first['items']}
    new_ids = {(generation,e['cursor']) for e in second['items']}
    result['retry'] = {'replayed_existing_events':len(old_ids & new_ids),'additional_revisions':len(new_ids-old_ids), 'deduplication_key':['generation','cursor']}
    next_page = checked(f"/api/v1/cases/changes?after={second['next_cursor']}&generation={generation}", bearer=token)
    result['checkpoint_poll'] = {'after':second['next_cursor'],'items':len(next_page['items']),'next_cursor':next_page['next_cursor']}
    queue = checked('/api/v1/cases', bearer=token)
    result['case_counts'] = queue['counts']
    result['cases'] = [{k:v for k,v in case.items() if k in ('case_id','subject_id','status','revision','priority','current_live_priority','peak_priority','channels')} for case in queue['items']]
    result['passed'] = (result['without_key_http']==401 and result['read_key_write_http']==403 and result['observed']['endpoint_score']==90 and bool(first['items']) and bool(old_ids & new_ids) and result['probe_event_origins']==['REAL_LOCAL_OBSERVATION'])
finally:
    if key:
        result['revocation'] = checked('/api/integrations/keys', {'action':'revoke','id':key['id']}, browser=True)
        result['revoked_key_http'] = call('/api/v1/cases', bearer=key['token'])[0]
    result['finished_at_utc'] = datetime.now(timezone.utc).isoformat()
    result['passed'] = result.get('passed',False) and result.get('revoked_key_http')==401
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT/'result.json').write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=True), flush=True)

if not result['passed']:
    raise SystemExit(1)
