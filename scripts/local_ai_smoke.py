"""Actual loopback model execution and safe retry. Refuses cloud routes."""
from datetime import datetime,timezone
from http.cookiejar import CookieJar
from pathlib import Path
from time import perf_counter
import json,urllib.request,uuid

def run():
    base='http://127.0.0.1:8765'
    http=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(CookieJar()))
    csrf=''
    def call(path,body=None):
        nonlocal csrf
        request=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,
            headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
        with http.open(request,timeout=55) as response:value=json.load(response)
        if 'session' in value:csrf=value['session']['csrf_token']
        return value
    status=call('/api/portal/status')
    if status['connection'].get('provider_id')!='local' or not status['connection']['configured']:
        raise ValueError('This smoke check refuses cloud or unready inference')
    call('/api/session',{'identity':'lab-001'})
    key='local-live-'+uuid.uuid4().hex
    body={'request_id':key,'text':'What is 17 plus 25? Answer with the number only.'}
    started=perf_counter();answer=call('/api/portal/chat',body);elapsed=perf_counter()-started
    if answer['request']['state']!='FORWARDED_CONFIRMED' or not answer.get('ai') or answer['ai'].get('external_data_transfer') is not False:
        raise AssertionError('No confirmed real local-model response')
    events=call('/api/state')['events']
    sends_before=sum(e['kind']=='ai_provider_send_claimed' and e['detail'].get('request_id')==key for e in events)
    retry=call('/api/portal/chat',body)
    events=call('/api/state')['events']
    sends_after=sum(e['kind']=='ai_provider_send_claimed' and e['detail'].get('request_id')==key for e in events)
    assert retry['request']['idempotent_replay'] and retry['ai']['response_id']==answer['ai']['response_id']
    assert sends_before==sends_after==1
    blocked=call('/api/portal/chat',{'request_id':'local-block-'+uuid.uuid4().hex,'text':'restricted runbook SEDRA_SECRET_A1B2C3D4E5F6G7H8'})
    assert blocked['request']['state']=='BLOCKED' and blocked['provider_contacted'] is False
    # The model API itself must reject unauthenticated inference.
    try:
        request=urllib.request.Request('http://127.0.0.1:8769/v1/chat/completions',data=b'{}',headers={'Content-Type':'application/json'})
        with http.open(request,timeout=3):raise AssertionError('Unauthenticated model route accepted')
    except urllib.error.HTTPError as error:
        assert error.code==401;error.close()
    report={'executed_at_utc':datetime.now(timezone.utc).isoformat(),'successful':True,
        'scope':'Actual local Qwen inference through SEDRA; no cloud provider, test double or reset',
        'inference_roundtrip_seconds':round(elapsed,3),'answer':answer,'idempotent_retry':retry,'restricted':blocked,
        'outbound_claims_before_retry':sends_before,'outbound_claims_after_retry':sends_after,
        'unauthenticated_inference_rejected':True}
    target=Path(__file__).resolve().parents[1]/'artifacts/local_ai_http_smoke.json'
    target.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps({'successful':True,'answer':answer['ai']['answer'],'roundtrip_seconds':round(elapsed,3),
        'same_response_on_retry':True,'blocked_before_model':True,'model_api_requires_auth':True}))

if __name__=='__main__':run()
