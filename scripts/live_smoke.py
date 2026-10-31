"""Rehearse the real loopback HTTP demo and save actual delivery evidence.

Explicitly resets only this application's synthetic demonstration ledger.
Never pass a production endpoint. No external AI or organization data is used.
"""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
from http.cookiejar import CookieJar
import json
from pathlib import Path
import urllib.request
from urllib.parse import urlsplit

def run(base, output):
    parsed=urlsplit(base)
    if parsed.scheme!='http' or parsed.hostname not in ('127.0.0.1','localhost'):
        raise ValueError('Only the authorized loopback hackathon lab is accepted')
    client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(CookieJar()))
    csrf=None
    def call(path,body=None):
        nonlocal csrf
        headers={}
        if body is not None:
            headers={'Content-Type':'application/json','X-CSRF-Token':csrf or ''}
        request=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,headers=headers)
        with client.open(request,timeout=10) as response:
            value=json.load(response)
        if 'session' in value:
            csrf=value['session']['csrf_token']
        return value
    call('/api/state')
    call('/api/session',{'identity':'analyst'})
    call('/api/reset',{})
    call('/api/session',{'identity':'lab-001'})
    state=call('/api/state')
    source=next(d for d in state['documents'] if d['id']=='araz-plan')
    results={}
    for i,fragment in enumerate(source['fragments'][:3]):
        call('/api/document?id=araz-plan')
        results[f'fragment_{i+1}']=call('/api/transfer',{'request_id':f'smoke-fragment-{i+1:03d}','text':fragment['text']})
    assert [results[f'fragment_{i+1}']['state'] for i in range(3)]==['FORWARDED_CONFIRMED','FORWARDED_CONFIRMED','BLOCKED']
    state=call('/api/state');assert len(state['receiver'])==2
    for i,fragment in enumerate(source['fragments'][:2]):
        receipt=next(r for r in state['receiver'] if r['request_id']==f'smoke-fragment-{i+1:03d}')
        assert receipt['sha256']==sha256(fragment['text'].encode()).hexdigest()
        assert receipt['utf8_bytes']==len(fragment['text'].encode())
    quote=source['fragments'][-1]['text']
    results['context_before']=call('/api/transfer',{'request_id':'smoke-context-before','text':quote})
    assert results['context_before']['decision']=='ALLOW'
    for _ in range(6):
        call('/api/document?id=araz-plan')
    results['context_after']=call('/api/transfer',{'request_id':'smoke-context-after','text':quote})
    assert results['context_after']['decision']=='BLOCK'
    assert results['context_before']['body_sha256']==results['context_after']['body_sha256']
    results['restricted_short']=call('/api/transfer',{'request_id':'smoke-restricted-short','text':'restricted runbook'})
    assert results['restricted_short']['state']=='BLOCKED'
    results['ack_loss']=call('/api/transfer',{'request_id':'smoke-ack-loss','text':'A public delivery acknowledgment example.','simulate_ack_loss':True})
    assert results['ack_loss']['state']=='DELIVERY_UNKNOWN'
    before=len(call('/api/state')['receiver'])
    results['reconciled']=call('/api/reconcile',{'request_id':'smoke-ack-loss'})
    assert results['reconciled']['state']=='FORWARDED_CONFIRMED'
    assert len(call('/api/state')['receiver'])==before
    state=call('/api/state')
    report={'executed_at_utc':datetime.now(timezone.utc).isoformat(),'base':base,'successful':True,
            'scope':'synthetic loopback HTTP only','results':results,'receiver':state['receiver'],'counts':state['counts']}
    Path(output).write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    call('/api/session',{'identity':'analyst'})
    print(json.dumps({'successful':True,'counts':state['counts'],'artifact':output},indent=2))
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',default='http://127.0.0.1:8765')
    p.add_argument('--output',default='artifacts/live_smoke.json')
    args=p.parse_args();run(args.base,args.output)
