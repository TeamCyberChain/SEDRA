"""Reproduce the access -> sensitive attempts -> changed policy sequence locally."""
from datetime import datetime,timezone
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from sedra import __version__
from sedra.app import AppState,handler_for
from sedra.corpus import catalog
from test_app import LocalClient


def main():
    with tempfile.TemporaryDirectory(prefix='sedra-ueba-http-') as folder:
        app=AppState(folder)
        server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(app))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            base=f'http://127.0.0.1:{server.server_port}'
            employee=LocalClient(base).login('lab-001');admin=LocalClient(base).login('analyst')
            def call(client,path,body=None):
                status,data=client.request(path,body);assert status==200,(path,status,data)
                return data
            quote=next(f['text'] for f in catalog()[0]['fragments'] if f['label']=='Context comparison excerpt')
            initial=call(employee,'/api/ueba?subject=lab-001')
            before=call(employee,'/api/transfer',{'request_id':'ueba-normal-quote','text':quote})
            assert before['decision']=='ALLOW'
            for i in range(3):call(employee,'/api/document?id=araz-plan')
            for i in range(2):
                blocked=call(employee,'/api/transfer',{'request_id':'ueba-sequence-'+str(i),'text':'FİN: A1B2C3D'})
                assert blocked['decision']=='BLOCK'
            elevated=call(employee,'/api/ueba?subject=lab-001')
            assert elevated['live_context']['protected_document_reads']==3
            assert elevated['live_context']['blocked_attempts']==2
            assert elevated['live_context']['score']==85
            assert elevated['live_context']['active_rule_ids']==['access_then_sensitive_attempts']
            after=call(employee,'/api/transfer',{'request_id':'ueba-elevated-quote','text':quote})
            assert after['decision']=='BLOCK' and before['body_sha256']==after['body_sha256']
            assert before['threshold']==.2 and after['threshold']==.1
            replay=call(employee,'/api/transfer',{'request_id':'ueba-normal-quote','text':quote})
            assert replay['idempotent_replay'] and replay['behavior_context']==before['behavior_context']
            assert len(app.receiver.list())==1
            public=call(employee,'/api/transfer',{'request_id':'ueba-public-negative','text':'Public workshop schedule.'})
            assert public['decision']=='ALLOW';assert len(app.receiver.list())==2
            # Exercise the same frozen context on the configured local AI route without inference.
            local_ready=app.portal.local_provider.ready()
            if local_ready:call(admin,'/api/portal/configure',{'provider':'local'})
            else:
                # A blocked-route fixture needs no installed model and must never reach generate().
                with app.guard:app.portal.route='local'
            portal=call(employee,'/api/portal/chat',{'request_id':'ueba-ai-context-quote','text':quote})
            assert not portal['provider_contacted'] and portal['request']['decision']=='BLOCK'
            assert portal['request']['behavior_context']['live_context']['score']>=85
            scopes=employee.request('/api/ueba?subject=lab-002')[0];assert scopes==403
            assert 'A1B2C3D' not in json.dumps(elevated)
            with patch('sedra.app.time.time',return_value=time.time()+1801):
                cooled=app.live_subject(app.subjects['lab-001'])
            assert cooled['live_context']['score']==0
            timings=[]
            for _ in range(3):
                start=time.perf_counter();view=call(admin,'/api/state');timings.append(round((time.perf_counter()-start)*1000,2))
            report={'executed_at_utc':datetime.now(timezone.utc).isoformat(),'version':__version__,'successful':True,
                'scope':'Isolated real HTTP, synthetic inputs, app-only events; no inference/cloud call or efficacy claim',
                'initial_policy':initial['policy_context'],'elevated_policy':elevated['policy_context'],
                'active_rules_at_3_reads_2_blocks':elevated['live_context']['active_rule_ids'],
                'before':{'decision':before['decision'],'threshold':before['threshold'],'body_sha256':before['body_sha256']},
                'after':{'decision':after['decision'],'threshold':after['threshold'],'body_sha256':after['body_sha256']},
                'frozen_context_replay':True,'receiver_receipts':len(app.receiver.list()),'public_negative_control':public['decision'],
                'portal_block_before_inference':True,'employee_other_subject_http':scopes,'live_value_masked':True,
                'portal_setup':'ready managed local service' if local_ready else 'server-side blocked-route fixture; no model dependency',
                'cooled_live_score':cooled['live_context']['score'],'live_baseline':elevated['live_context']['personal_baseline'],
                'three_local_state_response_times_ms':timings,'state_subject_count':len(view['subjects']),
                'elevated_evidence':elevated,'counts':view['counts']}
            (ROOT/'artifacts/ueba_http_smoke_v2.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
            print(json.dumps({k:v for k,v in report.items() if k not in ('elevated_evidence','live_baseline')},indent=2))
        finally:
            server.shutdown();server.server_close();thread.join(3);app.close()


if __name__=='__main__':main()
