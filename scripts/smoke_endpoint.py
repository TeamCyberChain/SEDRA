"""Windows-only real local endpoint -> UEBA -> gateway proof; no external calls."""
from datetime import datetime,timezone
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from sedra.app import AppState,handler_for
from sedra.corpus import catalog
from test_app import LocalClient


def main():
    if os.name!='nt':raise SystemExit('This live proof requires Windows; use unit fixtures on other platforms')
    with tempfile.TemporaryDirectory(prefix='sedra-endpoint-') as folder:
        app=AppState(folder);server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(app))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            base=f'http://127.0.0.1:{server.server_port}'
            admin=LocalClient(base).login('analyst');employee=LocalClient(base).login('lab-001')
            def call(c,path,body=None):
                status,value=c.request(path,body);assert status==200,(path,status,value)
                return value
            quote=next(f['text'] for f in catalog()[0]['fragments'] if f['label']=='Context comparison excerpt')
            before=call(employee,'/api/transfer',{'request_id':'endpoint-before-real','text':quote})
            assert before['decision']=='ALLOW' and before['behavior_score']==0
            assert employee.request('/api/endpoint/action',{'action':'start'})[0]==403
            assert admin.request('/api/endpoint/action',{'action':'start'},token=False)[0]==403
            call(admin,'/api/endpoint/action',{'action':'probe'})
            until=time.monotonic()+25
            while True:
                endpoint=call(admin,'/api/endpoint')
                if endpoint['score']==90:break
                if time.monotonic()>until:raise AssertionError('Real CIM + file sequence did not activate within 25 seconds')
                time.sleep(.4)
            assert sum(e['channel']=='file' for e in endpoint['events'])==10
            assert any(e['kind']=='controlled_process_observed' for e in endpoint['events'])
            assert all(e['origin']=='REAL_LOCAL_OBSERVATION' for e in endpoint['events'])
            after=call(employee,'/api/transfer',{'request_id':'endpoint-after-real','text':quote})
            assert after['decision']=='BLOCK' and after['behavior_score']==90
            assert after['body_sha256']==before['body_sha256'] and after['threshold']==.1
            assert after['behavior_context']['endpoint_context']['score']==90
            public=call(employee,'/api/transfer',{'request_id':'endpoint-public-control','text':'Public workshop agenda.'})
            assert public['decision']=='ALLOW'
            report={'executed_at_utc':datetime.now(timezone.utc).isoformat(),'successful':True,
                'scope':'Isolated real Windows current-identity collector, owned Python process, 10 real synthetic lab file creations and loopback HTTP; no external AI or real USB/authentication generated',
                'endpoint_before':0,'endpoint_after':90,'observed_file_changes':10,'cim_owned_process_observed':True,
                'historical_self_session_records':len(endpoint['historical_logons']),
                'collector_coverage':{k:endpoint['status'].get(k) for k in ('security','session_log','usb','process','files')},
                'before_decision':before['decision'],'after_decision':after['decision'],
                'thresholds':[before['threshold'],after['threshold']],'same_original_payload_sha256':before['body_sha256'],
                'endpoint_context_frozen':True,'alert_created':bool(after['alert_ids']),
                'public_negative_control':public['decision'],'receiver_receipts':len(app.receiver.list()),
                'employee_control_http':403,'missing_csrf_http':403,'physical_usb_tested':False,
                'privacy':'Only aggregate outcomes exported; real Windows event records, identity fingerprints and sensor salt remain private runtime data'}
            (ROOT/'artifacts/endpoint_http_smoke_v1.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
            print(json.dumps(report,indent=2))
        finally:
            server.shutdown();server.server_close();thread.join(3);app.close()


if __name__=='__main__':main()
