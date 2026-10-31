"""Actual local HTTP blocking/allow controls, separate from the user's live ledger."""
from datetime import datetime,timezone
from hashlib import sha256
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'tests'))
from test_app import LocalClient
from structured_cases import positive_cases,negative_cases
from sedra.app import AppState,handler_for


def main():
    with tempfile.TemporaryDirectory(prefix='sedra-structured-http-') as directory:
        app=AppState(directory)
        server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(app))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            base=f'http://127.0.0.1:{server.server_port}'
            employee=LocalClient(base).login('lab-001')
            admin=LocalClient(base).login('analyst')
            rows=[]
            for index,(name,(kind,text)) in enumerate(positive_cases().items()):
                status,result=employee.request('/api/transfer',{'request_id':f'http-positive-{index}','text':text})
                assert status==200 and result['decision']=='BLOCK',(name,status,result)
                assert kind in result['security_tags']['detector_tags']
                assert result['body_sha256']==sha256(text.encode()).hexdigest()
                rows.append({'name':name,'status':status,'decision':result['decision'],
                    'types':result['security_tags']['detector_tags'],'body_sha256':result['body_sha256']})
            assert app.receiver.list()==[]
            for index,(name,text) in enumerate(negative_cases().items()):
                status,result=employee.request('/api/transfer',{'request_id':f'http-negative-{index}','text':text})
                assert status==200 and result['state']=='FORWARDED_CONFIRMED',(name,status,result)
                rows.append({'name':name,'status':status,'decision':result['decision'],'state':result['state']})
            assert len(app.receiver.list())==len(negative_cases())
            status,_=admin.request('/api/portal/configure',{'provider':'local'})
            assert status==200
            status,catalog_view=admin.request('/api/state')
            assert status==200
            portal_rows=[]
            for key in ('fin_json','iban_grouped'):
                sample=catalog_view['data_types']['examples'][key]
                status,result=employee.request('/api/portal/chat',{'request_id':'portal-'+key,'text':sample['text']})
                assert status==200 and result['request']['decision']=='BLOCK'
                assert result['provider_contacted'] is False and result['ai'] is None
                portal_rows.append({'sample':key,'provider_contacted':False,'request':result['request']})
            assert len(app.receiver.list())==len(negative_cases())
            status,reply=employee.request('/api/portal/chat',{'request_id':'new-structured-model-proof','text':'Compute 17 + 25. Reply with only the integer.'})
            assert status==200 and reply['ai'] and '42' in reply['ai']['answer']
            status,final_view=admin.request('/api/state')
            assert status==200
            report={'executed_at_utc':datetime.now(timezone.utc).isoformat(),'successful':True,
                'scope':'Isolated HTTP app; synthetic cases and managed local model; no cloud or bank/identity lookup',
                'positive_blocked':len(positive_cases()),'negative_controls_forwarded':len(negative_cases()),
                'independent_receiver_receipts':len(app.receiver.list()),'rows':rows,'portal_blocks':portal_rows,
                'local_ai':reply['ai'],'counts':final_view['counts']}
            (ROOT/'artifacts/structured_http_smoke_v3.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
            print(json.dumps({k:v for k,v in report.items() if k not in ('rows','portal_blocks','local_ai')},indent=2))
        finally:
            server.shutdown();server.server_close();thread.join(3);app.close()


if __name__=='__main__':main()
