"""Isolated HTTP proof: recent public activity must not hide rule source evidence."""
import argparse
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from sedra.app import AppState,handler_for
from test_app import LocalClient


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-regression',action='store_true',help='Record the pre-repair failure, not a success claim')
    args=parser.parse_args()
    report={'executed_at_utc':datetime.now(timezone.utc).isoformat(),
        'scope':'Isolated real loopback HTTP with authenticated synthetic document reports; no main data, OS observation or external provider',
        'expected_phase':'before_repair' if args.expect_regression else 'after_repair'}
    with tempfile.TemporaryDirectory() as directory:
        app=AppState(directory);server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(app))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        admin=LocalClient(f'http://127.0.0.1:{server.server_port}').login('analyst');key=None
        try:
            status,key=admin.request('/api/integrations/keys',{'name':'Isolated rule evidence smoke','scopes':['telemetry:write','ueba:read','cases:read'],'subjects':['lab-001'],'ttl_hours':1})
            assert status==200
            http=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            def request(path,body=None):
                req=urllib.request.Request(admin.base+path,data=json.dumps(body).encode() if body is not None else None,
                    headers={'Authorization':'Bearer '+key['token'],'Content-Type':'application/json'})
                with http.open(req,timeout=10) as response:
                    assert response.status==200
                    return json.load(response)
            now=time.time()
            events=[{'event_id':'protected-'+str(i),'subject_id':'lab-001','occurred_at':now-10,'kind':'protected_document_access','doc_id':'araz-plan'} for i in range(6)]
            events += [{'event_id':'public-'+str(i),'subject_id':'lab-001','occurred_at':now-1,'kind':'protected_document_access','doc_id':'public-note'} for i in range(61)]
            ingestion=request('/api/v1/telemetry',{'events':events})
            current=request('/api/v1/ueba?subject=lab-001');feed=request('/api/v1/cases')
            report.update({'accepted':ingestion['accepted'],'origin':ingestion['origin'],'priority':current['live_context']['score'],
                'recent_timeline_rows':len(current['ueba']['timeline']),
                'recent_timeline_only_public':all(e['doc_id']=='public-note' for e in current['ueba']['timeline']),
                'retained_rule_records':len(current['ueba'].get('rule_evidence',[])),
                'case_count':feed['counts']['total']})
            if feed['items']:
                packet=app.cases.get(feed['items'][0]['case_id'])
                report.update({'case_trigger_records':len(packet['snapshot']['trigger_source_ids']),
                    'case_nodes':len(packet['snapshot']['nodes']),
                    'case_nodes_only_protected':all(n['doc_id']=='araz-plan' for n in packet['snapshot']['nodes']),
                    'case_hash_chain_valid':packet['integrity']['hash_chain_valid']})
            assert report['priority']==80 and report['recent_timeline_rows']==60 and report['recent_timeline_only_public']
            if args.expect_regression:
                assert report['case_count']==0
                report['defect_reproduced']=True
            else:
                assert report['retained_rule_records']==6 and report['case_count']==1
                assert report['case_trigger_records']==6 and report['case_nodes']==6 and report['case_nodes_only_protected'] and report['case_hash_chain_valid']
                report['successful']=True
        finally:
            if key and key.get('id'):
                status,revoked=admin.request('/api/integrations/keys',{'action':'revoke','id':key['id']})
                report['key_revoked']=status==200 and revoked['revoked']
            server.shutdown();server.server_close();thread.join(5);app.close()
    name='ueba_rule_evidence_before_v1.json' if args.expect_regression else 'ueba_rule_evidence_http_smoke_v1.json'
    (ROOT/'artifacts'/name).write_text(json.dumps(report,indent=2),encoding='utf-8',newline='\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
