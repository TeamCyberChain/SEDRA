"""Real Windows process/files -> independent case -> frozen policy explanation."""
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
    if os.name!='nt':raise SystemExit('Real Windows smoke requires Windows; fixture tests run separately')
    with tempfile.TemporaryDirectory(prefix='sedra-case-') as folder:
        app=AppState(folder);server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(app))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            base=f'http://127.0.0.1:{server.server_port}'
            analyst=LocalClient(base).login('analyst');employee=LocalClient(base).login('lab-001')
            def call(c,path,body=None):
                status,value=c.request(path,body);assert status==200,(path,status,value)
                return value
            quote=next(f['text'] for f in catalog()[0]['fragments'] if f['label']=='Context comparison excerpt')
            before=call(employee,'/api/transfer',{'request_id':'case-normal-quote','text':quote})
            assert before['decision']=='ALLOW' and before['behavior_score']==0
            call(analyst,'/api/endpoint/action',{'action':'probe'})
            until=time.monotonic()+30
            # Read the case store directly: the UI/API read must not create this case.
            while True:
                feed=app.cases.feed()
                if feed['items'] and feed['items'][0]['peak_score']==90:break
                if time.monotonic()>until:raise AssertionError('Independent case not captured from real collector callback')
                time.sleep(.3)
            case=feed['items'][0];packet=app.cases.get(case['case_id'],packet=True)
            assert app.gateway.alerts_feed()['counts']['total']==0
            assert packet['integrity']['hash_chain_valid'] and packet['integrity']['displayed_snapshot_bound']
            assert any(e['relation']=='same_server_probe_run_and_time' for e in packet['snapshot']['edges'])
            assert employee.request('/api/ueba/cases')[0]==403
            assert analyst.request('/api/ueba/cases/action',{},token=False)[0]==403
            after=call(employee,'/api/transfer',{'request_id':'case-tightened-quote','text':quote})
            assert after['decision']=='BLOCK' and after['behavior_score']==90
            assert before['body_sha256']==after['body_sha256']
            assert after['behavior_context']['behavior_case']['case_id']==case['case_id']
            rules=[*after['behavior_context']['live_context']['rules'],*after['behavior_context']['endpoint_context']['rules']]
            excluded=[r['rule_id'] for r in rules if r['active']]
            receipts=len(app.receiver.list())
            preview=call(analyst,'/api/ueba/counterfactual',{'subject_id':'lab-001','request_id':after['request_id'],'exclude_rules':excluded})
            assert preview['supported'] and preview['original']['decision']=='BLOCK' and preview['hypothetical']['decision']=='ALLOW'
            assert len(app.receiver.list())==receipts and app.gateway.get_request(subject_id='lab-001',request_id=after['request_id'])['decision']=='BLOCK'
            hard=call(employee,'/api/transfer',{'request_id':'case-hard-fin','text':'FİN: A1B2C3D'})
            hard_rules=[*hard['behavior_context']['live_context']['rules'],*hard['behavior_context']['endpoint_context']['rules']]
            hard_preview=call(analyst,'/api/ueba/counterfactual',{'subject_id':'lab-001','request_id':hard['request_id'],
                'exclude_rules':[r['rule_id'] for r in hard_rules if r['active']],'exclude_daily':True})
            assert hard_preview['hypothetical']['decision']=='BLOCK' and hard_preview['hypothetical']['hard_policy_unchanged']
            call(analyst,'/api/endpoint/action',{'action':'stop'})
            # Stop/join before evaluating a future window: no future-timestamp source rows are generated.
            app.endpoint.close()
            process_at=max(e['at'] for e in app.endpoint.view()['events'] if e['channel']=='process')
            partial=app.live_subject(app.subjects['lab-001'],now=process_at+120.05)
            assert partial['live_context']['score']==75
            retained=app.cases.get(case['case_id'])
            assert retained['snapshot']['priority']==90 and any(e['relation']=='same_server_probe_run_and_time' for e in retained['snapshot']['edges'])
            cooled=app.live_subject(app.subjects['lab-001'],now=time.time()+1801)
            assert cooled['live_context']['score']==0
            quiet=app.cases.get(case['case_id']);assert quiet['case']['status']=='OPEN' and quiet['case']['signal_state']=='QUIET' and quiet['case']['peak_score']==90
            body={'case_id':case['case_id'],'action':'ACKNOWLEDGE','expected_revision':quiet['case']['revision'],'action_id':'live-case-ack-01'}
            call(analyst,'/api/ueba/cases/action',body)
            replay=call(analyst,'/api/ueba/cases/action',body);assert replay['idempotent_replay']
            stale=body|{'action_id':'live-case-stale-01','action':'RESOLVE','disposition':'EXPECTED_LAB_TEST'}
            assert analyst.request('/api/ueba/cases/action',stale)[0]==409
            current=call(analyst,'/api/ueba/cases?id='+case['case_id'])
            call(analyst,'/api/ueba/cases/action',stale|{'action_id':'live-case-resolve-01','expected_revision':current['case']['revision']})
            final=call(analyst,'/api/ueba/cases?id='+case['case_id'])
            assert final['case']['status']=='RESOLVED' and final['integrity']['hash_chain_valid'] and final['integrity']['displayed_snapshot_bound']
            report={'executed_at_utc':datetime.now(timezone.utc).isoformat(),'successful':True,
                'scope':'Isolated loopback HTTP, real Windows CIM current-identity owned process and real synthetic lab file creation; aggregate proof only',
                'independent_case_before_any_dlp_block':True,'peak_observed_live_priority':90,
                'exact_run_process_file_edges':sum(e['relation']=='same_server_probe_run_and_time' for e in packet['snapshot']['edges']),
                'original_quote_decisions':[before['decision'],after['decision']],'original_quote_thresholds':[before['threshold'],after['threshold']],
                'same_payload':before['body_sha256']==after['body_sha256'],
                'frozen_ablation_decisions':[preview['original']['decision'],preview['hypothetical']['decision']],
                'preview_did_not_resend_or_unblock':True,'hard_fin_still_blocks':True,
                'case_retained_when_live_window_cooled':True,'peak_graph_retained_during_partial_sequence_expiry':True,
                'review_workflow':'OPEN -> IN_REVIEW -> RESOLVED / EXPECTED_LAB_TEST',
                'idempotent_action_replay':True,'stale_revision_http':409,'employee_read_http':403,'missing_csrf_http':403,
                'hash_chain_consistent':final['integrity']['hash_chain_valid'],'displayed_snapshot_bound':final['integrity']['displayed_snapshot_bound'],
                'integrity_limit':'Self-contained consistency only; no independently trusted signature or privileged rewrite resistance',
                'receiver_receipts':len(app.receiver.list()),'physical_usb_tested':False,
                'privacy':'Private source rows, case packets, Windows identity fingerprints and sensor salt excluded from this artifact'}
            (ROOT/'artifacts/behavior_cases_http_smoke_v1.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
            print(json.dumps(report,indent=2))
        finally:server.shutdown();server.server_close();thread.join(3);app.close()


if __name__=='__main__':main()

