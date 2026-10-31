"""Exercise the alert lifecycle over real isolated loopback HTTP endpoints."""
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from sedra import __version__
from sedra.app import AppState,handler_for
from test_app import LocalClient


def main():
    with tempfile.TemporaryDirectory(prefix='sedra-alert-http-') as directory:
        app=AppState(directory)
        server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(app))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            base=f'http://127.0.0.1:{server.server_port}'
            admin=LocalClient(base).login('analyst');employee=LocalClient(base).login('lab-001')
            def call(client,path,body=None):
                status,result=client.request(path,body)
                assert status==200,(path,status,result)
                return result
            body={'request_id':'alert-http-fin-test','text':'FİN: A1B2C3D'}
            blocked=call(employee,'/api/transfer',body)
            repeated=call(employee,'/api/transfer',body)
            assert blocked['decision']=='BLOCK' and repeated['idempotent_replay']
            assert blocked['alert_ids']==repeated['alert_ids'] and len(blocked['alert_ids'])==1
            key=blocked['alert_ids'][0]
            feed=call(admin,'/api/alerts');assert feed['counts']['total']==1
            detail=call(admin,'/api/alerts?id='+key)
            assert 'A1B2C3D' not in json.dumps(detail)
            assert app.receiver.list()==[]
            assert employee.request('/api/alerts')[0]==403
            assert employee.request('/api/alerts?id='+key)[0]==403
            ack={'alert_id':key,'action_id':'alert-http-ack-001','action':'ACKNOWLEDGE','expected_revision':0}
            assert employee.request('/api/alerts/action',ack)[0]==403
            assert admin.request('/api/alerts/action',ack,token=False)[0]==403
            review=call(admin,'/api/alerts/action',ack)['alert'];assert review['status']=='IN_REVIEW'
            assert call(admin,'/api/alerts/action',ack)['idempotent_replay']
            assert admin.request('/api/alerts/action',ack|{'action_id':'http-stale-ack-001'})[0]==409
            closed=call(admin,'/api/alerts/action',{'alert_id':key,'action_id':'alert-http-resolve-001',
                'action':'RESOLVE','expected_revision':1,'disposition':'EXPECTED_TEST'})['alert']
            assert closed['status']=='RESOLVED'
            final_detail=call(admin,'/api/alerts?id='+key)
            assert len(final_detail['history'])==2 and final_detail['request']['state']=='BLOCKED'
            call(admin,'/api/portal/configure',{'provider':'local'})
            portal=call(employee,'/api/portal/chat',{'request_id':'alert-http-portal-001','text':'FİN: A1B2C3D'})
            assert portal['provider_contacted'] is False and portal['ai'] is None
            assert len(portal['request']['alert_ids'])==1
            unknown=call(employee,'/api/transfer',{'request_id':'alert-http-ackloss','text':'Public workshop invitation.', 'simulate_ack_loss':True})
            assert unknown['state']=='DELIVERY_UNKNOWN' and len(unknown['alert_ids'])==1
            ukey=unknown['alert_ids'][0];uncertain=call(admin,'/api/alerts?id='+ukey)['alert']
            assert uncertain['decision']=='ALLOW' and uncertain['severity']=='medium'
            assert uncertain['outcome']=='Delivery unconfirmed'
            receipt_count=len(app.receiver.list());assert receipt_count==1
            reconciled=call(employee,'/api/reconcile',{'request_id':'alert-http-ackloss'})
            assert reconciled['state']=='FORWARDED_CONFIRMED' and len(app.receiver.list())==receipt_count
            updated=call(admin,'/api/alerts?id='+ukey)['alert']
            assert updated['outcome']=='Delivery confirmed' and updated['status']=='OPEN'
            feed=call(admin,'/api/alerts');assert feed['counts']['total']==3
            report={'executed_at_utc':datetime.now(timezone.utc).isoformat(),'version':__version__,
                'successful':True,'scope':'Isolated loopback HTTP, synthetic fixtures, no AI inference or external notification sent',
                'policy_block_alert':detail['alert'],'blocked_retry_deduplicated':True,
                'masked_value_absent':True,'employee_feed_detail_and_action_http':403,'missing_csrf_http':403,
                'stale_revision_http':409,'repeated_action_deduplicated':True,'analyst_history':final_detail['history'],
                'resolved_request_remained':'BLOCKED','portal_block_before_provider':True,
                'uncertainty_before':uncertain['outcome'],'uncertainty_after':updated['outcome'],
                'reconciliation_receipts_before':receipt_count,'reconciliation_receipts_after':len(app.receiver.list()),
                'reconciliation_did_not_close_analyst_review':updated['status'],'final_counts':feed['counts']}
            (ROOT/'artifacts/alerts_http_smoke_v1.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
            print(json.dumps({k:v for k,v in report.items() if k not in ('policy_block_alert','analyst_history')},indent=2))
        finally:
            server.shutdown();server.server_close();thread.join(3);app.close()


if __name__=='__main__':main()
