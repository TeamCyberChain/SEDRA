import base64
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import json
from pathlib import Path
import unittest
import urllib.error
import urllib.request
import zipfile

from sedra.browser_guard import extract_file,InspectionFailure,EXTENSION_ORIGIN,MAX_FILE
import test_integrations as integration_test_support


def office(name,source,extra=None):
    stream=BytesIO()
    with zipfile.ZipFile(stream,'w') as z:
        z.writestr(name,source)
        for n,b in (extra or {}).items():z.writestr(n,b)
    return stream.getvalue()


class BrowserPolicyHTTPTests(unittest.TestCase):
    def setUp(self):
        self.lab=integration_test_support.IntegrationHTTPTests();self.lab.setUp()
        self.key=self.lab.key(['browser:inspect'],['lab-001'])
    def tearDown(self):self.lab.tearDown()
    def payload(self,**change):
        return {'request_id':'br-browser-test-001','host':'gemini.google.com','operation':'send','mode':'preview','text':'Explain photosynthesis.','files':[]}|change
    def call(self,b,key=None,origin=EXTENSION_ORIGIN,method=None):
        request=urllib.request.Request(self.lab.base+'/api/v1/browser/inspect',data=json.dumps(b).encode() if b is not None else None,
            headers={'Content-Type':'application/json','Authorization':'Bearer '+(key if key is not None else self.key['token']),**({'Origin':origin} if origin else {})},method=method)
        http=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:response=http.open(request,timeout=10)
        except urllib.error.HTTPError as error:response=error
        with response:return response.status,json.load(response),dict(response.headers)
    def test_scope_actor_binding_and_precise_extension_origin(self):
        self.assertEqual(self.call(self.payload(),key='')[0],401)
        reader=self.lab.key(['cases:read'])
        self.assertEqual(self.call(self.payload(),key=reader['token'])[0],403)
        for subjects in ([],['lab-001','lab-002']):
            self.assertEqual(self.lab.admin.request('/api/integrations/keys',{'name':'invalid browser','scopes':['browser:inspect'],'subjects':subjects})[0],400)
        self.assertEqual(self.call(self.payload(subject_id='lab-002'))[0],400)
        self.assertEqual(self.call(self.payload(behavior_score=0))[0],400)
        self.assertEqual(self.call(self.payload(),origin='https://gemini.google.com')[0],403)
        self.assertEqual(self.call(self.payload(),origin='chrome-extension://'+'a'*32)[0],403)
        status,_,headers=self.call(None,method='OPTIONS');self.assertEqual(status,200);self.assertEqual(headers['Access-Control-Allow-Origin'],EXTENSION_ORIGIN)
        self.assertEqual(self.call(self.payload())[0],200)
    def test_safe_preview_does_not_reserve_exposure_or_create_attempt_rows(self):
        for i in range(5):
            status,value,_=self.call(self.payload(request_id='br-preview-'+str(i)));self.assertEqual(status,200)
            self.assertEqual(value['decision'],'ALLOW');self.assertEqual(value['state'],'PREVIEW_ALLOWED')
        self.assertEqual(self.lab.app.gateway.requests(),[])
        self.assertEqual(self.lab.app.gateway.alerts_feed()['items'],[])
    def test_local_harness_does_not_claim_installed_extension_evidence(self):
        status,value=self.lab.admin.request('/api/browser-lab/inspect',self.payload(host='sedra-browser-lab',text='FIN: 7ABC123'))
        self.assertEqual(status,200);self.assertEqual(value['decision'],'BLOCK')
        alert=self.lab.app.gateway.alerts_feed()['items'][0]
        self.assertEqual(alert['browser_context']['origin'],'LOCAL_BROWSER_DOM_HARNESS')
        self.assertIn('Local harness',alert['outcome'])
        self.assertNotIn('Extension-reported',alert['browser_context']['enforcement'])
        self.assertEqual(self.lab.admin.request('/api/browser-lab/inspect',self.payload())[0],400)
        for path in ['/browser-deployment/signing.key','/browser-deployment/../signing.key']:
            self.assertEqual(self.lab.admin.request(path)[0],404)
    def test_sensitive_prompt_and_text_attachment_block_create_masked_alerts(self):
        secret='FIN: 7ABC123'
        for operation,files,text in [('paste',[],secret),('draft',[],secret),('file',[{'name':'Private customer James.txt','data':base64.b64encode(secret.encode()).decode()}],'')]:
            status,value,_=self.call(self.payload(request_id='br-secret-'+operation,operation=operation,text=text,files=files))
            self.assertEqual(status,200);self.assertEqual(value['decision'],'BLOCK');self.assertTrue(value['alert_ids'])
        alerts=self.lab.app.gateway.alerts_feed()['items'];self.assertEqual(len(alerts),3)
        self.assertEqual({a['subject_id'] for a in alerts},{'lab-001'})
        wire=json.dumps(alerts);self.assertNotIn('7ABC123',wire);self.assertNotIn('James',wire)
        self.assertTrue(all(a['browser_context']['origin']=='AUTHENTICATED_BROWSER_REPORT' for a in alerts))
        self.assertEqual(self.lab.app.browser_guard.lab_receipts()['items'],[])
        for path in self.lab.app.data_dir.glob('*.sqlite'):
            self.assertNotIn(secret.encode(),path.read_bytes())
    def test_release_is_one_use_concurrency_safe_and_never_claims_delivery(self):
        body=self.payload(mode='release')
        with ThreadPoolExecutor(max_workers=2) as pool:values=list(pool.map(lambda _:self.call(body)[1],range(2)))
        self.assertEqual(sum(v['decision']=='ALLOW' for v in values),1)
        row=self.lab.app.gateway.requests()[0];self.assertEqual(row['state'],'DELIVERY_UNKNOWN')
        self.assertTrue(all(v.get('delivery_confirmed') is not True for v in values))
        self.assertEqual(len(self.lab.app.gateway.requests()),1)
        self.assertEqual(self.call(self.payload(mode='release',text='Changed prompt'))[0],400)
    def test_unknown_oversized_and_mislabeled_files_fail_closed_with_alert(self):
        for i,(name,raw) in enumerate([('image.png',b'png'),('pretend.txt',b'%PDF compressed'),('unknown.pdf',b'%PDF'),('large.txt',b'a'*(MAX_FILE+1))]):
            status,value,_=self.call(self.payload(request_id='br-file-limit-'+str(i),operation='file',files=[{'name':name,'data':base64.b64encode(raw).decode()}]))
            self.assertEqual(status,200);self.assertEqual(value['decision'],'BLOCK');self.assertTrue(value['inspection_failure']);self.assertTrue(value['alert_ids'])
        self.assertEqual(self.call(self.payload(files=[{'name':'a.txt','data':'!!!!'}]))[0],400)
    def test_offline_reports_are_idempotent_and_do_not_fabricate_current_behavior(self):
        for i in range(3):
            body=self.payload(request_id='br-offline-test-'+str(i),operation='offline',failure='BACKEND_UNAVAILABLE',text='')
            self.assertEqual(self.call(body)[1]['decision'],'BLOCK');self.assertEqual(self.call(body)[0],200)
        self.assertEqual(len(self.lab.app.gateway.alerts_feed()['items']),3)
        self.assertEqual(self.lab.app.live_subject(self.lab.app.subjects['lab-001'])['live_context']['score'],0)
    def test_file_bytes_bind_request_even_when_extracted_text_is_identical(self):
        body=self.payload(operation='file',files=[{'name':'a.txt','data':base64.b64encode(b'FIN: 7ABC123').decode()}])
        self.assertEqual(self.call(body)[1]['decision'],'BLOCK')
        changed=self.payload(operation='file',files=[{'name':'a.txt','data':base64.b64encode(b'\xef\xbb\xbfFIN: 7ABC123').decode()}])
        self.assertEqual(self.call(changed)[0],400)
    def test_browser_releases_share_cumulative_gateway_coverage(self):
        from sedra.corpus import DOCUMENTS
        words=next(d['text'] for d in DOCUMENTS if d['id']=='araz-plan').split();n=int(len(words)*.13)
        first=' '.join(words[:n]);second=' '.join(words[n:2*n])
        self.assertEqual(self.call(self.payload(request_id='br-budget-preview1',text=first))[1]['decision'],'ALLOW')
        self.assertEqual(self.lab.app.gateway.requests(),[])
        self.assertEqual(self.call(self.payload(request_id='br-budget-release1',text=first,mode='release'))[1]['decision'],'ALLOW')
        status,value,_=self.call(self.payload(request_id='br-budget-preview2',text=second))
        self.assertEqual(status,200);self.assertEqual(value['decision'],'BLOCK')
        self.assertIn('CUMULATIVE_DISCLOSURE_LIMIT',value['reason_codes'])


class AttachmentExtractionTests(unittest.TestCase):
    def test_word_split_runs_are_rejoined_and_sheet_text_is_inspected(self):
        xml='<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>FIN: 7AB</w:t></w:r><w:r><w:t>C123</w:t></w:r></w:p></w:document>'
        self.assertIn('FIN: 7ABC123',extract_file('a.docx',office('word/document.xml',xml)))
        raw=office('xl/workbook.xml','<workbook/>',{'xl/sharedStrings.xml':'<sst><si><t>FIN: 7ABC123</t></si></sst>'})
        self.assertIn('FIN: 7ABC123',extract_file('a.xlsx',raw))
    def test_xml_entities_embedded_binary_path_traversal_and_macros_block(self):
        for name,raw in [('a.docx',office('word/document.xml','<!DOCTYPE x [<!ENTITY a "secret">]><x>&a;</x>')),
                         ('a.docx',office('word/document.xml','<document/>',{'word/media/image.png':b'image'})),
                         ('a.xlsx',office('xl/workbook.xml','<x/>',{'../outside.xml':'<x/>'})),('a.docm',b'anything')]:
            with self.assertRaises(InspectionFailure):extract_file(name,raw)
    def test_utf16_and_binary_disguise_and_resource_bounds(self):
        self.assertEqual(extract_file('a.txt','FIN: 7ABC123'.encode('utf-16')),'FIN: 7ABC123')
        for raw in (b'\x00binary',b'\xffnot utf8',b'a'*65537):
            with self.assertRaises(InspectionFailure):extract_file('a.txt',raw)
