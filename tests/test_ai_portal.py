"""Explicit provider doubles test contracts, never live AI efficacy."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from http.server import ThreadingHTTPServer
from pathlib import Path
import io,json,tempfile,threading,unittest,urllib.error
from unittest.mock import patch
from sedra.app import AppState,handler_for
from sedra.ai_portal import OpenAIProvider,ProviderError,NoRedirect
from test_app import LocalClient

TEST_KEY='sk-proj-UNITTEST-NOT-A-REAL-KEY-1234567890'
def fake_answer(key,model,text):
    return {'provider':'OpenAI','response_id':'resp_test_contract_only','provider_request_id':'req_test',
        'model':model,'status':'completed','answer':'A contract-test answer, not live AI.',
        'usage':{'total_tokens':15},'output_sha256':sha256(b'A contract-test answer, not live AI.').hexdigest(),
        'evidence_kind':'provider_response_observed_by_gateway','independent_delivery_receipt':False,'store_requested':False}

class PortalIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.app=AppState(Path(cls.temp.name))
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(cls.app))
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.base=f'http://127.0.0.1:{cls.server.server_port}'
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(timeout=3);cls.app.close();cls.temp.cleanup()
    def setUp(self):
        self.app.reset();self.analyst=self.app.new_session('analyst')[1];self.employee=self.app.new_session('lab-001')[1]
        self.app.portal.configure(self.analyst,{'api_key':TEST_KEY,'model':'gpt-4.1-mini'})
        with self.app.portal.db() as db:db.execute('DELETE FROM daily_calls')
    def chat(self,key,text='Explain public cybersecurity practices.'):
        return self.app.portal.chat(self.employee,{'request_id':key,'text':text})
    def test_restricted_content_blocks_before_provider_io(self):
        with patch.object(self.app.portal.provider,'generate') as provider:
            result=self.chat('portal-block-001','restricted runbook SEDRA_SECRET_A1B2C3D4E5F6G7H8')
        provider.assert_not_called();self.assertEqual(result['request']['state'],'BLOCKED')
        self.assertFalse(result['provider_contacted']);self.assertIsNone(result['ai']);self.assertEqual(self.app.receiver.list(),[])
    def test_allowed_result_and_idempotent_retry(self):
        with patch.object(self.app.portal.provider,'generate',side_effect=fake_answer) as provider:
            first=self.chat('portal-allow-001');retry=self.chat('portal-allow-001')
        self.assertEqual(provider.call_count,1);self.assertEqual(first['request']['state'],'FORWARDED_CONFIRMED')
        self.assertTrue(retry['request']['idempotent_replay']);self.assertEqual(first['ai'],retry['ai'])
        self.assertFalse(first['ai']['independent_delivery_receipt']);self.assertEqual(self.app.receiver.list(),[])
    def test_concurrent_same_id_has_one_external_send(self):
        entered=threading.Event();release=threading.Event()
        def hold(*args):entered.set();release.wait(4);return fake_answer(*args)
        with patch.object(self.app.portal.provider,'generate',side_effect=hold) as provider:
            with ThreadPoolExecutor(2) as pool:
                first=pool.submit(self.chat,'portal-race-001');self.assertTrue(entered.wait(3))
                retry=pool.submit(self.chat,'portal-race-001').result(3);release.set();first.result(3)
        self.assertEqual(provider.call_count,1);self.assertEqual(retry['request']['state'],'SENDING')
    def test_timeout_unknown_and_retry_never_resends(self):
        with patch.object(self.app.portal.provider,'generate',side_effect=ProviderError('Safe provider timeout')) as provider:
            first=self.chat('portal-timeout-001');retry=self.chat('portal-timeout-001')
        self.assertEqual(provider.call_count,1);self.assertEqual(first['request']['state'],'DELIVERY_UNKNOWN')
        self.assertEqual(retry['request']['state'],'DELIVERY_UNKNOWN')
        with patch.object(self.app,'local_http') as local:result=self.app.reconcile(self.employee,{'request_id':'portal-timeout-001'})
        local.open.assert_not_called();self.assertEqual(result['state'],'DELIVERY_UNKNOWN')
    def test_persisted_response_recovers_without_resending(self):
        with patch.object(self.app.portal.provider,'generate',side_effect=fake_answer):
            with patch.object(self.app.gateway,'confirm_forwarded',side_effect=RuntimeError('Simulated worker crash')):
                with self.assertRaises(RuntimeError):self.chat('portal-crash-001')
        with patch.object(self.app.portal.provider,'generate') as provider:retry=self.chat('portal-crash-001')
        provider.assert_not_called();self.assertEqual(retry['request']['state'],'FORWARDED_CONFIRMED')
    def test_key_never_returned_or_persisted(self):
        with patch.object(self.app.portal.provider,'generate',side_effect=fake_answer):result=self.chat('portal-key-store-001')
        self.assertNotIn(TEST_KEY,json.dumps(self.app.portal.status())+json.dumps(result)+json.dumps(self.app.events()))
        for file in Path(self.temp.name).glob('*.sqlite'):self.assertNotIn(TEST_KEY.encode(),file.read_bytes())
        self.app.portal.configure(self.analyst,{'clear':True});self.assertFalse(self.app.portal.status()['configured'])
    def test_http_configuration_authorization_csrf_and_chat(self):
        employee=LocalClient(self.base).login('lab-001');admin=LocalClient(self.base).login('analyst')
        self.assertEqual(employee.request('/api/portal/configure',{'api_key':TEST_KEY})[0],403)
        self.assertEqual(admin.request('/api/portal/configure',{'api_key':TEST_KEY},token=False)[0],403)
        code,result=admin.request('/api/portal/configure',{'api_key':TEST_KEY})
        self.assertEqual(code,200);self.assertNotIn(TEST_KEY,json.dumps(result))
        with patch.object(self.app.portal.provider,'generate',side_effect=fake_answer):
            code,result=employee.request('/api/portal/chat',{'request_id':'portal-http-001','text':'Public cyber awareness advice.'})
        self.assertEqual(code,200);self.assertEqual(result['request']['state'],'FORWARDED_CONFIRMED')
    def test_client_cannot_override_context_identity_model_or_destination(self):
        for name,value in [('subject_id','lab-002'),('behavior_score',0),('destination','https://example.com'),('model','other')]:
            with self.subTest(name=name),patch.object(self.app.portal.provider,'generate') as provider:
                with self.assertRaises(ValueError):self.app.portal.chat(self.employee,{'request_id':'portal-spoof-001','text':'Public',name:value})
                provider.assert_not_called()
        with self.assertRaises(PermissionError):self.app.portal.chat(self.analyst,{'request_id':'portal-admin-001','text':'Public'})
    def test_mutated_retry_and_other_identity_cannot_reconcile(self):
        with patch.object(self.app.portal.provider,'generate',side_effect=fake_answer) as provider:
            self.chat('portal-mutated-001')
            with self.assertRaises(ValueError):self.chat('portal-mutated-001','A changed public question.')
        self.assertEqual(provider.call_count,1)
        with self.assertRaises(ValueError):self.app.reconcile(self.app.new_session('lab-002')[1],{'request_id':'portal-mutated-001'})
    def test_daily_limit_survives_reset_and_has_no_provider_io(self):
        from datetime import datetime,timezone
        day=datetime.now(timezone.utc).date().isoformat()
        with self.app.portal.db() as db:db.execute('INSERT INTO daily_calls VALUES (?,20)',(day,))
        self.app.reset()
        with patch.object(self.app.portal.provider,'generate') as provider:result=self.chat('portal-budget-001')
        provider.assert_not_called();self.assertFalse(result['provider_contacted'])
        self.assertNotEqual(result['request']['state'],'FORWARDED_CONFIRMED')

class ProviderContractTests(unittest.TestCase):
    def test_fixed_https_original_input_bounded_output_and_store_false(self):
        class Response(io.BytesIO):headers={'x-request-id':'req_contract'}
        body={'id':'resp_contract','status':'completed','model':'gpt-4.1-mini','usage':{'total_tokens':5},
            'output':[{'type':'message','content':[{'type':'output_text','text':'<script>untrusted output</script>'}]}]}
        provider=OpenAIProvider()
        with patch.object(provider.http,'open',return_value=Response(json.dumps(body).encode())) as send:
            result=provider.generate(TEST_KEY,'gpt-4.1-mini','Original İŞIQ text.')
        request=send.call_args.args[0];payload=json.loads(request.data)
        self.assertEqual(request.full_url,'https://api.openai.com/v1/responses');self.assertEqual(payload['input'],'Original İŞIQ text.')
        self.assertIs(payload['store'],False);self.assertEqual(payload['max_output_tokens'],600)
        self.assertNotIn('tools',payload);self.assertNotIn('previous_response_id',payload)
        self.assertEqual(result['answer'],'<script>untrusted output</script>')
    def test_upstream_error_body_hidden_and_redirect_refused(self):
        provider=OpenAIProvider();failure=urllib.error.HTTPError(provider.endpoint,401,'Unauthorized',{},io.BytesIO(TEST_KEY.encode()))
        with patch.object(provider.http,'open',side_effect=failure):
            with self.assertRaises(ProviderError) as raised:provider.generate(TEST_KEY,'gpt-4.1-mini','Public')
        self.assertNotIn(TEST_KEY,str(raised.exception))
        with self.assertRaises(ProviderError):NoRedirect().redirect_request(None,None,302,'',{},'https://example.com')
    def test_malformed_or_empty_response_is_not_success(self):
        class Response(io.BytesIO):headers={}
        for body in [{'id':'missing','status':'completed'},{'id':'resp_empty','status':'completed','output':[]}]:
            provider=OpenAIProvider()
            with patch.object(provider.http,'open',return_value=Response(json.dumps(body).encode())):
                with self.assertRaises(ProviderError):provider.generate(TEST_KEY,'gpt-4.1-mini','Public')
