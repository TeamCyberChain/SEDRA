"""Local adapter and route contracts; generated fixtures are explicitly doubles."""
import io,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from sadd.app import AppState
from sadd.local_ai import LocalAIProvider
from sadd.ai_portal import ProviderError
from sadd.corpus import catalog
from test_ai_portal import fake_answer,TEST_KEY

def local_answer(key,model,text):
    result=fake_answer(key,model,text)
    result.update(provider='Local AI · test double',external_data_transfer=False,
                  evidence_kind='local_model_response_observed_by_gateway')
    return result

class LocalPortalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.app=AppState(Path(cls.temp.name))
    @classmethod
    def tearDownClass(cls):cls.app.close();cls.temp.cleanup()
    def setUp(self):
        self.app.reset();self.admin=self.app.new_session('analyst')[1];self.employee=self.app.new_session('lab-001')[1]
        with self.app.portal.db() as db:db.execute('DELETE FROM daily_calls')
        with patch.object(self.app.portal.local_provider,'ready',return_value=True):
            self.app.portal.configure(self.admin,{'provider':'local'})
        self.app.portal.key=''
    def send(self,key,text):return self.app.portal.chat(self.employee,{'request_id':key,'text':text})
    def test_local_inference_needs_no_cloud_key_and_never_calls_cloud(self):
        with patch.object(self.app.portal.local_provider,'generate',side_effect=local_answer) as local,patch.object(self.app.portal.provider,'generate') as cloud:
            result=self.send('local-answer-001','What is 17 plus 25?')
            retry=self.send('local-answer-001','What is 17 plus 25?')
        local.assert_called_once();cloud.assert_not_called()
        self.assertEqual(result['request']['destination'],'local_ai')
        self.assertEqual(result['request']['state'],'FORWARDED_CONFIRMED')
        self.assertFalse(result['ai']['external_data_transfer']);self.assertEqual(result['ai'],retry['ai'])
    def test_local_restricted_block_contacts_neither_model(self):
        with patch.object(self.app.portal.local_provider,'generate') as local,patch.object(self.app.portal.provider,'generate') as cloud:
            result=self.send('local-block-001','restricted runbook SADD_SECRET_A1B2C3D4E5F6G7H8')
        local.assert_not_called();cloud.assert_not_called();self.assertFalse(result['provider_contacted'])
        self.assertEqual(result['request']['state'],'BLOCKED')
    def test_cloud_and_local_routes_share_cumulative_exposure(self):
        fragments=next(d for d in catalog() if d['id']=='araz-plan')['fragments']
        self.app.portal.configure(self.admin,{'provider':'openai','api_key':TEST_KEY})
        with patch.object(self.app.portal.provider,'generate',side_effect=fake_answer):
            first=self.send('shared-budget-001',fragments[0]['text'])
        with patch.object(self.app.portal.local_provider,'ready',return_value=True):self.app.portal.configure(self.admin,{'provider':'local'})
        with patch.object(self.app.portal.local_provider,'generate',side_effect=local_answer) as local:
            second=self.send('shared-budget-002',fragments[1]['text'])
            third=self.send('shared-budget-003',fragments[2]['text'])
        self.assertEqual(first['request']['decision'],'ALLOW');self.assertEqual(second['request']['decision'],'ALLOW')
        self.assertEqual(third['request']['decision'],'BLOCK');self.assertEqual(local.call_count,1)
    def test_existing_request_cannot_move_between_providers(self):
        with patch.object(self.app.portal.local_provider,'generate',side_effect=local_answer):self.send('fixed-route-001','Public example question.')
        self.app.portal.configure(self.admin,{'api_key':TEST_KEY})
        with patch.object(self.app.portal.provider,'generate') as cloud:
            with self.assertRaises(ValueError):self.send('fixed-route-001','Public example question.')
        cloud.assert_not_called()
    def test_local_timeout_no_cloud_fallback(self):
        with patch.object(self.app.portal.local_provider,'generate',side_effect=ProviderError('Local timeout')) as local,patch.object(self.app.portal.provider,'generate') as cloud:
            result=self.send('local-timeout-001','Public example question.')
            retry=self.send('local-timeout-001','Public example question.')
        self.assertEqual(local.call_count,1);cloud.assert_not_called()
        self.assertEqual(result['request']['state'],'DELIVERY_UNKNOWN');self.assertEqual(retry['request']['state'],'DELIVERY_UNKNOWN')
    def test_local_ai_is_independent_of_exhausted_cloud_budget(self):
        from datetime import datetime,timezone
        with self.app.portal.db() as db:
            db.execute('INSERT INTO daily_calls VALUES (?,20)',(datetime.now(timezone.utc).date().isoformat(),))
        with patch.object(self.app.portal.local_provider,'generate',side_effect=local_answer):
            result=self.send('local-no-cloud-quota-001','Public demonstration question.')
        self.assertEqual(result['request']['state'],'FORWARDED_CONFIRMED')

class LocalAdapterTests(unittest.TestCase):
    def test_fixed_authenticated_loopback_original_message_and_usage(self):
        class Response(io.BytesIO):pass
        body={'id':'chatcmpl_contract','choices':[{'message':{'content':'42'},'finish_reason':'stop'}],
              'usage':{'prompt_tokens':10,'completion_tokens':2,'total_tokens':12}}
        provider=LocalAIProvider()
        with patch.object(provider,'token',return_value='local-contract-token'),patch.object(provider.http,'open',return_value=Response(json.dumps(body).encode())) as send:
            result=provider.generate('ignored-browser-key','ignored-client-model','What is 17 plus 25?')
        request=send.call_args.args[0];payload=json.loads(request.data)
        self.assertEqual(request.full_url,'http://127.0.0.1:8769/v1/chat/completions')
        self.assertEqual(request.get_header('Authorization'),'Bearer local-contract-token')
        self.assertEqual(payload['messages'][-1]['content'],'What is 17 plus 25?')
        self.assertEqual(payload['model'],'sadd-qwen2.5-1.5b');self.assertFalse(payload['stream'])
        self.assertFalse(result['external_data_transfer']);self.assertEqual(result['usage']['total_tokens'],12)
    def test_missing_token_refuses_inference(self):
        provider=LocalAIProvider()
        with patch.object(provider,'token',return_value=''),patch.object(provider.http,'open') as send:
            self.assertFalse(provider.ready())
            with self.assertRaises(ProviderError):provider.generate('','','Public')
        send.assert_not_called()
