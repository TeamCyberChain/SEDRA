"""Authenticated fixed-loopback llama.cpp inference; no cloud fallback."""
import hashlib,json,urllib.request,urllib.error
from pathlib import Path
from .ai_portal import ProviderError,NoRedirect

LOCAL_ROOT=Path(__file__).resolve().parents[1]/'data/local_ai'

class LocalAIProvider:
    endpoint='http://127.0.0.1:8769/v1/chat/completions'
    model='sadd-qwen2.5-1.5b'

    def __init__(self):
        self.http=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())

    def token(self):
        try:return (LOCAL_ROOT/'access.key').read_text(encoding='utf-8').strip()
        except OSError:return ''

    def ready(self):
        key=self.token()
        if not key:return False
        try:
            request=urllib.request.Request('http://127.0.0.1:8769/health',headers={'Authorization':'Bearer '+key})
            with self.http.open(request,timeout=1) as response:
                return json.loads(response.read(4096)).get('status')=='ok'
        except (OSError,ValueError,urllib.error.URLError):return False

    def generate(self,key,model,text):
        # Credentials/host/model are managed locally, never supplied by a browser.
        key=self.token()
        if not key:raise ProviderError('Local AI runtime is not configured. Start Start-Local-AI.cmd; no cloud fallback was used.')
        body={'model':self.model,'messages':[
            {'role':'system','content':'You are a helpful assistant in a fictional security demonstration. '
             'Give a direct, accurate answer in at most three short sentences. Do not claim access to files or tools.'},
            {'role':'user','content':text}], 'stream':False,'max_tokens':240,'temperature':0.2,'seed':42,'cache_prompt':False}
        request=urllib.request.Request(self.endpoint,data=json.dumps(body,ensure_ascii=False).encode('utf-8'),
            headers={'Content-Type':'application/json','Authorization':'Bearer '+key},method='POST')
        try:
            with self.http.open(request,timeout=45) as response:raw=response.read(500_001)
            if len(raw)>500_000:raise ProviderError('Local AI response exceeded the configured limit.')
            data=json.loads(raw)
        except urllib.error.HTTPError as exc:
            code=exc.code;exc.close()
            raise ProviderError(f'Local AI returned HTTP {code}. No cloud fallback or automatic retry.') from None
        except (OSError,ValueError,urllib.error.URLError):
            raise ProviderError('Local AI response could not be confirmed. No cloud fallback or automatic retry.') from None
        try:
            choice=data['choices'][0];answer=choice['message']['content'];identifier=data['id']
            if not isinstance(answer,str) or not answer.strip() or len(answer.encode('utf-8'))>100_000 or not isinstance(identifier,str):raise ValueError()
            usage=data.get('usage',{})
            usage={target:usage[source] for source,target in [('prompt_tokens','input_tokens'),('completion_tokens','output_tokens'),('total_tokens','total_tokens')]
                   if type(usage.get(source)) is int}
        except (KeyError,IndexError,TypeError,ValueError,AttributeError):
            raise ProviderError('Local AI returned no valid bounded text answer.') from None
        return {'provider':'Local AI · Qwen / llama.cpp','response_id':identifier[:200],
                'provider_request_id':'','model':self.model,'status':'incomplete' if choice.get('finish_reason')=='length' else 'completed',
                'answer':answer,'usage':usage,'output_sha256':hashlib.sha256(answer.encode('utf-8')).hexdigest(),
                'evidence_kind':'local_model_response_observed_by_gateway','independent_delivery_receipt':False,
                'external_data_transfer':False,'runtime':'llama.cpp CPU','model_family':'Qwen2.5-1.5B-Instruct Q4_K_M'}
