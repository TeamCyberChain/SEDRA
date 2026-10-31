"""Start the verified, authenticated CPU model on loopback without a console."""
from datetime import datetime,timezone
import hashlib,json,os,secrets,subprocess,sys,time,urllib.request,urllib.error
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/'data/local_ai'
MODEL=DATA/'qwen2.5-1.5b-instruct-q4_k_m.gguf'

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def ready(token):
    try:
        http=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        request=urllib.request.Request('http://127.0.0.1:8769/health',headers={'Authorization':'Bearer '+token})
        with http.open(request,timeout=1) as response:return json.load(response).get('status')=='ok'
    except (OSError,ValueError,urllib.error.URLError):return False

def main():
    source=ROOT/'artifacts/local_ai_source_manifest.json'
    if not source.exists():raise SystemExit('Run Setup-Local-AI.cmd first; verified runtime/model not installed.')
    manifest=json.loads(source.read_text())
    entry=next(e for e in manifest['files'] if e['file']==MODEL.name)
    if not MODEL.exists() or MODEL.stat().st_size!=entry['bytes'] or sha(MODEL)!=entry['sha256']:
        raise SystemExit('Local model hash/size mismatch. Refusing to start.')
    for entry in manifest['runtime_files']:
        file=DATA/entry['path']
        if not file.resolve().is_relative_to(DATA.resolve()) or not file.is_file() or sha(file)!=entry['sha256']:
            raise SystemExit('Local runtime integrity mismatch. Refusing to start.')
    token_file=DATA/'access.key'
    if not token_file.exists():
        with token_file.open('x',encoding='utf-8') as stream:stream.write(secrets.token_urlsafe(40))
    token=token_file.read_text(encoding='utf-8').strip()
    if ready(token):print('Local Qwen model is already ready on loopback port 8769.');return
    binary=DATA/'runtime/llama-server.exe'
    (ROOT/'work').mkdir(exist_ok=True)
    args=[str(binary),'-m',str(MODEL),'--alias','sedra-qwen2.5-1.5b','--api-key-file',str(token_file),
          '--host','127.0.0.1','--port','8769','--parallel','1','--ctx-size','4096','--threads','8',
          '--threads-batch','8','--gpu-layers','0','--no-webui','--no-ui-mcp-proxy','--no-slots','--log-disable']
    with (ROOT/'work/local-ai-server.log').open('ab') as out,(ROOT/'work/local-ai-server-error.log').open('ab') as err:
        process=subprocess.Popen(args,cwd=binary.parent,stdout=out,stderr=err,
             creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    (DATA/'server.json').write_text(json.dumps({'pid':process.pid,'port':8769,'host':'127.0.0.1',
        'started_at_utc':datetime.now(timezone.utc).isoformat(),'model_sha256':manifest['files'][1]['sha256']},indent=2))
    for _ in range(50):
        if ready(token):print('Local Qwen model is ready. No API credits or cloud inference are used.');return
        if process.poll() is not None:raise SystemExit('Local model server stopped. Inspect work/local-ai-server-error.log.')
        time.sleep(.5)
    raise SystemExit('Model is still loading. Run Start-Local-AI.cmd again to check readiness.')

if __name__=='__main__':main()
