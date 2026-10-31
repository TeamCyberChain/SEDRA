"""Download official pinned llama.cpp CPU runtime and Qwen weights, verify hashes.

No system installer, service registration, firewall change or cloud inference.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import hashlib,json,os,time,urllib.request,zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
DEST=ROOT/'data/local_ai'
TAG='b12020'
MODEL='qwen2.5-1.5b-instruct-q4_k_m.gguf'
REV='91cad51170dc346986eccefdc2dd33a9da36ead9'
MODEL_SHA='6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e'

def get(url):
    return urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'SEDRA-Hackathon-LocalAI'}),timeout=45)

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def download(entry):
    path=DEST/entry['file'];partial=path.with_suffix(path.suffix+'.part')
    if path.exists():
        if path.stat().st_size==entry['bytes'] and sha(path)==entry['sha256']:return
        raise ValueError('Existing local AI file fails its pinned hash; refusing overwrite')
    for attempt in range(5):
        offset=partial.stat().st_size if partial.exists() else 0
        if offset==entry['bytes']:break
        headers={'User-Agent':'SEDRA-Hackathon-LocalAI'}
        if offset:headers['Range']=f'bytes={offset}-'
        try:
            with urllib.request.urlopen(urllib.request.Request(entry['url'],headers=headers),timeout=45) as response:
                if offset and (response.status!=206 or not response.headers.get('Content-Range','').startswith(f'bytes {offset}-')):
                    raise ValueError('Resume response did not honor exact range')
                with partial.open('ab' if offset else 'wb') as out:
                    reported=offset//(32*1024*1024)
                    while chunk:=response.read(1024*1024):
                        out.write(chunk);offset+=len(chunk)
                        if offset>entry['bytes']:raise ValueError('Source size exceeded manifest')
                        if offset//(32*1024*1024)>reported:
                            reported=offset//(32*1024*1024)
                            print(json.dumps({'file':entry['file'],'downloaded':offset,'total':entry['bytes']}),flush=True)
            if offset==entry['bytes']:break
        except (OSError,urllib.error.URLError):
            if attempt==4:raise
            time.sleep(2)
    if partial.stat().st_size!=entry['bytes'] or sha(partial)!=entry['sha256']:
        raise ValueError('Downloaded local AI source failed exact byte count or SHA-256')
    partial.replace(path)
    print('Verified '+entry['file'],flush=True)

def main():
    DEST.mkdir(parents=True,exist_ok=True)
    with get(f'https://api.github.com/repos/ggml-org/llama.cpp/releases/tags/{TAG}') as response:
        release=json.load(response)
    asset=next(a for a in release['assets'] if a['name']==f'llama-{TAG}-bin-win-cpu-x64.zip')
    digest=asset.get('digest','')
    if not digest.startswith('sha256:'):raise ValueError('Official GitHub asset has no SHA-256 digest')
    entries=[{'file':asset['name'],'bytes':asset['size'],'sha256':digest.split(':',1)[1],
              'url':asset['browser_download_url'],'source':'official ggml-org/llama.cpp release'},
             {'file':MODEL,'bytes':1117320736,'sha256':MODEL_SHA,
              'url':f'https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/{REV}/{MODEL}',
              'source':'official Qwen GGUF repository; pinned commit and LFS digest'}]
    (DEST/'download_manifest.json').write_text(json.dumps({'runtime_tag':TAG,'model_revision':REV,'files':entries},indent=2))
    print(json.dumps(entries),flush=True)
    with ThreadPoolExecutor(2) as pool:list(pool.map(download,entries))
    runtime=DEST/'runtime';runtime.mkdir(exist_ok=True)
    old_path=ROOT/'artifacts/local_ai_source_manifest.json'
    old=json.loads(old_path.read_text()) if old_path.exists() else {}
    reusable=old.get('runtime_tag')==TAG and bool(old.get('runtime_files')) and all(
        (DEST/e['path']).is_file() and sha(DEST/e['path'])==e['sha256'] for e in old.get('runtime_files',[]))
    if not reusable:
        with zipfile.ZipFile(DEST/asset['name']) as archive:
            for entry in archive.infolist():
                target=(runtime/entry.filename).resolve()
                if not target.is_relative_to(runtime.resolve()):raise ValueError('Unsafe runtime archive member')
                archive.extract(entry,runtime)
    for name,url in [('llama-LICENSE.txt',f'https://raw.githubusercontent.com/ggml-org/llama.cpp/{TAG}/LICENSE'),
                     ('Qwen-LICENSE.txt','https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct/resolve/main/LICENSE')]:
        with get(url) as response:content=response.read(100000)
        (DEST/name).write_bytes(content)
    manifest={'verified_at_utc':datetime.now(timezone.utc).isoformat(),'runtime_tag':TAG,'model_revision':REV,
              'files':entries,'inference':'CPU-only local model; no cloud inference',
              'runtime_files':[{'path':str(p.relative_to(DEST)).replace('\\','/'),'sha256':sha(p),'bytes':p.stat().st_size}
                               for p in sorted(runtime.rglob('*')) if p.is_file()]}
    (ROOT/'artifacts/local_ai_source_manifest.json').write_text(json.dumps(manifest,indent=2))
    print('Local AI sources verified and extracted.',flush=True)

if __name__=='__main__':main()
