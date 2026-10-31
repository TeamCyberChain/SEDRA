"""Portable verified model supplement. Never includes its generated access token."""
from pathlib import Path
import argparse,hashlib,json,shutil,zipfile
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1]
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def build(delivery):
    source=ROOT/'artifacts/local_ai_source_manifest.json';manifest=json.loads(source.read_text())
    data=ROOT/'data/local_ai'
    entries=manifest['runtime_files']
    files=[source,ROOT/'docs/LOCAL_AI.md']
    for entry in entries:
        path=data/entry['path']
        if not path.resolve().is_relative_to(data.resolve()) or sha(path)!=entry['sha256']:raise ValueError('Runtime hash mismatch')
        files.append(path)
    model=next(e for e in manifest['files'] if e['file'].endswith('.gguf'))
    path=data/model['file']
    if sha(path)!=model['sha256']:raise ValueError('Model hash mismatch')
    files.extend([path,data/'llama-LICENSE.txt',data/'Qwen-LICENSE.txt'])
    output=ROOT/'dist/SEDRA-Local-AI-Model.zip';temporary=output.with_suffix('.zip.tmp')
    with zipfile.ZipFile(temporary,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for file in files:
            archive.write(file,'sedra/'+str(file.relative_to(ROOT)).replace('\\','/'),
                          compress_type=zipfile.ZIP_STORED if file.suffix=='.gguf' else zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(temporary) as check:
        if check.testzip():raise ValueError('Supplement ZIP failed integrity check')
        if any(n.endswith(('.key','.sqlite','server.json')) for n in check.namelist()):raise ValueError('Runtime secret/cache in supplement')
    temporary.replace(output)
    report={'created_at_utc':datetime.now(timezone.utc).isoformat(),'file':output.name,'bytes':output.stat().st_size,
            'sha256':sha(output),'model_sha256':model['sha256'],'zip_crc':'passed',
            'excluded':'Generated local API token, server state, API key, prompts, answer caches and raw research data',
            'install':'Extract beside/over the base SEDRA package, then run Start-SEDRA.cmd'}
    (ROOT/'dist/local_ai_package_checksums.json').write_text(json.dumps(report,indent=2))
    if delivery:
        folder=Path(delivery);folder.mkdir(parents=True,exist_ok=True)
        shutil.copy2(output,folder/output.name)
        shutil.copy2(ROOT/'dist/local_ai_package_checksums.json',folder/'local_ai_package_checksums.json')
    print(json.dumps(report))
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--delivery-dir');build(parser.parse_args().delivery_dir)
