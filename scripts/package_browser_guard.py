"""Package only reviewed extension source and instructions, never runtime data."""
import argparse
import base64
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

ROOT=Path(__file__).resolve().parents[1]
FILES={'manifest.json','core.js','worker.js','guard.js','options.html','options.css','options.js'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=ROOT/'dist'/'browser-guard');args=parser.parse_args()
    source=ROOT/'browser-extension';manifest=json.loads((source/'manifest.json').read_text())
    if {p.name for p in source.iterdir() if p.is_file()}!=FILES:raise SystemExit('Unexpected extension source boundary')
    fingerprint=hashlib.sha256(base64.b64decode(manifest['key'],validate=True)).hexdigest()[:32]
    identifier=''.join(chr(97+int(c,16)) for c in fingerprint)
    output=args.output.resolve();bundle=output/'browser-extension';bundle.mkdir(parents=True,exist_ok=True)
    entries=[]
    for name in sorted(FILES):
        raw=(source/name).read_bytes();(bundle/name).write_bytes(raw);entries.append({'file':name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
    shutil.copyfile(ROOT/'docs/BROWSER_GUARD.md',output/'README.md')
    archive=output/f"SEDRA-Browser-Guard-{manifest['version']}.zip"
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for name in sorted(FILES):
            info=zipfile.ZipInfo(name,(2026,10,31,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,(source/name).read_bytes())
        info=zipfile.ZipInfo('README.md',(2026,10,31,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,(ROOT/'docs/BROWSER_GUARD.md').read_bytes())
    report={'packaged_at_utc':datetime.now(timezone.utc).isoformat(),'version':manifest['version'],'extension_id':identifier,'files':entries,
        'zip_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'scope':'Extension source and setup instructions only; no credentials, runtime, model or Windows telemetry'}
    (output/'package-manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8',newline='\n')
    print(json.dumps({'version':manifest['version'],'extension_id':identifier,'file_count':len(entries),'output':str(output)}))


if __name__=='__main__':main()
