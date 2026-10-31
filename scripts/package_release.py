"""Package the local demo and factual evidence, excluding runtime/private files."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import zipfile

ROOT=Path(__file__).resolve().parents[1]

def selected_files():
    roots=['sadd','static','scripts','tests','docs','artifacts','presentation']
    files=[]
    for name in roots:
        for path in (ROOT/name).rglob('*'):
            if not path.is_file():continue
            relative=path.relative_to(ROOT)
            if ('__pycache__' in relative.parts or path.suffix in ('.pyc','.sqlite','.tmp','.key')
                    or path.name.startswith('.env') or path.name.endswith(('.sqlite-wal','.sqlite-shm'))
                    or 'versions' in relative.parts):
                continue
            if re.match(r'SADD_Final_EN_v\d+\.pptx$',path.name):continue
            if path.name=='python_version_guard.txt':continue
            files.append(path)
    for name in ['README.md','AI_ASSISTANCE.md','THIRD_PARTY_NOTICES.md','requirements.txt','pyproject.toml','package.json',
                 '.gitignore','Start-SADD.cmd','Setup-SADD.cmd','Resume-CERT-Research.cmd','Setup-Local-AI.cmd','Start-Local-AI.cmd']:
        files.append(ROOT/name)
    return sorted(set(files))

def build(delivery=None):
    files=selected_files()
    manifest={'created_at_utc':datetime.now(timezone.utc).isoformat(),
        'excluded':'Raw CERT data, .venv, runtime databases, scratch files, alternate presentation revisions; optional wheels separate',
        'files':[{'path':str(p.relative_to(ROOT)).replace('\\','/'),'bytes':p.stat().st_size,
                  'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]}
    (ROOT/'PACKAGE_MANIFEST.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    files.append(ROOT/'PACKAGE_MANIFEST.json')
    destination=ROOT/'dist';destination.mkdir(exist_ok=True)
    outputs=[]
    for filename,offline in [('SADD-Hackathon-Source.zip',False),('SADD-Offline-Windows.zip',True)]:
        target=destination/filename;temporary=target.with_suffix('.zip.tmp')
        with zipfile.ZipFile(temporary,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as bundle:
            for path in files:
                bundle.write(path,'sadd/'+str(path.relative_to(ROOT)).replace('\\','/'))
            if offline:
                wheels=sorted((ROOT/'offline_wheels').glob('*.whl'))
                if len(wheels)!=5:raise ValueError('Five pinned offline wheels required for the Windows package')
                for wheel in wheels:
                    bundle.write(wheel,'sadd/offline_wheels/'+wheel.name,compress_type=zipfile.ZIP_STORED)
        with zipfile.ZipFile(temporary) as check:
            if check.testzip() is not None:raise ValueError('Package ZIP integrity check failed')
            if any('/data/' in name or '/.venv/' in name or '/work/' in name for name in check.namelist()):
                raise ValueError('Private runtime data must not be packaged')
        temporary.replace(target)
        outputs.append(target)
    if delivery:
        delivery=Path(delivery);delivery.mkdir(parents=True,exist_ok=True)
        for path in outputs:
            shutil.copy2(path,delivery/path.name)
        for name,target in [('presentation/SADD_Final_EN.pptx','SADD_Final_EN.pptx'),
                            ('docs/STATUS.md','SADD-Readiness.md'),
                            ('docs/SPEAKER_SCRIPT_EN.md','Speaker-Script-EN.md'),
                            ('docs/QA_EN.md','QA-EN.md'),
                            ('docs/AI_PORTAL.md','AI-Portal-Guide.md'),
                            ('docs/LOCAL_AI.md','Local-AI-Guide.md'),
                            ('artifacts/screenshots/overview.png','SADD-Overview.png')]:
            source=ROOT/name
            if source.exists():shutil.copy2(source,delivery/target)
        # Offline presentation needs its local CSS and JS beside the HTML file.
        offline_dir=delivery/'Offline-Presentation';offline_dir.mkdir(exist_ok=True)
        for name in ('index.html','presentation.css','presentation.js'):
            shutil.copy2(ROOT/'presentation'/name,offline_dir/name)
    report={'created_at_utc':datetime.now(timezone.utc).isoformat(),
            'archives':[{'file':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in outputs]}
    (destination/'package_checksums.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    if delivery:shutil.copy2(destination/'package_checksums.json',Path(delivery)/'package_checksums.json')
    print(json.dumps(report,indent=2))
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--delivery-dir',type=Path)
    args=parser.parse_args();build(args.delivery_dir)
