"""Create separate SEDRA archives without overwriting historical SADD packages."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
import zipfile

from package_release import ROOT, selected_files
sys.path.insert(0,str(ROOT))
from sadd import __version__
VERSION=__version__
SHORT_VERSION=".".join(VERSION.split(".")[:2])


def build(delivery):
    delivery = Path(delivery)
    delivery.mkdir(parents=True, exist_ok=True)
    files = sorted(set(selected_files() + [ROOT/'Start-SEDRA.cmd', ROOT/'Setup-SEDRA.cmd']))
    manifest = {'product':'SEDRA', 'version':VERSION, 'created_at_utc':datetime.now(timezone.utc).isoformat(),
        'presentation_status':'Previous-build materials retained; presentation and QA updates deferred',
        'excluded':'Runtime databases, private keys, raw CERT data, local model/runtime, virtual environments and scratch files',
        'files':[{'path':p.relative_to(ROOT).as_posix(), 'bytes':p.stat().st_size,
                  'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]}
    manifest_path = ROOT/'SEDRA_MANIFEST.json'
    manifest_path.write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    report = {'product':'SEDRA','version':VERSION,'archives':[]}
    for name, offline in [(f'SEDRA-{SHORT_VERSION}-Source.zip',False),(f'SEDRA-{SHORT_VERSION}-Offline-Windows.zip',True)]:
        target=delivery/name
        temporary=target.with_suffix('.zip.tmp')
        with zipfile.ZipFile(temporary,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as bundle:
            for path in files+[manifest_path]:
                bundle.write(path,'sadd/'+path.relative_to(ROOT).as_posix())
            if offline:
                wheels=sorted((ROOT/'offline_wheels').glob('*.whl'))
                if len(wheels)!=5:
                    raise ValueError('Expected five pinned offline wheels')
                for wheel in wheels:
                    bundle.write(wheel,'sadd/offline_wheels/'+wheel.name,compress_type=zipfile.ZIP_STORED)
        with zipfile.ZipFile(temporary) as check:
            assert check.testzip() is None
            for entry in manifest['files']:
                assert hashlib.sha256(check.read('sadd/'+entry['path'])).hexdigest()==entry['sha256']
            assert not any('/data/' in n or '/work/' in n or '/.venv/' in n or n.endswith(('.key','.sqlite','.sqlite-wal','.sqlite-shm')) for n in check.namelist())
            assert 'sadd/static/sedra.css' in check.namelist()
            assert 'sadd/sadd/labels.py' in check.namelist()
            assert 'sadd/sadd/alerts.py' in check.namelist()
            assert 'sadd/static/alerts.js' in check.namelist()
            assert 'sadd/sadd/ueba.py' in check.namelist()
            assert 'sadd/static/ueba.js' in check.namelist()
            assert 'sadd/sadd/endpoint.py' in check.namelist()
            assert 'sadd/static/endpoint.js' in check.namelist()
            assert 'sadd/sadd/behavior_cases.py' in check.namelist()
            assert 'sadd/sadd/policy_explain.py' in check.namelist()
            assert 'sadd/static/cases.js' in check.namelist()
            assert 'sadd/docs/BEHAVIOR_CASES.md' in check.namelist()
            assert 'sadd/scripts/collect_local_endpoint.ps1' in check.namelist()
            assert not any(n.endswith('endpoint_main_live_v1.json') for n in check.namelist())
            assert 'sadd/Start-SEDRA.cmd' in check.namelist()
        temporary.replace(target)
        report['archives'].append({'file':name,'bytes':target.stat().st_size,
            'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'zip_crc_and_manifest':'PASS'})
    (delivery/'checksums.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    shutil.copy2(ROOT/'docs/SEDRA_GOVERNANCE.md',delivery/'SEDRA-Governance-Guide.md')
    shutil.copy2(ROOT/'docs/STRUCTURED_DATA_CONTROLS.md',delivery/'Structured-Data-Controls.md')
    shutil.copy2(ROOT/'docs/ALERTS.md',delivery/'SEDRA-Alerts-Guide.md')
    shutil.copy2(ROOT/'docs/UEBA.md',delivery/'SEDRA-UEBA-Guide.md')
    shutil.copy2(ROOT/'docs/LOCAL_ENDPOINT.md',delivery/'Local-Endpoint-Guide.md')
    shutil.copy2(ROOT/'docs/BEHAVIOR_CASES.md',delivery/'Behavior-Casework-Guide.md')
    shutil.copy2(ROOT/'artifacts/behavior_cases_http_smoke_v1.json',delivery/'behavior-cases-http-smoke.json')
    shutil.copy2(ROOT/'artifacts/behavior_cases_main_summary_v1.json',delivery/'behavior-cases-main-summary.json')
    shutil.copy2(ROOT/'artifacts/release_readiness.json',delivery/'release-readiness.json')
    shutil.copy2(ROOT/'docs/STATUS.md',delivery/'SEDRA-Readiness.md')
    shutil.copy2(ROOT/'artifacts/endpoint_http_smoke_v1.json',delivery/'endpoint-http-smoke.json')
    shutil.copy2(ROOT/'artifacts/endpoint_main_summary_v1.json',delivery/'endpoint-main-summary.json')
    shutil.copy2(ROOT/'artifacts/ueba_http_smoke_v2.json',delivery/'ueba-http-smoke.json')
    shutil.copy2(ROOT/'artifacts/ueba_main_live_v2.json',delivery/'ueba-main-live.json')
    shutil.copy2(ROOT/'artifacts/alerts_http_smoke_v1.json',delivery/'alerts-http-smoke.json')
    shutil.copy2(ROOT/'artifacts/alerts_main_live_v1.json',delivery/'alerts-main-live.json')
    shutil.copy2(ROOT/'artifacts/structured_regression_v3.json',delivery/'structured-regression.json')
    shutil.copy2(ROOT/'artifacts/structured_http_smoke_v3.json',delivery/'structured-http-smoke.json')
    shutil.copy2(ROOT/'artifacts/test_summary.json',delivery/'test-summary.json')
    shutil.copy2(ROOT/'artifacts/sedra_live_smoke.json',delivery/'live-smoke.json')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--delivery-dir',required=True)
    build(parser.parse_args().delivery_dir)
