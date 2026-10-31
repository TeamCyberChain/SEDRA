"""Resume official CERT intake, verify, extract and execute the frozen v2 run.

This optional long-running job changes only the local hackathon research files.
It never changes system security/network settings and never visits dataset URLs.
"""
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]

def progress(stage,status='running',detail=None):
    value={'stage':stage,'status':status,'updated_at_utc':datetime.now(timezone.utc).isoformat(),
           'detail':detail,'scope':'official public CERT acquisition and local development evaluation'}
    path=ROOT/'artifacts/research_progress.json';temporary=path.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(value,indent=2),encoding='utf-8');temporary.replace(path)
    print(json.dumps(value),flush=True)

def execute(script,*args):
    subprocess.run([sys.executable,'-u',str(ROOT/'scripts'/script),*args],cwd=ROOT,check=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parallel',action='store_true',help='Use validated range chunks instead of sequential resume')
    parser.add_argument('--workers',default=8,type=int)
    parser.add_argument('--chunk-mib',default=8,type=int)
    args=parser.parse_args()
    root=ROOT/'data/cert';root.mkdir(parents=True,exist_ok=True)
    lock=root/'research.lock'
    try:
        with lock.open('x') as stream:stream.write(str(os.getpid()))
    except FileExistsError:
        parser.error('Research lock exists. Verify the previous runner has stopped before removing its local lock.')
    stage='downloading_official_archive'
    try:
        progress(stage)
        if args.parallel:
            execute('download_cert_parallel.py','--workers',str(args.workers),'--chunk-mib',str(args.chunk_mib))
        execute('download_cert.py','--destination','data/cert')
        stage='extracting_verified_channels';progress(stage)
        manifest=root/'multichannel/extraction_manifest.json'
        if not manifest.exists():
            execute('extract_multichannel.py','data/cert')
        stage='ingesting_and_evaluating_development';progress(stage)
        execute('cert_multichannel.py')
        stage='complete';progress(stage,'complete','Measured development report saved. This is not independent efficacy.')
        execute('release_report.py')
    except BaseException as exc:
        progress(stage,'interrupted' if isinstance(exc,KeyboardInterrupt) else 'failed',str(exc))
        try:execute('release_report.py')
        except Exception:pass
        raise
    finally:
        lock.unlink(missing_ok=True)

if __name__=='__main__':main()
