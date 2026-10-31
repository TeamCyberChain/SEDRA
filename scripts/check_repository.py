"""Check tracked review files, private-data boundary and selected credential patterns."""
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]

def main():
    names=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode('utf-8').split('\0')
    names=[n for n in names if n]
    problems=[]
    required=['README.md','AI_ASSISTANCE.md','THIRD_PARTY_NOTICES.md','SECURITY.md',
        'requirements.txt','docs/TECHNICAL_REPORT.md','docs/REQUIREMENTS_TRACEABILITY.md',
        'docs/REVIEWER_GUIDE.md','.github/workflows/verify.yml','sedra/behavior_cases.py']
    for name in required:
        if name not in names:problems.append({'path':name,'reason':'required review file missing'})
    patterns=[('SEDRA machine key',re.compile(r'sedra_k_[0-9a-f]{16}\.[A-Za-z0-9_-]{40,}')),('OpenAI key',re.compile(r'\bsk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{32,}')),
        ('GitHub token',re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})'))]
    for name in names:
        p=Path(name)
        legacy='sa'+'dd'
        if legacy in name.lower():problems.append({'path':name,'reason':'legacy project name in published path'})
        if p.parts[0]=='presentation' or p.suffix.lower() in ('.pptx','.zip'):
            problems.append({'path':name,'reason':'presentation or superseded archive must stay local'})
        if p.parts[0] in ('data','work','dist','.venv','offline_wheels') or p.name.startswith('.env') or p.suffix in ('.key','.sqlite','.pyc') or p.name.endswith(('.sqlite-wal','.sqlite-shm')):
            problems.append({'path':name,'reason':'private/runtime/build file tracked'})
        source=ROOT/name
        if source.stat().st_size>50*1024*1024:problems.append({'path':name,'reason':'oversized source file'})
        try:text=source.read_text(encoding='utf-8')
        except UnicodeError:continue
        if legacy in text.lower() or ('S'+chr(399)+'DD') in text:problems.append({'path':name,'reason':'legacy project name in published text'})
        for label,regex in patterns:
            if regex.search(text.replace('sk-proj-UNITTEST-NOT-A-REAL-KEY-1234567890','UNIT_TEST_PLACEHOLDER')):problems.append({'path':name,'reason':label+' pattern; value deliberately omitted'})
    report={'tracked_files':len(names),'successful':not problems,'problems':problems,
        'scope':'Tracked boundary and selected token patterns only; not complete secret detection'}
    print(json.dumps(report,indent=2))
    return 0 if not problems else 1

if __name__=='__main__':sys.exit(main())
