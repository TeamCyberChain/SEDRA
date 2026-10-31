"""Execute both the frozen previous detector and current detector on identical cases."""
from datetime import datetime,timezone
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from structured_cases import positive_cases,negative_cases
from sedra.content_security import structured_findings,STRUCTURED_PROFILE,iban_registry


def main():
    path=ROOT/'docs/history/content_security_pre_structured_v3.py'
    spec=importlib.util.spec_from_file_location('frozen_structured_v2',path)
    old=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    cases=[]
    for name,(expected,text) in positive_cases().items():
        before=old.structured_findings(text)
        after=structured_findings(text)
        cases.append({'name':name,'body_sha256':sha256(text.encode()).hexdigest(),'expected_type':expected,
            'before_types':sorted({f['type'] for f in before}),'after_types':sorted({f['type'] for f in after}),
            'passed':expected in {f['type'] for f in after}})
    controls=[]
    for name,text in negative_cases().items():
        controls.append({'name':name,'body_sha256':sha256(text.encode()).hexdigest(),
            'before_types':sorted({f['type'] for f in old.structured_findings(text)}),
            'after_types':sorted({f['type'] for f in structured_findings(text)})})
    report={'executed_at_utc':datetime.now(timezone.utc).isoformat(),'profile':STRUCTURED_PROFILE,
        'previous_source_sha256':sha256(path.read_bytes()).hexdigest(),
        'positive_cases':len(cases),'before_expected_type_detected':sum(c['expected_type'] in c['before_types'] for c in cases),
        'after_expected_type_detected':sum(c['passed'] for c in cases),'negative_controls':len(controls),
        'before_control_flags':sum(bool(c['before_types']) for c in controls),
        'after_control_flags':sum(bool(c['after_types']) for c in controls),
        'cases':cases,'controls':controls,'iban_country_formats':len(iban_registry()['countries']),
        'scope':'Synthetic adversarial regression set; not an estimate of population precision/recall or account/identity validity.'}
    report['successful']=all(c['passed'] for c in cases) and not report['after_control_flags']
    (ROOT/'artifacts/structured_regression_v3.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('cases','controls')},indent=2))
    if not report['successful']:raise SystemExit(1)


if __name__=='__main__':main()
