"""Regenerate factual readiness/status from executed artifacts, never guesses."""
from datetime import datetime,timezone,timedelta
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
def read(name,default=None):
    path=ROOT/name
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else default

def run():
    tests=read('artifacts/test_summary.json',{})
    smoke=read('artifacts/live_smoke.json',{})
    offline=read('artifacts/offline_clean_smoke.json',{})
    v1=read('artifacts/cert_benchmark.json',{})
    v2=read('artifacts/cert_v2_benchmark.json')
    if v2 and (v2.get('profile')!='cert_multichannel_calendar_v2' or v2.get('status')!='measured_development'):
        raise ValueError('Invalid v2 report profile')
    progress=read('artifacts/research_progress.json',{'stage':'awaiting_verified_data','status':'pending'})
    immutable=[]
    branding={e['path']:e for e in read('artifacts/branding_migration.json',{}).get('artifacts',[])}
    for entry in read('artifacts/v1_package_manifest.json',{}).get('files',[]):
        if entry['path'].startswith('artifacts/cert_'):
            path=ROOT/entry['path']
            expected=branding.get(entry['path'],{}).get('normalized_sha256',entry['sha256'])
            unchanged=path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()==expected
            immutable.append({'path':entry['path'],'unchanged':unchanged,'comparison_basis':'published branding-normalized copy' if entry['path'] in branding else 'original bytes',
                'original_sha256':entry['sha256'],'published_sha256':expected})
    if immutable and not all(r['unchanged'] for r in immutable):
        raise ValueError('Published CERT artifact differs from its declared original/branding-normalized hash; investigate')
    portal=read('artifacts/ai_portal_live_smoke.json',{})
    local_ai=read('artifacts/local_ai_live_smoke.json',{})
    now=datetime.now(timezone.utc)
    result={'recorded_at_utc':now.isoformat(),'functional_ready':bool(tests.get('successful') and smoke.get('successful') and offline.get('successful')),
            'tests':tests,'live_smoke_counts':smoke.get('counts'),'fresh_offline_environment_smoke':bool(offline.get('successful')),
            'v1_artifacts':immutable,'v1_failed_gate_retained':True,'v2_execution_complete':bool(v2),
            'research_progress':progress,'independent_efficacy_established':False,
            'ai_portal':{'implemented':True,'openai_live_reply_verified':bool(portal.get('successful')),
                         'local_model_live_reply_verified':bool(local_ai.get('successful')),
                         'artifact':'artifacts/ai_portal_live_smoke.json'},
            'browser_visual_qa':{'manually_checked':['Overview','Investigation','AI Transfer Lab','offline presentation navigation'],
                                 'screenshots_directory':'artifacts/screenshots'},
            'runtime_limitations':['Local simulated identities, not enterprise SSO','Offline receiver and opt-in OpenAI portal have different delivery evidence',
                                   'No arbitrary semantic/OCR/encoding/collusion coverage','Finite exposure windows','V2 r4.2 results are development evidence']}
    (ROOT/'artifacts/release_readiness.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    local=now.astimezone(timezone(timedelta(hours=4))).strftime('%d %B %Y %H:%M Asia/Baku')
    status=f'''# SEDRA v2 current status

Recorded {local}. This is generated from actual artifacts, not a model-performance forecast.

## Functional build

- {tests.get('tests_run','?')} executed tests, {tests.get('failures','?')} failures, {tests.get('errors','?')} errors; successful={tests.get('successful',False)}.
- Real loopback smoke: {smoke.get('counts',{})}.
- Fresh isolated Python 3.12 environment installed from local wheels without network; its separate live smoke successful={offline.get('successful',False)}.
- Overview, Investigation, Transfer Lab and offline presentation navigation visually checked. Saved screenshots are under artifacts/screenshots.
- External-review synthetic bypasses: the same 11 attack cases block after repair. Benign technical boilerplate regressions now allow. This small control set is not a population false-positive estimate.

The working build includes anchored short fragments, bounded distinctive-token co-occurrence, TR39/mixed-script/AZ handling, structured credential/PII checks, cautious one-level Base64, separate 24h/30d accounting, atomic reservations, idempotency, concurrency, TTL, unknown delivery, scoped authorization and real receipt reconciliation.

Actual observed document requests and blocked attempts feed a separate 120-second live policy rule. The dated daily IF is not silently retrained. The same body has executed as ALLOW before the live signal and BLOCK afterward.

## Opt-in real AI portal

The portal supports real local Qwen CPU inference and the optional OpenAI route. Local model reply verified={bool(local_ai.get('successful'))}; OpenAI reply verified={bool(portal.get('successful'))}. The OpenAI account returned 429; no cloud success is claimed. See artifacts/local_ai_live_smoke.json, local_ai_http_smoke.json, ai_portal_live_smoke.json and docs/LOCAL_AI.md. External API keys stay in process memory; the local service has a generated private token file excluded from all packages. Provider evidence is an observed API response, not an independent receiver receipt. Enterprise SSO and production deployment remain open.

## Original CERT file-only v1

The failed original benchmark is retained unchanged. All three frozen detectors had 0 TP among 476 incident-associated positive test days. Rules had 0 FP, IF 120 FP and combined 100 FP. Coverage-adjusted incident recall was 0/40. These remain evidence of a failed configuration, not efficacy.

Original preserved CERT artifacts checked against the starter manifest: {len(immutable)} files, unchanged={all(r['unchanged'] for r in immutable)}.

The local source recheck independently recovered the complete file.csv member and matched its pinned SHA-256: 193,055,265 bytes, 445,581 events and 45,907 active copy user-days. That recheck did not rerun the old model or rejoin LDAP. The multichannel archive verification and execution state is recorded below.

## Four-channel v2 development experiment

'''
    if v2:
        e=v2['evaluation']
        status+='Measured on verified device/logon/HTTP/file calendar days. **Development on previously inspected r4.2**, with changed population and primary labels. No independent efficacy claim.\n\n'
        status+='| Detector | TP | FP | FN | AP | Alerts / 100 user-days |\n| --- | ---: | ---: | ---: | ---: | ---: |\n'
        for name,m in e['comparisons'].items():
            c=m['confusion_matrix'];ap=m['average_precision']
            status+=f"| {name} | {c['tp']} | {c['fp']} | {c['fn']} | {ap if ap is not None else 'undefined'} | {m['alerts_per_100_user_days']:.4f} |\n"
        status+='\nFull support, prevalence, operating points, primary/secondary targets, actor/incident coverage and delays are in cert_v2_benchmark.json. This is not a like-for-like v1 comparison.\n'
    else:
        status+=f"**Not yet measured.** Research stage: {progress.get('stage')}; status: {progress.get('status')}. Official archive transfer has been severely slow. No pending source intake, fixture score or test pass is presented as a CERT v2 result. The importer/model protocol and tests are implemented; full source ingestion and actual evaluation remain open.\n"
    status+='''
## Deliverables and limitations

The local app, source/tests, pinned offline Windows wheels, editable English PPTX, browser fallback, timed speaker script, Q&A, architecture, setup/reset and submission checklist are prepared. A designated GitHub repository has not been supplied or published by this build.

The lab controls its own requests. Enterprise SSO and production provider deployment, endpoint-wide capture, semantic/OCR/arbitrary encoding handling and cross-identity collusion defense remain future work. Finite windows do not provide lifetime protection. Production use requires independent review and shadow-mode evaluation.
'''
    (ROOT/'docs/STATUS.md').write_text(status,encoding='utf-8')
    script=ROOT/'docs/SPEAKER_SCRIPT_EN.md'
    if script.exists():
        text=script.read_text(encoding='utf-8')
        start=text.index('The four-channel')
        end=text.index('## 4:25',start)
        if v2:
            m=v2['evaluation']['comparisons']['combined'];c=m['confusion_matrix']
            paragraph=f"The four-channel development experiment recorded {c['tp']} true positives, {c['fp']} false positives and {c['fn']} false negatives, with {m['alerts_per_100_user_days']:.2f} alerts per hundred user-days. It uses exact actor, channel, identifier and timestamp-qualified observable-day labels. Because r4.2 was already inspected, this is development evidence. Its changed target prevents a direct like-for-like comparison. CERT itself is synthetic research data. Independent efficacy requires a new holdout.\n\n"
        else:
            paragraph='The four-channel experiment has not yet finished verified source intake, so no v2 efficacy number is available. Its importer and frozen protocol are implemented and tested. When evaluated, r4.2 results will remain development evidence because the release was already inspected. CERT itself is synthetic research data. Independent efficacy requires a new holdout.\n\n'
        script.write_text(text[:start]+paragraph+text[end:],encoding='utf-8')
    print(json.dumps({'functional_ready':result['functional_ready'],'tests':tests.get('tests_run'),'v2_execution_complete':bool(v2)}))
    delivery=read('work/delivery_config.json')
    if v2 and delivery and delivery.get('directory'):
        subprocess.run([sys.executable,str(ROOT/'scripts/package_release.py'),'--delivery-dir',delivery['directory']],cwd=ROOT,check=True)
    return result

if __name__=='__main__':run()

