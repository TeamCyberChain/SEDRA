"""Explainable app-only streaming UEBA. No inference of employee intent.

Live rules and observed application baselines are independent of the dated
completed-day Isolation Forest. Labels, prompt bodies and provider output are
never inputs. Thresholds are declared laboratory engineering parameters.
"""
from collections import defaultdict
from datetime import datetime, timezone
import math
from statistics import median

PROFILE='sedra-app-ueba-v2'
SHORT=120
LONG=1800
DAY=86400
HISTORY_DAYS=28
MAX_MODEL_AGE=72*3600
INPUT_LIMIT=20000


def epoch(value):
    try:
        if isinstance(value,(int,float)) and not isinstance(value,bool):result=float(value)
        else:
            parsed=datetime.fromisoformat(value)
            if parsed.tzinfo is None:return None
            result=parsed.timestamp()
        return result if math.isfinite(result) else None
    except (ValueError,TypeError,OverflowError):return None


def active_baseline(events,cutoff,now):
    """Earlier complete fixed 30m active bins only; absent coverage is not zero."""
    bins=defaultdict(int)
    for e in events:
        at=e['at'];slot=int(at//LONG)
        if now-HISTORY_DAYS*DAY<=at and (slot+1)*LONG<=cutoff:bins[slot]+=1
    days=len({int(slot*LONG//DAY) for slot in bins})
    sufficient=len(bins)>=14 and days>=7
    values=list(bins.values())
    center=median(values) if values else None
    scale=max(1.,math.sqrt(center),1.4826*median(abs(x-center) for x in values)) if values else None
    return {'status':'sufficient' if sufficient else 'insufficient_history','active_bins':len(values),
        'observed_days':days,'minimum_bins':14,'minimum_days':7,'median':center if sufficient else None,
        'robust_scale':scale if sufficient else None,'window_seconds':LONG,'lookback_days':HISTORY_DAYS,
        'reference_ends_before':cutoff,'inactive_slots_imputed':False,
        'scope':'Observed app actions in earlier complete active 30-minute bins; not an endpoint workday baseline'}


def assess(subject,reads,requests,history,now,*,truncated=False):
    if not math.isfinite(now):raise ValueError('UEBA clock must be finite')
    uid=subject['subject_id'];events=[]
    for row in reads:
        at=epoch(row.get('timestamp'))
        if row.get('subject_id')!=uid or at is None or not now-HISTORY_DAYS*DAY<=at<=now:continue
        d=row.get('detail',{})
        if row.get('kind')!='document_read':continue
        events.append({'id':'audit:'+str(row['id']),'at':at,'channel':'document','kind':'document_read',
            'origin':d.get('source','OBSERVED_APPLICATION'),'protected':d.get('classification') in ('controlled_excerpt','restricted'),
            'doc_id':d.get('doc_id'),'request_id':None,'types':[],'route':None,'bytes':0})
    seen=set()
    for row in requests:
        at=epoch(row.get('created_at'));key=(row.get('subject_id'),row.get('request_id'))
        if key[0]!=uid or key in seen or at is None or not now-HISTORY_DAYS*DAY<=at<=now:continue
        seen.add(key)
        events.append({'id':'gateway:'+str(row['row_id']),'at':at,'channel':'gateway',
            'kind':'policy_block' if row['decision']=='BLOCK' else 'outbound_attempt',
            'protected':False,'doc_id':None,'request_id':row['request_id'],
            'types':sorted(set(row.get('detector_types',[]))), 'route':row['destination'],
            'bytes':row['body_bytes'],'state':row['state'],'decision':row['decision']})
    events.sort(key=lambda e:(e['at'],e['id']))
    recent=[e for e in events if e['at']>now-LONG]
    short=[e for e in recent if e['at']>now-SHORT]
    protected=[e for e in recent if e['protected']]
    blocked=[e for e in recent if e['kind']=='policy_block']
    short_reads=[e for e in short if e['protected']]
    short_blocks=[e for e in short if e['kind']=='policy_block']
    sensitive=[e for e in blocked if any(t!='STRUCTURED_INSPECTION_LIMIT' for t in e['types'])]
    families=sorted({t for e in sensitive for t in e['types'] if t!='STRUCTURED_INSPECTION_LIMIT'})
    third_access=protected[2]['at'] if len(protected)>=3 else None
    chain=[e for e in sensitive if third_access is not None and third_access<e['at']]
    baseline=active_baseline(events,now-LONG,now)
    if truncated:baseline['status']='input_bound_reached';baseline['median']=None;baseline['robust_scale']=None
    rules=[]
    def rule(key,title,score,active,observed,limit,seconds,evidence,note):
        rules.append({'rule_id':key,'title':title,'score':score if active else 0,'active':bool(active),
            'observed':observed,'activation':limit,'window_seconds':seconds,
            'evidence_ids':[e['id'] for e in evidence[-12:]],'evidence_count':len(evidence),'note':note})
    rule('protected_read_burst','Protected-content access burst',80,len(short_reads)>=6,len(short_reads),6,SHORT,short_reads,
         'Includes repeated reads of the same document; a small lab trigger, not learned employee intent.')
    rule('policy_block_burst','Repeated policy blocks',85,len(short_blocks)>=3,len(short_blocks),3,SHORT,short_blocks,
         'Unique durable gateway requests only. Retries and audit duplicates do not increase this count.')
    rule('sustained_sensitive_attempts','Sensitive attempts over a longer window',75,len(sensitive)>=4,len(sensitive),4,LONG,sensitive,
         'Catches spaced attempts outside the two-minute burst; finite 30-minute scope.')
    rule('multiple_sensitive_types','Multiple sensitive data types attempted',90,len(sensitive)>=3 and len(families)>=2,
         {'attempts':len(sensitive),'types':families},{'attempts':3,'types':2},LONG,sensitive,
         'Different supported detector types plus repeated blocked requests; types are not independently validated secrets.')
    rule('access_then_sensitive_attempts','Protected access followed by sensitive attempts',85,len(protected)>=3 and len(chain)>=2,
         {'protected_reads':len(protected),'subsequent_attempts':len(chain)}, {'reads':3,'attempts':2},LONG,protected+chain,
         'Three protected reads must precede both attempts. Temporal correlation does not prove the values came from the accessed document.')
    deviation=(len(recent)-baseline['median'])/baseline['robust_scale'] if baseline['status']=='sufficient' else None
    rule('personal_activity_deviation','Activity above personal active-window norm',60,
         deviation is not None and deviation>=6 and len(recent)>=10,
         {'actions':len(recent),'robust_deviation':round(deviation,2) if deviation is not None else None},
         {'minimum_actions':10,'robust_deviation':6},LONG,recent,
         'Advisory alone (60). Requires at least 14 earlier active bins over 7 days. No synthetic history is substituted.')
    live_score=max(r['score'] for r in rules)
    age_at=epoch(subject.get('as_of'));age=now-age_at if age_at is not None else None
    sufficient=subject.get('baseline',{}).get('history_days',0)>=14
    status='missing_timestamp' if age is None else 'future_snapshot' if age<0 else 'stale' if age>MAX_MODEL_AGE else 'insufficient_history' if not sufficient else 'fresh'
    raw=subject.get('behavior_score',0)
    raw=raw if isinstance(raw,(int,float)) and math.isfinite(raw) else 0
    daily=raw if status=='fresh' else 0
    # Input saturation tightens the boundary as a quality safeguard, not a behavior finding.
    guard=80 if truncated else 0
    effective=max(daily,live_score,guard)
    timeline=[{'event_id':e['id'],'timestamp':e['at'],'channel':e['channel'],'kind':e['kind'],
        'doc_id':e['doc_id'],'request_id':e['request_id'],'detector_types':e['types'],
        'origin':e.get('origin','OBSERVED_APPLICATION'),'route':e['route'],'body_bytes':e['bytes'],'state':e.get('state')} for e in recent[-60:]]
    buckets=[]
    for i in range(12):
        start=now-LONG+i*150;items=[e for e in recent if start<e['at']<=start+150]
        buckets.append({'start':start,'end':start+150,'document_reads':sum(e['channel']=='document' for e in items),
            'outbound_attempts':sum(e['channel']=='gateway' for e in items),'blocks':sum(e['kind']=='policy_block' for e in items)})
    trend=[{k:r.get(k) for k in ('date','behavior_score','rule_score','ml_score','copy_count')} for r in history
        if r['subject_id']==uid and r['date']<=subject.get('date','')][-21:]
    model={'status':status,'eligible_for_policy':status=='fresh','as_of':subject.get('as_of'),
        'age_seconds':round(age,1) if age is not None else None,'maximum_age_hours':72,
        'recorded_score':raw,'applied_score':daily,'profile':subject.get('model_version'),
        'provenance':subject.get('provenance'),'history_days':subject.get('baseline',{}).get('history_days',0),
        'note':'Dated completed-day synthetic Isolation Forest + rules. Never fitted on partial live activity.'}
    live={'as_of':datetime.fromtimestamp(now,timezone.utc).isoformat(),'profile':PROFILE,'window_seconds':SHORT,
        'long_window_seconds':LONG,'protected_document_reads':len(short_reads),'blocked_attempts':len(short_blocks),
        'score':live_score,'source':'observed_application_events','rule':'maximum of declared app UEBA rules',
        'rules':rules,'active_rule_ids':[r['rule_id'] for r in rules if r['active']],
        'personal_baseline':baseline,'unique_protected_documents_30m':len({e['doc_id'] for e in protected}),
        'sensitive_attempts_30m':len(sensitive),'detector_types_30m':families,
        'input_bound_reached':truncated,'limitation':'Application-only correlation; not live IF or probability of malicious intent'}
    policy={'effective_score':effective,'daily_component':daily,'live_component':live_score,'quality_guard':guard,
        'combination':'max; no summation of correlated signals','boundary':70,
        'mode':'tightened' if effective>=70 else 'standard',
        'normal_24h_4gram_limit':.20,'active_24h_4gram_limit':.10 if effective>=70 else .20,
        'scope':'Controlled-excerpt budgets only. Restricted content and supported structured findings always block.'}
    return {**subject,'completed_day_score':raw,'behavior_score':effective,'live_context':live,
        'model_context':model,'policy_context':policy,
        'ueba':{'profile':PROFILE,'timeline':timeline,'timeline_total_30m':len(recent),'timeline_limit':60,
            'activity_buckets':buckets,'daily_trend':trend,
            'daily_contributions':{'rules':round(60*subject.get('rule_score',0),2),'anomaly':round(40*subject.get('ml_score',0),2)},
            'coverage':[{'channel':'Registered document access','status':'observed_app_only'},
                {'channel':'Gateway / AI outbound','status':'observed_app_only'},
                {'channel':'Endpoint logon / workstation','status':'not_connected'},
                {'channel':'USB / file / HTTP endpoint telemetry','status':'not_connected'}]}}
