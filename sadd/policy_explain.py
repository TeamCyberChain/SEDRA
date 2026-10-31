"""Frozen-facts policy explanation. Read-only; never sends or changes admission."""
import math

PROFILE='sadd-dual-window-anchored-token-restricted-v2'


def limits(score):
    score=float(score)
    if not math.isfinite(score) or not 0<=score<=100:raise ValueError('Priority must be finite and between 0 and 100')
    high=score>=70
    return {'threshold':.10 if high else .20,'long_threshold':.20 if high else .35,
        'token_threshold':.12 if high else .25,'long_token_threshold':.25 if high else .40}


def replay(snapshot,score):
    """Re-evaluate immutable admission coverage, not current ledger coverage."""
    budget=limits(score)
    if snapshot.get('model_profiles',{}).get('policy')!=PROFILE:
        return {'supported':False,'reason':'Historical policy profile is not supported; no hypothetical verdict is invented'}
    hard=[r for r in snapshot.get('reason_codes',[]) if r in ('KNOWN_DEMO_SECRET','RESTRICTED_DOCUMENT_MATCH','GOVERNED_RESTRICTED_LABEL') or r.startswith('STRUCTURED_')]
    reasons=list(hard);comparisons=[]
    try:
        for doc in snapshot['matched_documents']:
            incoming=doc.get('eligible_match_count',0)>0 or doc.get('token_match_count',0)>0
            if not incoming:continue
            if doc['effective_sensitivity']=='restricted':
                reasons.append('RESTRICTED_DOCUMENT_MATCH');continue
            if doc['classification']!='controlled_excerpt' or snapshot['destination_trust_class']!='unapproved_ai':continue
            for metric,key,reason in (
                ('evaluation_coverage','threshold','CUMULATIVE_DISCLOSURE_LIMIT'),
                ('token_evaluation_coverage','token_threshold','CUMULATIVE_DISCLOSURE_LIMIT'),
                ('long_evaluation_coverage','long_threshold','CUMULATIVE_30D_DISCLOSURE_LIMIT'),
                ('long_token_evaluation_coverage','long_token_threshold','CUMULATIVE_30D_DISCLOSURE_LIMIT')):
                value=doc[metric]['prospective']['ratio']
                if not isinstance(value,(int,float)) or not math.isfinite(value) or not 0<=value<=1:raise ValueError('Invalid coverage')
                matched=value>=budget[key]
                comparisons.append({'doc_id':doc['doc_id'],'metric':metric,'frozen_ratio':value,'limit':budget[key],'blocks':matched})
                if matched:reasons.append(reason)
    except (KeyError,TypeError,ValueError):
        return {'supported':False,'reason':'Frozen coverage evidence is incomplete or invalid; no hypothetical verdict is invented'}
    return {'supported':True,'decision':'BLOCK' if reasons else 'ALLOW','priority':score,'limits':budget,
        'reason_codes':list(dict.fromkeys(reasons)),'hard_policy_unchanged':bool(hard),'comparisons':comparisons}


def counterfactual(snapshot,excluded,exclude_daily=False):
    context=snapshot.get('behavior_context',{});live=context.get('live_context',{})
    rules=[*live.get('rules',[]),*context.get('endpoint_context',{}).get('rules',[])]
    if not isinstance(excluded,list) or len(excluded)>24 or any(not isinstance(x,str) for x in excluded):raise ValueError('Choose up to 24 recorded rules')
    known={r['rule_id'] for r in rules}
    if set(excluded)-known:raise ValueError('Only rules recorded at admission can be excluded')
    if type(exclude_daily) is not bool:raise ValueError('exclude_daily must be boolean')
    if not context.get('policy_context'):return {'supported':False,'reason':'This historical request has no frozen component contract'}
    daily=0 if exclude_daily else context['policy_context']['daily_component']
    active=[r for r in rules if r.get('active') and r['rule_id'] not in excluded]
    rule_score=max([r['score'] for r in active]+[0])
    guard=context['policy_context'].get('quality_guard',0)
    score=max(daily,rule_score,guard)
    original=replay(snapshot,snapshot['behavior_score'])
    if not original.get('supported') or original['decision']!=snapshot['decision']:
        return {'supported':False,'reason':'Original verdict cannot be exactly reproduced from this frozen policy contract'}
    return {'supported':True,'request_id':snapshot['request_id'],'subject_id':snapshot['subject_id'],
        'original':original,'hypothetical':replay(snapshot,score),'excluded_rules':sorted(set(excluded)),
        'exclude_daily':exclude_daily,'remaining_active_rules':[r['rule_id'] for r in active],
        'quality_guard_retained':guard,'method':'Rule ablation over frozen facts; not causal ML attribution or a new live admission',
        'side_effects':'No resend, unblock, reservation, label change, or policy change',
        'fact_scope':'Original labels, destination trust and admission-time cumulative coverage remain frozen'}
