"""CERT r4.2 v2: verified four-channel calendar-day development experiment.

Labels join on channel + ID + declared actor + original timestamp. Neither labels
nor incident metadata enter feature extraction, model fitting or calibration.
Raw URLs/content are discarded; dataset URLs are never requested.
"""
from __future__ import annotations
import argparse
import bisect
from collections import defaultdict, deque
import csv
from datetime import date, datetime, timedelta
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
from sadd.behavior import budget_threshold, evaluate_detector
from cert_ingest import load_ldap_snapshots, sha256_file

ROOT = Path(__file__).resolve().parents[1]
CHANNELS = ('device','logon','http','file')
HEADERS = {
    'device': {'id','date','user','pc','activity'},
    'logon': {'id','date','user','pc','activity'},
    'http': {'id','date','user','pc','url','content'},
    'file': {'id','date','user','pc','filename','content'},
}

def load_labels(archive):
    labels = {}
    incidents = []
    skipped = 0
    with tarfile.open(archive,'r:bz2') as bundle:
        members = {Path(m.name).name:m for m in bundle.getmembers() if m.isfile()}
        with io.TextIOWrapper(bundle.extractfile(members['insiders.csv']), encoding='utf-8-sig') as stream:
            master = [r for r in csv.DictReader(stream) if r['dataset']=='4.2']
        for incident in master:
            episode = Path(incident['details']).stem
            start = datetime.strptime(incident['start'],'%m/%d/%Y %H:%M:%S').isoformat()
            end = datetime.strptime(incident['end'],'%m/%d/%Y %H:%M:%S').isoformat()
            incidents.append({'actor':incident['user'],'episode_id':episode,
                              'scenario':incident['scenario'],'start':start,'end':end})
            with io.TextIOWrapper(bundle.extractfile(members[incident['details']]), encoding='utf-8-sig') as stream:
                for r in csv.reader(stream):
                    if len(r)<4 or r[0] not in CHANNELS:
                        continue
                    if r[3] != incident['user']:
                        skipped += 1
                        continue
                    key = (r[0],r[1])
                    item = {'actor':r[3],'timestamp':datetime.strptime(r[2],'%m/%d/%Y %H:%M:%S').isoformat(),
                            'episode_id':episode,'scenario':incident['scenario']}
                    if key in labels and labels[key] != item:
                        raise ValueError('Conflicting official observable identity')
                    labels[key] = item
    return labels, incidents, skipped

def aggregate(source_dir, answers, output):
    if output.resolve() in {answers.resolve(),(source_dir/'extraction_manifest.json').resolve(),
                            *((source_dir/f'{c}.csv').resolve() for c in CHANNELS)}:
        raise ValueError('User-day output must not overwrite an input source')
    manifest = json.loads((source_dir/'extraction_manifest.json').read_text())
    if manifest.get('status') != 'verified_complete' or manifest.get('archive_sha256') != '586446b00e83ce5cdabf9dc889b0b6e7a9f44556cee3c03d39445d790122556c':
        raise ValueError('A completed verified extraction manifest is required')
    labels, incidents, skipped = load_labels(answers)
    days = defaultdict(lambda:[0]*8)
    hosts = defaultdict(set)
    positive = defaultdict(set)
    evidence = defaultdict(list)
    matched = set()
    matched_by_day = defaultdict(int)
    metadata = {}
    csv.field_size_limit(16*1024*1024)
    for channel in CHANNELS:
        path = source_dir/f'{channel}.csv'
        member = next(m for m in manifest['members'] if Path(m['path']).name==path.name)
        if path.stat().st_size != member['bytes'] or sha256_file(path) != member['sha256']:
            raise ValueError(f'Channel integrity mismatch: {channel}')
        n, first, last = 0, None, None
        checked_dates = set()
        # Content is parsed for CSV correctness, then discarded.
        with path.open(encoding='utf-8-sig', newline='') as stream:
            reader = csv.reader(stream)
            header = next(reader)
            if len(header)!=len(set(header)) or not HEADERS[channel] <= set(header):
                raise ValueError(f'Unsupported {channel} schema: {header}')
            ix = {name:header.index(name) for name in HEADERS[channel]}
            c = CHANNELS.index(channel)*2
            for r in reader:
                if len(r) != len(header):
                    raise ValueError(f'Malformed {channel} row {n+2}')
                event_id, literal, user, pc = (r[ix[k]] for k in ('id','date','user','pc'))
                if not all((event_id,literal,user,pc)):
                    raise ValueError('Missing event identity')
                if len(literal)!=19 or literal[2]!='/' or literal[5]!='/' or literal[10]!=' ':
                    raise ValueError('Invalid source timestamp')
                day = literal[6:10]+'-'+literal[:2]+'-'+literal[3:5]
                if day not in checked_dates:
                    date.fromisoformat(day)
                    checked_dates.add(day)
                hour, minute, second = int(literal[11:13]),int(literal[14:16]),int(literal[17:19])
                if literal[13]!=':' or literal[16]!=':' or not (0<=hour<24 and 0<=minute<60 and 0<=second<60):
                    raise ValueError('Invalid source clock fields')
                stamp = day+'T'+literal[11:]
                first = min(first,day) if first else day
                last = max(last,day) if last else day
                key = (day,user)
                active = channel not in ('device','logon') or r[ix['activity']].lower() in ('connect','logon')
                if channel in ('device','logon') and r[ix['activity']].lower() not in (
                        ('connect','disconnect') if channel=='device' else ('logon','logoff')):
                    raise ValueError('Unknown activity')
                if active:
                    row = days[key]
                    row[c] += 1
                    row[c+1] += int(int(literal[11:13]) < 9 or int(literal[11:13]) >= 18)
                hosts[key].add(pc)
                official = labels.get((channel,event_id))
                if official:
                    if official['actor'] != user or official['timestamp'] != stamp:
                        raise ValueError('Official channel/ID/actor/time join mismatch')
                    positive[key].add(official['episode_id'])
                    matched.add((channel,event_id))
                    matched_by_day[key] += 1
                    if len(evidence[key])<8:
                        evidence[key].append({'release':'4.2','channel':channel,'event_id':event_id,
                                              'timestamp':stamp,'actor':user})
                n += 1
                if n%2000000==0:
                    print(f'{channel}: {n:,} rows',flush=True)
        metadata[channel] = {'rows':n,'sha256':member['sha256'],'bytes':member['bytes'],
                             'first_day':first,'last_day':last,'headers':header,
                             'zero_semantics':'no recorded event inside verified source-file coverage; dirty log omissions still possible'}
        print(f'Aggregated {channel}: {n:,} events',flush=True)
    months, ldap, ldap_meta = load_ldap_snapshots(source_dir/'LDAP')
    start = max(date.fromisoformat(m['first_day']) for m in metadata.values()) + timedelta(days=1)
    end = min(date.fromisoformat(m['last_day']) for m in metadata.values()) - timedelta(days=1)
    if end <= start:
        raise ValueError('Channels have no common complete-day range')
    by_actor = defaultdict(list)
    for incident in incidents:
        by_actor[incident['actor']].append(incident)
    output.parent.mkdir(parents=True,exist_ok=True)
    row_count = 0
    eligible_observables = 0
    with output.open('w',encoding='utf-8') as stream:
        day = start
        while day <= end:
            literal = day.isoformat()
            index = bisect.bisect_right(months,literal[:7])-1
            if index < 0:
                raise ValueError('No contemporaneous LDAP snapshot')
            for user, role in sorted(ldap[months[index]].items()):
                key = (literal,user)
                episodes = sorted(positive[key])
                contextual = [i for i in by_actor[user] if i['start'][:10] <= literal <= i['end'][:10]
                              and sum(days[key])>0]
                row = {'subject_id':'cert-r4.2:'+user,'date':literal,'role':role,
                       'counts':days[key], 'workstations':sorted(hosts[key]),'label':int(bool(episodes)),
                       'episode_id':episodes[0] if episodes else None,'episode_ids':episodes,
                       'secondary_label':int(bool(contextual)),
                       'secondary_episode_ids':[i['episode_id'] for i in contextual],
                       'exact_observable_event_count':matched_by_day[key],
                       'evidence':evidence[key], 'coverage':'all_four_source_files_available'}
                stream.write(json.dumps(row,separators=(',',':'))+'\n')
                row_count += 1
                eligible_observables += matched_by_day[key]
            day += timedelta(days=1)
    result = {'profile':'cert_multichannel_calendar_v2','provenance':'published_synthetic_CERT_r4.2',
              'evaluation_status':'development_on_previously_inspected_release',
              'channels':metadata,'calendar_start':start.isoformat(),'calendar_end':end.isoformat(),
              'user_days':row_count,'ldap':ldap_meta,'incidents':incidents,
              'answer_sha256':sha256_file(answers),'official_modeled_observables':len(labels),
              'matched_official_observables':len(matched),
              'official_observables_in_eligible_calendar_rows':eligible_observables,
              'matched_observables_excluded_by_roster_or_calendar_bounds':len(matched)-eligible_observables,
              'unmatched_official_observables_by_channel':dict((ch,sum(k[0]==ch for k in labels.keys()-matched)) for ch in CHANNELS),
              'other_actor_context_rows_excluded':skipped,
              'archive_sha256':manifest['archive_sha256'],'user_days_sha256':sha256_file(output),
              'limits':['Original r4.2 is synthetic and has dirty log omissions.',
                        'Counts preserve official source rows; a full duplicate-ID scan is not performed.',
                        'HTTP features use counts/hours, not page topics or content.',
                        'No original URLs or content are retained in model rows.',
                        'First/last partial source days excluded; terminated users follow dated roster membership.']}
    output.with_suffix('.metadata.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(f'Calendar output: {row_count:,} user-days; exact joins {len(matched):,}/{len(labels):,}',flush=True)
    return result

def features(records):
    """Earlier calendar days only; labels are never consulted in this function."""
    users = sorted({r['subject_id'] for r in records})
    user_index = {u:i for i,u in enumerate(users)}
    by_day = defaultdict(list)
    for row in records:
        by_day[row['date']].append(row)
    history = deque(maxlen=28)
    age = np.zeros(len(users),dtype=int)
    seen = defaultdict(set)
    output = []
    for day in sorted(by_day):
        todays = by_day[day]
        current = np.full((len(users),8),np.nan)
        if history:
            h = np.stack(history)
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore',RuntimeWarning)
                med = np.nanmedian(h,axis=0)
                scale = 1.4826*np.nanmedian(abs(h-med),axis=0)
            med = np.nan_to_num(med)
            scale = np.maximum(np.nan_to_num(scale),np.sqrt(np.maximum(1,med)))
            population = np.median(med[age>0],axis=0) if np.any(age>0) else np.zeros(8)
            window_age = np.sum(~np.isnan(h[:,:,0]),axis=0)
        else:
            med = np.zeros((len(users),8)); scale = np.ones_like(med); population=np.zeros(8)
            window_age = np.zeros(len(users),dtype=int)
        role_members = defaultdict(list)
        # Roles supplied for this day, references exclusively from previous days.
        for row in todays:
            i = user_index[row['subject_id']]
            if window_age[i]>=14:
                role_members[row['role']].append(i)
        for row in todays:
            user = row['subject_id']; i = user_index[user]
            counts = np.asarray(row['counts'],dtype=float)
            current[i] = counts
            enough = window_age[i]>=14
            reference = med[i] if enough else population
            reference_scale = scale[i] if enough else np.sqrt(np.maximum(1,population))
            personal_z = np.maximum(0,(counts-reference)/reference_scale)
            peers = [j for j in role_members[row['role']] if j != i]
            peer_med = np.median(med[peers],axis=0) if len(peers)>=5 else reference
            peer_scale = np.maximum(1,np.sqrt(np.maximum(1,peer_med)))
            peer_z = np.maximum(0,(counts-peer_med)/peer_scale)
            adjusted = np.minimum(personal_z,peer_z) if len(peers)>=5 else personal_z
            hosts = set(row['workstations'])
            novelty = len(hosts-seen[user])/max(1,len(hosts))
            # Cold start is explicit; no novelty alert solely because history is absent.
            novelty_signal = novelty if enough else 0.
            personal_rule = float(max(np.log1p(personal_z).max(),novelty_signal*2))
            peer_rule = float(max(np.log1p(adjusted).max(),novelty_signal*2))
            vector = np.r_[np.log1p(counts),np.log1p(np.minimum(personal_z,100)),
                           np.log1p(np.minimum(adjusted,100)),novelty_signal, float(not enough)]
            output.append({**row,'vector':vector.tolist(),'rules_personal':personal_rule,'rules_peer':peer_rule,
                           'baseline':{'history_days':int(window_age[i]),'sufficiency':'personal_14d' if enough else 'limited_population_fallback',
                                       'peer_users':len(peers),'prior_days_only':True},
                           'novel_workstation_fraction':novelty_signal})
        for row in todays:
            i = user_index[row['subject_id']]
            seen[row['subject_id']].update(row['workstations'])
            age[i] += 1
        history.append(current)
    return output

def ecdf(values, validation):
    return np.searchsorted(np.sort(validation),values,side='right')/max(1,len(validation))

def run_benchmark(user_days, output):
    if output.resolve()==user_days.resolve():
        raise ValueError('Report must not overwrite user-day input')
    output.parent.mkdir(parents=True,exist_ok=True)
    protocol = json.loads((ROOT/'artifacts/cert_v2_protocol.json').read_text())
    metadata = json.loads(user_days.with_suffix('.metadata.json').read_text())
    if metadata.get('archive_sha256') != '586446b00e83ce5cdabf9dc889b0b6e7a9f44556cee3c03d39445d790122556c' or metadata.get('answer_sha256') != 'ed21bf921def01e97326b314f2d1fa77651a945bd31bf513095f8ac7658c9ddd':
        raise ValueError('This benchmark requires the pinned official r4.2 and answer provenance')
    if sha256_file(user_days) != metadata['user_days_sha256']:
        raise ValueError('User-day integrity mismatch')
    with user_days.open() as stream:
        records = [json.loads(line) for line in stream]
    print(f'Extracting past-only features for {len(records):,} days',flush=True)
    rows = features(records)
    dates = np.asarray([r['date'] for r in rows])
    train = dates <= protocol['train_end']
    validation = (dates > protocol['train_end']) & (dates <= protocol['validation_end'])
    test = dates > protocol['validation_end']
    if not all(mask.any() for mask in (train,validation,test)):
        raise ValueError('Three nonempty chronological splits required')
    x = np.asarray([r.pop('vector') for r in rows],dtype=float)
    model = IsolationForest(n_estimators=160,max_samples=256,random_state=42,n_jobs=1,contamination='auto')
    model.fit(x[train])
    anomaly = -model.score_samples(x)
    peer = np.asarray([r['rules_peer'] for r in rows])
    personal = np.asarray([r['rules_personal'] for r in rows])
    combined = .6*ecdf(peer,peer[validation])+.4*ecdf(anomaly,anomaly[validation])
    # A label-independent deterministic perturbation declares the tie order.
    tie = np.asarray([int(hashlib.sha256((r['subject_id']+r['date']).encode()).hexdigest()[:12],16)/16**12*1e-9 for r in rows])
    scores = {'rules_personal':personal+tie,'rules_peer':peer+tie,'isolation_forest':anomaly+tie,'combined':combined+tie}
    test_rows = [r for r,t in zip(rows,test) if t]
    comparisons, secondary, points, coverage = {}, {}, {}, {}
    horizon = (min(r['date'] for r in test_rows),max(r['date'] for r in test_rows))
    incidents = [i for i in metadata['incidents'] if i['start'][:10]<=horizon[1] and i['end'][:10]>=horizon[0]]
    for name, values in scores.items():
        point = budget_threshold(values[validation],1.)
        point['ties'] = 'SHA256(subject_id + ISO day), ascending fractional score; independent of labels'
        point['active'] = bool(point['observed_validation_alerts'])
        points[name] = point
        comparisons[name] = evaluate_detector(test_rows,values[test].tolist(),point['threshold'])
        predictions = values[test] >= point['threshold']
        comparisons[name]['actors_with_false_positive_day_alert'] = len({r['subject_id'] for r,p in zip(test_rows,predictions) if p and not r['label']})
        prevalence = sum(r['label'] for r in test_rows)/len(test_rows)
        ap = comparisons[name]['average_precision']
        comparisons[name]['average_precision_lift_over_prevalence'] = ap/prevalence if ap is not None and prevalence else None
        secondary_rows = [{**r,'label':r['secondary_label'],'episode_id':next(iter(r['secondary_episode_ids']),None)} for r in test_rows]
        secondary[name] = evaluate_detector(secondary_rows,values[test].tolist(),point['threshold'])
        detected = set(); observable = set(); limited = set(); delays=[]
        detected_actors = set()
        for row, alert in zip(test_rows,predictions):
            observable.update(row['episode_ids'])
            if row['baseline']['sufficiency'] != 'personal_14d':
                limited.update(row['episode_ids'])
            if alert and row['label']:
                detected.update(row['episode_ids'])
                detected_actors.add(row['subject_id'].removeprefix('cert-r4.2:'))
        for incident in incidents:
            dates_hit = [r['date'] for r,p in zip(test_rows,predictions) if p and incident['episode_id'] in r['episode_ids']]
            if dates_hit:
                delays.append((date.fromisoformat(min(dates_hit))-date.fromisoformat(incident['start'][:10])).days)
        coverage[name] = {'denominator_incidents':len(incidents),'detected_incidents_on_exact_positive_days':len(detected),
                          'denominator_actors':len({i['actor'] for i in incidents}),
                          'detected_actors_on_exact_positive_days':len(detected_actors),
                          'coverage_adjusted_actor_recall':len(detected_actors)/max(1,len({i['actor'] for i in incidents})),
                          'coverage_adjusted_episode_recall':len(detected)/max(1,len(incidents)),
                          'no_modeled_observable_incidents':len({i['episode_id'] for i in incidents}-observable),
                          'incidents_with_limited_history_positive_days':len(limited),
                          'mean_days_from_master_start_for_detected':float(np.mean(delays)) if delays else None}
    model_file = output.with_suffix('.model.joblib')
    joblib.dump({'model':model,'protocol':protocol,'operating_points':points,
                 'feature_names':[f'log_{c}_{p}' for c in CHANNELS for p in ('count','after_hours')]+
                    [f'personal_{c}_{p}' for c in CHANNELS for p in ('count','after_hours')]+
                    [f'peer_{c}_{p}' for c in CHANNELS for p in ('count','after_hours')]+['host_novelty','cold_start'],
                 'validation_rule_reference':np.sort(peer[validation]),'validation_if_reference':np.sort(anomaly[validation])},model_file,compress=3)
    # Retain representative high-priority test days, with exact source evidence.
    ranked_indices = np.where(test)[0][np.argsort(combined[test])[::-1]]
    top_indices, shown_users = [], set()
    for index in ranked_indices:
        if rows[index]['subject_id'] not in shown_users:
            top_indices.append(index)
            shown_users.add(rows[index]['subject_id'])
        if len(top_indices)>=100:
            break
    subjects = []
    for index in top_indices:
        row = rows[index]
        subjects.append({**row,'behavior_score':round(100*combined[index],2),'rule_score':float(ecdf([peer[index]],peer[validation])[0]),
                         'ml_score':float(ecdf([anomaly[index]],anomaly[validation])[0]),'as_of':row['date']+'T23:59:59',
                         'model_version':'iforest-cert-multichannel-v2','provenance':'published_synthetic_CERT_r4.2',
                         'reasons':[f'{c}: {row["counts"][i*2]} recorded events; {row["counts"][i*2+1]} outside 09–18 reference hours.' for i,c in enumerate(CHANNELS)],
                         'features':dict(zip(('device_connects','after_hours_device','logons','after_hours_logons','http_requests','after_hours_http','removable_copies','after_hours_copies'),row['counts']))})
    report = {'dataset':'CERT r4.2 — multichannel v2 development','profile':'cert_multichannel_calendar_v2',
              'status':'measured_development','evaluation_status':protocol['evaluation_status'],
              'provenance':'published_synthetic_CERT_r4.2','dataset_is_synthetic':True,
              'model_version':'iforest-cert-multichannel-v2','subjects':subjects,
              'display_selection':'Top 100 unique subjects by maximum combined historical test-day priority; each row retains its own day, not a live or latest score.',
              'protocol_sha256':sha256_file(ROOT/'artifacts/cert_v2_protocol.json'),
              'source_metadata':metadata,'evaluation':{
                  'claim_scope':'Development on previously inspected r4.2; not independent efficacy or production accuracy.',
                  'label_provenance':'channel_ID_actor_timestamp_matched_official_observable_days',
                  'split':{'train_user_days':int(train.sum()),'validation_user_days':int(validation.sum()),'test_user_days':int(test.sum()),
                           'train_end':protocol['train_end'],'validation_end':protocol['validation_end'],'test_start':horizon[0],'test_end':horizon[1]},
                  'comparisons':comparisons,'secondary_contextual_comparisons':secondary,
                  'incident_coverage':coverage,'operating_points':points,
                  'prevalence':sum(r['label'] for r in test_rows)/len(test_rows),
                  'dataset_selection':{'available_users':len({r['subject_id'] for r in records}),
                                       'selected_users':len({r['subject_id'] for r in records}),
                                       'population':'All contemporaneous LDAP roster user-calendar-days within verified common channel bounds; zero recorded activity retained.'},
                  'cold_start_test_days':sum(r['baseline']['sufficiency']!='personal_14d' for r in test_rows),
                  'model':{'estimator':'IsolationForest','labels_used_in_fit':False,'n_estimators':160,'seed':42},
                  'model_sha256':sha256_file(model_file),'limits':metadata['limits']+[protocol['holdout_warning']]}}
    output.write_text(json.dumps(report,indent=2,allow_nan=False),encoding='utf-8')
    summary = {'profile':report['profile'],'split':report['evaluation']['split'],'comparisons':comparisons,'incident_coverage':coverage}
    output.with_name('cert_v2_run_summary.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print(json.dumps(summary,indent=2),flush=True)
    return report

if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir',type=Path,default=ROOT/'data/cert/multichannel')
    parser.add_argument('--answers',type=Path,default=ROOT/'data/cert/answers.tar.bz2')
    parser.add_argument('--user-days',type=Path,default=ROOT/'data/cert/multichannel_user_days.jsonl')
    parser.add_argument('--output',type=Path,default=ROOT/'artifacts/cert_v2_benchmark.json')
    parser.add_argument('--benchmark-only',action='store_true')
    args = parser.parse_args()
    if not args.benchmark_only:
        aggregate(args.source_dir,args.answers,args.user_days)
    run_benchmark(args.user_days,args.output)
