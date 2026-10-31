"""Evidence-bound UEBA review cases. Separate from gateway enforcement alerts."""
from contextlib import contextmanager
from hashlib import sha256
import json
import sqlite3
import time
import uuid

PROFILE='sedra-evidence-case-v1'


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
def digest(value):return sha256(canonical(value).encode()).hexdigest()


class CaseConflict(ValueError):pass


def evidence_snapshot(s,now):
    rules=[*s['live_context'].get('rules',[]),*s.get('endpoint_context',{}).get('rules',[])]
    active=[r for r in rules if r.get('active') and r['score']>=70]
    if not active:return None
    refs={key for r in active for key in r.get('evidence_ids',[])}
    nodes={}
    for e in s.get('ueba',{}).get('timeline',[]):
        if e['event_id'] in refs:
            nodes[e['event_id']]={'id':e['event_id'],'channel':e['channel'],'kind':e['kind'],'at':e['timestamp'],
                'origin':'OBSERVED_APPLICATION','doc_id':e.get('doc_id'),'request_id':e.get('request_id')}
    for e in s.get('endpoint_context',{}).get('events',[]):
        key='endpoint:'+str(e['seq'])
        if key in refs and e['origin']=='REAL_LOCAL_OBSERVATION':
            nodes[key]={'id':key,'channel':e['channel'],'kind':e['kind'],'at':e['at'],
                'origin':e['origin'],'detail':e['detail']}
    primary=sorted(nodes)
    if not primary:return None
    requests=[r for r in s.get('ueba',{}).get('request_evidence',[]) if now-1800<r['created_at']<=now][:3]
    for r in requests:
        key='gateway:'+str(r['row_id'])
        nodes[key]={'id':key,'channel':'gateway','kind':'policy_block' if r['decision']=='BLOCK' else 'outbound_attempt',
            'at':r['created_at'],'origin':'OBSERVED_APPLICATION','request_id':r['request_id'],
            'decision':r['decision'],'delivery_state':r['state'],'destination':r['destination'],
            'payload_sha256':r['body_sha256'],'detector_types':r['detector_types'],'reason_codes':r['reason_codes'],
            'matched_document_ids':r['matched_document_ids']}
    items=sorted(nodes.values(),key=lambda n:(n['at'],n['id']))[-40:]
    edges=[]
    for a in items:
        for b in items:
            if a['id']==b['id'] or a['at']>b['at']:continue
            if a['channel']=='process' and b['channel']=='file' and a.get('detail',{}).get('probe_run') and a['detail']['probe_run']==b.get('detail',{}).get('probe_run'):
                edges.append({'from':a['id'],'to':b['id'],'relation':'same_server_probe_run_and_time','claim':'Controlled run association; not syscall-level file writer attribution'})
            elif a['channel']=='document' and b['channel']=='gateway' and a.get('doc_id') in b.get('matched_document_ids',[]):
                edges.append({'from':a['id'],'to':b['id'],'relation':'registered_source_match_after_access','claim':'Registered-content match and time order; not proof of intent'})
            elif a['channel'] in ('file','usb','logon') and b['channel']=='gateway' and b['at']-a['at']<=300:
                edges.append({'from':a['id'],'to':b['id'],'relation':'same_lab_subject_temporal_context','claim':'Temporal context only; no proof of copy or exfiltration'})
    active=sorted(active,key=lambda r:(-r['score'],r['rule_id']))
    channels=sorted({n['channel'] for n in items if n['id'] in refs})
    snapshot={'profile':PROFILE,'subject_id':s['subject_id'],'captured_at':now,'title':active[0].get('title',active[0]['rule_id']),
        'priority':max(r['score'] for r in active),'active_rules':active,'trigger_source_ids':primary,
        'signal_last_at':max(nodes[k]['at'] for k in primary),'nodes':items,'edges':edges[:60],
        'edge_total':len(edges),'node_limit':40,'edge_limit':60,
        'policy_context':s['policy_context'],'model_context':s['model_context'],
        'baseline_support':s['live_context'].get('personal_baseline'),
        'sensor_health':s.get('endpoint_context',{}).get('status',{}).get('health'),
        'source_support':'multi-channel observed context' if len(channels)>1 else 'single-channel observed context',
        'channels':channels,'environment':'local_test','identity_binding':'Fictional lab identity; Windows mapping is explicit local test mapping',
        'narrative':f"{len(primary)} referenced source records across {', '.join(channels)}. Highest active rule: {active[0].get('title',active[0]['rule_id'])}. Live review priority {max(r['score'] for r in active)}; effective controlled-excerpt budget {s['policy_context']['active_24h_4gram_limit']*100:g}%.",
        'limits':['Priority is not maliciousness probability.','Temporal edges do not establish causation or exfiltration.',
            'Sources and rule references are bounded; source counts and displayed records can differ.',
            'Daily model is generated lab data; endpoint observations are labeled separately.']}
    semantic=dict(snapshot);semantic.pop('captured_at')
    semantic['model_context']={k:v for k,v in semantic['model_context'].items() if k!='age_seconds'}
    if semantic.get('baseline_support'):semantic['baseline_support']={k:v for k,v in semantic['baseline_support'].items() if k!='reference_ends_before'}
    # A polling heartbeat age is not new behavioral evidence.
    if semantic.get('sensor_health'):semantic['sensor_health']={k:v for k,v in semantic['sensor_health'].items() if k!='ages_seconds'}
    return snapshot,digest(semantic)


class CaseStore:
    def __init__(self,path):
        self.path=path
        with self.db() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS behavior_cases(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT UNIQUE NOT NULL,subject_id TEXT NOT NULL,
                title TEXT NOT NULL,status TEXT NOT NULL,current_score REAL NOT NULL,peak_score REAL NOT NULL,
                opened_at REAL NOT NULL,last_signal_at REAL NOT NULL,updated_at REAL NOT NULL,
                revision INTEGER NOT NULL,disposition TEXT NOT NULL,snapshot_json TEXT NOT NULL,
                semantic_sha256 TEXT NOT NULL,head_hash TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS behavior_case_actor ON behavior_cases(subject_id,seq);
                CREATE TABLE IF NOT EXISTS behavior_case_seen(subject_id TEXT NOT NULL,source_id TEXT NOT NULL,PRIMARY KEY(subject_id,source_id));
                CREATE TABLE IF NOT EXISTS behavior_case_history(case_id TEXT NOT NULL,revision INTEGER NOT NULL,
                payload_json TEXT NOT NULL,previous_hash TEXT NOT NULL,event_hash TEXT NOT NULL,PRIMARY KEY(case_id,revision));
                CREATE TABLE IF NOT EXISTS behavior_case_actions(action_id TEXT PRIMARY KEY,payload_sha256 TEXT NOT NULL,case_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS behavior_case_meta(key TEXT PRIMARY KEY,value INTEGER NOT NULL);
                INSERT OR IGNORE INTO behavior_case_meta VALUES('generation',0);''')
    @contextmanager
    def db(self):
        db=sqlite3.connect(self.path,timeout=10);db.row_factory=sqlite3.Row
        try:
            with db:yield db
        finally:db.close()

    def _event(self,db,row,action,actor,now,extra=None):
        revision=row['revision']+1;previous=row['head_hash']
        payload={'case_id':row['case_id'],'revision':revision,'action':action,'actor':actor,'at':now,**(extra or {})}
        value=digest({'previous':previous,'payload':payload})
        db.execute('INSERT INTO behavior_case_history VALUES(?,?,?,?,?)',(row['case_id'],revision,canonical(payload),previous,value))
        db.execute('UPDATE behavior_cases SET revision=?,head_hash=?,updated_at=? WHERE case_id=?',(revision,value,now,row['case_id']))

    def _summary(self,row):
        return {k:row[k] for k in ('seq','case_id','subject_id','title','status','current_score','peak_score','opened_at','last_signal_at','updated_at','revision','disposition')}|{
            'display_id':f"UEBA-{row['seq']:06d}",'signal_state':'ACTIVE' if row['current_score']>=70 else 'QUIET',
            'evidence_sha256':digest(json.loads(row['snapshot_json']))}

    def observe(self,subject,now=None):
        now=time.time() if now is None else now;uid=subject['subject_id'];built=evidence_snapshot(subject,now)
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM behavior_cases WHERE subject_id=? ORDER BY seq DESC LIMIT 1',(uid,)).fetchone()
            current=subject['live_context']['score']
            if built is None:
                if row and row['current_score']!=current:
                    db.execute('UPDATE behavior_cases SET current_score=? WHERE case_id=?',(current,row['case_id']))
                    self._event(db,row,'SIGNAL_STATE','engine',now,{'current_live_priority':current,'review_status_unchanged':row['status']})
                return self._summary(db.execute('SELECT * FROM behavior_cases WHERE case_id=?',(row['case_id'],)).fetchone()) if row else None
            snapshot,semantic=built
            unseen=[key for key in snapshot['trigger_source_ids'] if not db.execute('SELECT 1 FROM behavior_case_seen WHERE subject_id=? AND source_id=?',(uid,key)).fetchone()]
            new_episode=not row or row['status']=='RESOLVED' or snapshot['signal_last_at']-row['last_signal_at']>1800
            if new_episode:
                if not unseen:return self._summary(row) if row else None
                key='UC-'+uuid.uuid4().hex
                db.execute('INSERT INTO behavior_cases(case_id,subject_id,title,status,current_score,peak_score,opened_at,last_signal_at,updated_at,revision,disposition,snapshot_json,semantic_sha256,head_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                    (key,uid,snapshot['title'],'OPEN',current,current,now,snapshot['signal_last_at'],now,-1,'UNASSESSED',canonical(snapshot),semantic,'0'*64))
                row=db.execute('SELECT * FROM behavior_cases WHERE case_id=?',(key,)).fetchone()
                self._event(db,row,'OPENED','engine',now,{'snapshot':snapshot})
            elif current<row['peak_score']:
                # Keep the strongest source graph when earlier sequence components expire first.
                # A lower live priority changes state; it must not replace the peak evidence.
                if row['current_score']!=current:
                    db.execute('UPDATE behavior_cases SET current_score=?,last_signal_at=max(last_signal_at,?) WHERE case_id=?',
                        (current,snapshot['signal_last_at'],row['case_id']))
                    self._event(db,row,'SIGNAL_STATE','engine',now,{'current_live_priority':current,'peak_evidence_retained':True})
            elif row['semantic_sha256']!=semantic or row['current_score']!=current:
                db.execute('UPDATE behavior_cases SET title=?,current_score=?,peak_score=max(peak_score,?),last_signal_at=max(last_signal_at,?),snapshot_json=?,semantic_sha256=? WHERE case_id=?',
                    (snapshot['title'] if current>=row['peak_score'] else row['title'],current,current,snapshot['signal_last_at'],canonical(snapshot),semantic,row['case_id']))
                self._event(db,row,'EVIDENCE_UPDATED','engine',now,{'snapshot':snapshot})
            db.executemany('INSERT OR IGNORE INTO behavior_case_seen VALUES(?,?)',[(uid,key) for key in snapshot['trigger_source_ids']])
            result=db.execute('SELECT * FROM behavior_cases WHERE case_id=?',(row['case_id'],)).fetchone()
            return self._summary(result)

    def feed(self):
        with self.db() as db:
            db.execute('BEGIN')
            rows=db.execute('SELECT * FROM behavior_cases ORDER BY seq DESC LIMIT 100').fetchall()
            counts={r['status']:r['n'] for r in db.execute('SELECT status,count(*) n FROM behavior_cases GROUP BY status')}
            return {'available':True,'profile':PROFILE,'items':[self._summary(r) for r in rows],
                'counts':{'open':counts.get('OPEN',0),'in_review':counts.get('IN_REVIEW',0),'resolved':counts.get('RESOLVED',0),'total':sum(counts.values())},
                'generation':db.execute("SELECT value FROM behavior_case_meta WHERE key='generation'").fetchone()[0],
                'limit':100,'truncated':sum(counts.values())>100,'scope':'UEBA review findings, separate from confirmed compromise and gateway alerts'}

    def get(self,case_id,packet=False):
        with self.db() as db:
            db.execute('BEGIN');row=db.execute('SELECT * FROM behavior_cases WHERE case_id=?',(case_id,)).fetchone()
            if not row:raise KeyError('UEBA case not found')
            entries=list(reversed(db.execute('SELECT * FROM behavior_case_history WHERE case_id=? ORDER BY revision DESC LIMIT 101',(case_id,)).fetchall()))
            complete=len(entries)<=100
            if not complete:entries=entries[-100:]
            previous='0'*64 if complete else entries[0]['previous_hash'];valid=True;history=[]
            for e in entries:
                payload=json.loads(e['payload_json'])
                valid &= e['previous_hash']==previous and digest({'previous':previous,'payload':payload})==e['event_hash']
                previous=e['event_hash']
                history.append({'revision':e['revision'],'action':payload['action'],'actor':payload['actor'],'at':payload['at'],
                    'priority':payload.get('snapshot',{}).get('priority',payload.get('current_live_priority')),
                    'previous_hash':e['previous_hash'],'event_hash':e['event_hash'],**({'payload':payload} if packet else {})})
            valid &= previous==row['head_hash']
            snapshot=json.loads(row['snapshot_json'])
            # Bind the displayed latest evidence to an actual stored ledger snapshot.
            bound=any('snapshot' in (p:=json.loads(e['payload_json'])) and digest(p['snapshot'])==digest(snapshot) for e in entries)
            return {'case':self._summary(row),'snapshot':snapshot,'history':history,
                'integrity':{'hash_chain_valid':bool(valid),'displayed_snapshot_bound':bound,'complete_history':complete,
                    'head_hash':row['head_hash'],'note':'Self-contained consistency check, not a signature or independently trusted attestation. Privileged rewrite can recompute hashes.'},
                'export_scope':'Private local investigation metadata; do not publish Windows source records in a submission archive'}

    def action(self,body,now=None):
        now=time.time() if now is None else now
        if set(body)-{'case_id','action','action_id','expected_revision','disposition'} or not {'case_id','action','action_id','expected_revision'}<=set(body):raise ValueError('Declared case action fields required')
        if body['action'] not in ('ACKNOWLEDGE','RESOLVE','REOPEN'):raise ValueError('Unknown case action')
        if type(body['expected_revision']) is not int or body['expected_revision']<0:raise ValueError('Expected revision required')
        for key in ('action_id','case_id'):
            if not isinstance(body[key],str) or not 8<=len(body[key])<=100 or any(not(c.isascii() and (c.isalnum() or c in '-_')) for c in body[key]):raise ValueError('Bounded ASCII action and case IDs required')
        if body['action']=='RESOLVE' and body.get('disposition') not in ('EXPECTED_LAB_TEST','BENIGN_EXPLAINED','REQUIRES_FOLLOWUP'):raise ValueError('Choose a review disposition')
        if body['action']!='RESOLVE' and 'disposition' in body:raise ValueError('Disposition is accepted only for resolution')
        hashed=digest(body)
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE');prior=db.execute('SELECT * FROM behavior_case_actions WHERE action_id=?',(body['action_id'],)).fetchone()
            if prior:
                if prior['payload_sha256']!=hashed:raise ValueError('Action ID reused for another operation')
                return {'case_id':prior['case_id'],'idempotent_replay':True}
            row=db.execute('SELECT * FROM behavior_cases WHERE case_id=?',(body['case_id'],)).fetchone()
            if not row:raise KeyError('UEBA case not found')
            if row['revision']!=body['expected_revision']:raise CaseConflict('Case changed; refresh before applying an action')
            status={'ACKNOWLEDGE':'IN_REVIEW','RESOLVE':'RESOLVED','REOPEN':'OPEN'}[body['action']]
            if (body['action']=='ACKNOWLEDGE' and row['status']!='OPEN') or (body['action']=='RESOLVE' and row['status']=='RESOLVED') or (body['action']=='REOPEN' and row['status']!='RESOLVED'):raise CaseConflict('Action is not valid in the current review status')
            disposition=body.get('disposition','UNASSESSED')
            db.execute('UPDATE behavior_cases SET status=?,disposition=? WHERE case_id=?',(status,disposition,row['case_id']))
            self._event(db,row,body['action'],'analyst',now,{'old_status':row['status'],'new_status':status,'disposition':disposition})
            db.execute('INSERT INTO behavior_case_actions VALUES(?,?,?)',(body['action_id'],hashed,row['case_id']))
            return {'case_id':row['case_id'],'idempotent_replay':False}

    def reset(self):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            for table in ('behavior_case_history','behavior_case_actions','behavior_case_seen','behavior_cases'):db.execute('DELETE FROM '+table)
            db.execute("UPDATE behavior_case_meta SET value=value+1 WHERE key='generation'")
