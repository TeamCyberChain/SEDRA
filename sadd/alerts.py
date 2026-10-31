"""Durable local alert queue. Admission and alert writes share one transaction."""
from hashlib import sha256
import json
import math
import time
import uuid

ALERT_PROFILE='sedra-gateway-alerts-v1'
RESOLUTIONS={'CONFIRMED_POLICY_EVENT','FALSE_POSITIVE','EXPECTED_TEST'}


class AlertConflict(ValueError):
    pass


def _now(value=None):
    value=time.time() if value is None else float(value)
    if not math.isfinite(value):raise ValueError('Alert time must be finite')
    return value


def _json(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))


def _classification(snapshot,kind):
    if kind=='DELIVERY_UNKNOWN':
        return 'medium','Delivery acknowledgement unresolved','delivery_reliability','Delivery uncertainty; not proof of exfiltration'
    types={f.get('type') for f in snapshot.get('structured_findings',[])}
    reasons=set(snapshot.get('reason_codes',[]))
    if types & {'PEM_PRIVATE_KEY','LABELED_CREDENTIAL','BEARER_TOKEN'}:
        return 'critical','Credential material blocked','credential_protection','Potential credential impact; blocked by policy; validity not verified'
    if types & {'AZ_FIN_CONTEXTUAL','AZ_IBAN_MOD97','IBAN_MOD97','PAYMENT_CARD_LUHN'}:
        return 'high','Sensitive data blocked','structured_sensitive_data','Supported identifier/financial rule matched; blocked before delivery'
    if 'RESTRICTED_DOCUMENT_MATCH' in reasons:
        return 'high','Restricted content blocked','registered_content','Registered or governed Restricted label matched'
    if types & {'AWS_ACCESS_KEY_ID'}:
        return 'high','Access key identifier blocked','credential_protection','Access-ID format matched; service validity not verified'
    if 'CUMULATIVE_DISCLOSURE_LIMIT' in reasons or 'CUMULATIVE_30D_DISCLOSURE_LIMIT' in reasons:
        severity='high' if snapshot.get('behavior_score',0)>=70 else 'medium'
        return severity,'Disclosure budget exceeded','cumulative_disclosure','24-hour or 30-day disclosure budget; triage priority is not a probability'
    if 'STRUCTURED_INSPECTION_LIMIT' in types:
        return 'medium','Content inspection limit reached','inspection_limits','Inspection could not complete within its declared resource bound'
    return 'medium','Outbound request blocked','policy_enforcement','Gateway policy block; no confirmed compromise claim'


class AlertStore:
    def _init_alerts(self,con):
        con.executescript('''
            CREATE TABLE IF NOT EXISTS security_alerts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL UNIQUE,
                request_row_id INTEGER NOT NULL, kind TEXT NOT NULL,
                severity TEXT NOT NULL, title TEXT NOT NULL, category TEXT NOT NULL,
                severity_basis TEXT NOT NULL, occurred_at REAL NOT NULL, created_at REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN', disposition TEXT NOT NULL DEFAULT 'UNASSESSED',
                assigned_to TEXT, read_at REAL, updated_at REAL NOT NULL,
                revision INTEGER NOT NULL DEFAULT 0, imported INTEGER NOT NULL DEFAULT 0,
                UNIQUE(request_row_id,kind),
                FOREIGN KEY(request_row_id) REFERENCES gateway_requests(row_id)
            );
            CREATE INDEX IF NOT EXISTS alert_queue_status ON security_alerts(status,seq);
            CREATE TABLE IF NOT EXISTS security_alert_meta (key TEXT PRIMARY KEY,value INTEGER NOT NULL);
            INSERT OR IGNORE INTO security_alert_meta VALUES('generation',0);
            CREATE TABLE IF NOT EXISTS security_alert_actions (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT, action_id TEXT NOT NULL UNIQUE,
                alert_id TEXT NOT NULL, actor TEXT NOT NULL, at REAL NOT NULL,
                action TEXT NOT NULL, old_status TEXT, new_status TEXT NOT NULL,
                disposition TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
                FOREIGN KEY(alert_id) REFERENCES security_alerts(alert_id)
            );
        ''')

    def _record_alert(self,con,row,kind,now,imported=False):
        snapshot=json.loads(row['snapshot_json'])
        severity,title,category,basis=_classification(snapshot,kind)
        con.execute('''INSERT OR IGNORE INTO security_alerts
            (alert_id,request_row_id,kind,severity,title,category,severity_basis,occurred_at,created_at,updated_at,imported)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
            ('SE-'+uuid.uuid4().hex,row['row_id'],kind,severity,title,category,basis,
             row['created_at'] if kind=='POLICY_BLOCK' else row['updated_at'],now,now,int(imported)))

    def _backfill_alerts(self,con,now):
        for row in con.execute("SELECT * FROM gateway_requests WHERE decision='BLOCK' OR state='DELIVERY_UNKNOWN'").fetchall():
            self._record_alert(con,row,'POLICY_BLOCK' if row['decision']=='BLOCK' else 'DELIVERY_UNKNOWN',now,imported=True)

    def _alert_row(self,con,alert_id):
        row=con.execute('''SELECT a.*,r.subject_id,r.request_id,r.destination,r.decision,r.state,r.body_sha256,
            r.body_bytes,r.behavior_score,r.snapshot_json FROM security_alerts a
            JOIN gateway_requests r ON r.row_id=a.request_row_id WHERE a.alert_id=?''',(alert_id,)).fetchone()
        if row is None:raise KeyError('Alert not found')
        return row

    def _alert_view(self,row):
        snapshot=json.loads(row['snapshot_json'])
        uncertainty=row['state'] in ('SENDING','DELIVERY_UNKNOWN')
        return {k:row[k] for k in ('seq','alert_id','kind','severity','title','category','severity_basis',
            'occurred_at','created_at','status','disposition','assigned_to','read_at','updated_at','revision',
            'subject_id','request_id','destination','decision','state','body_sha256','body_bytes','behavior_score')} | {
            'display_id':f"SEDRA-{row['seq']:06d}",'imported_from_ledger':bool(row['imported']),
            'profile':ALERT_PROFILE,'environment':'synthetic_lab',
            'reason_codes':snapshot.get('reason_codes',[]),'security_tags':snapshot.get('security_tags'),
            'detector_types':sorted({f['type'] for f in snapshot.get('structured_findings',[])}),
            'delivery_uncertain':uncertainty,
            'outcome':'Prevented by policy' if row['decision']=='BLOCK' else 'Delivery unconfirmed' if uncertainty else
                'Delivery confirmed' if row['state']=='FORWARDED_CONFIRMED' else 'Confirmed not sent' if row['state']=='NOT_SENT_CONFIRMED' else row['state'],
            'workflow_note':'Analyst review does not change enforcement, resend content or establish compromise.'}

    def alerts_feed(self,now=None,limit=200,before=None):
        now=_now(now)
        if type(limit) is not int or not 1<=limit<=200:raise ValueError('Alert page limit is 1–200')
        if before is not None and (type(before) is not int or before<1):raise ValueError('Invalid alert page cursor')
        with self._transaction() as con:
            self._expire(con,now)
            ids=[r['alert_id'] for r in con.execute('SELECT alert_id FROM security_alerts '+('WHERE seq<? ' if before else '')+'ORDER BY seq DESC LIMIT ?',
                (before,limit) if before else (limit,))]
            items=[self._alert_view(self._alert_row(con,key)) for key in ids]
            counts={r['status']:r['n'] for r in con.execute('SELECT status,count(*) n FROM security_alerts GROUP BY status')}
            unread=con.execute('SELECT count(*) n FROM security_alerts WHERE read_at IS NULL').fetchone()['n']
            active=con.execute("SELECT count(*) n FROM security_alerts WHERE status!='RESOLVED'").fetchone()['n']
            critical=con.execute("SELECT count(*) n FROM security_alerts WHERE severity='critical' AND status!='RESOLVED'").fetchone()['n']
            watermark=con.execute('SELECT coalesce(max(seq),0) n FROM security_alerts').fetchone()['n']
            generation=con.execute("SELECT value FROM security_alert_meta WHERE key='generation'").fetchone()['value']
            return {'available':True,'items':items,'counts':{'total':sum(counts.values()),'open':counts.get('OPEN',0),
                'in_review':counts.get('IN_REVIEW',0),'resolved':counts.get('RESOLVED',0),'unread':unread,
                'active':active,'critical_active':critical},'watermark':watermark,'returned':len(items),
                'truncated':sum(counts.values())>len(items),'generation':generation,'poll_interval_seconds':2,
                'scope':'Live gateway ledger only; historical CERT benchmark records never generate these alerts.'}

    def alert_detail(self,alert_id,now=None):
        now=_now(now)
        with self._transaction() as con:
            self._expire(con,now)
            row=self._alert_row(con,alert_id)
            history=[dict(r) for r in con.execute('''SELECT event_id,actor,at,action,old_status,new_status,disposition
                FROM security_alert_actions WHERE alert_id=? ORDER BY event_id''',(alert_id,))]
            return {'alert':self._alert_view(row),'history':history,
                'request':self._response(con,self._row(con,row['subject_id'],row['request_id']),now)}

    def update_alert(self,body,actor='analyst',now=None):
        now=_now(now)
        required={'alert_id','action_id','action','expected_revision'}
        if not required<=set(body) or set(body)-required-{'disposition'}:raise ValueError('Use declared alert action fields')
        for key in ('alert_id','action_id'):
            if not isinstance(body[key],str) or not 8<=len(body[key])<=100 or any(not(c.isascii() and (c.isalnum() or c in '-_')) for c in body[key]):
                raise ValueError('Invalid alert/action identifier')
        if type(body['expected_revision']) is not int or body['expected_revision']<0:raise ValueError('Expected revision must be a nonnegative integer')
        action=body['action']
        if action not in ('READ','ACKNOWLEDGE','RESOLVE','REOPEN'):raise ValueError('Unknown alert action')
        disposition=body.get('disposition')
        if action=='RESOLVE' and disposition not in RESOLUTIONS:raise ValueError('Choose a resolution disposition')
        if action!='RESOLVE' and disposition is not None:raise ValueError('Disposition is accepted only on resolution')
        digest=sha256(_json(body).encode()).hexdigest()
        with self._transaction() as con:
            prior=con.execute('SELECT * FROM security_alert_actions WHERE action_id=?',(body['action_id'],)).fetchone()
            if prior:
                if prior['alert_id']!=body['alert_id'] or prior['actor']!=actor or prior['payload_sha256']!=digest:
                    raise ValueError('Action ID reused for a different operation')
                return {'alert':self._alert_view(self._alert_row(con,body['alert_id'])),'idempotent_replay':True}
            row=self._alert_row(con,body['alert_id'])
            if row['revision']!=body['expected_revision']:raise AlertConflict('Alert changed; refresh before applying this action')
            old=row['status'];status=old;resolved=row['disposition'];owner=row['assigned_to']
            if action=='ACKNOWLEDGE':
                if old!='OPEN':raise AlertConflict('Only an open alert can be acknowledged')
                status='IN_REVIEW';owner=actor
            elif action=='RESOLVE':
                if old=='RESOLVED':raise AlertConflict('Alert is already resolved')
                status='RESOLVED';resolved=disposition;owner=owner or actor
            elif action=='REOPEN':
                if old!='RESOLVED':raise AlertConflict('Only a resolved alert can be reopened')
                status='OPEN';resolved='UNASSESSED';owner=None
            con.execute('''UPDATE security_alerts SET status=?,disposition=?,assigned_to=?,read_at=coalesce(read_at,?),
                updated_at=?,revision=revision+1 WHERE alert_id=?''',(status,resolved,owner,now,now,body['alert_id']))
            con.execute('''INSERT INTO security_alert_actions(action_id,alert_id,actor,at,action,old_status,new_status,disposition,payload_sha256)
                VALUES(?,?,?,?,?,?,?,?,?)''',(body['action_id'],body['alert_id'],actor,now,action,old,status,resolved,digest))
            return {'alert':self._alert_view(self._alert_row(con,body['alert_id'])),'idempotent_replay':False}
