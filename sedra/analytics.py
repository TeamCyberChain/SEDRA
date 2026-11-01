"""Observed operational aggregates and scoped, immutable report snapshots."""
import csv,hashlib,html,io,json,secrets,sqlite3,time
from collections import Counter
from datetime import datetime,timezone,timedelta
from pathlib import Path
from contextlib import contextmanager

TEMPLATES={'executive':'Executive security brief','security':'Security operations report','activity':'Activity and delivery report'}
PERIODS={1,7,30}
TZ=timezone(timedelta(hours=4))

def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
def principal(session):return session.get('principal') or ('subject:'+session['subject_id'] if session.get('subject_id') else 'analyst')
def scope(session):
    if session['role']=='analyst':return None
    uid=session.get('subject_id')
    if not isinstance(uid,str) or not uid:raise PermissionError('Authenticated subject required')
    return uid


def aggregate(app,session,days=7,subject=None,now=None):
    if type(days) is not int or days not in PERIODS:raise ValueError('Choose 1, 7 or 30 days')
    bound=scope(session)
    if bound and subject and subject!=bound:raise PermissionError('Subject-scoped access required')
    uid=bound or subject
    if uid is not None and uid not in app.subjects:raise ValueError('Known subject required')
    now=time.time() if now is None else now;start=now-days*86400
    clause='created_at>=? AND created_at<=?'+(' AND subject_id=?' if uid else '')
    args=[start,now]+([uid] if uid else [])
    with app.gateway._connection() as c:
        totals=dict(c.execute("SELECT count(*) attempts,coalesce(sum(decision='BLOCK'),0) blocked,coalesce(sum(state='FORWARDED_CONFIRMED'),0) confirmed,coalesce(sum(state IN ('DELIVERY_UNKNOWN','SENDING')),0) unconfirmed,count(DISTINCT subject_id) active_identities FROM gateway_requests WHERE "+clause,args).fetchone())
        rows=c.execute('SELECT subject_id,created_at,decision,state,destination,snapshot_json FROM gateway_requests WHERE '+clause+' ORDER BY created_at DESC,row_id DESC LIMIT 5000',args).fetchall()
        routes=[dict(r) for r in c.execute('SELECT destination route,count(*) attempts,coalesce(sum(decision=\'BLOCK\'),0) blocked FROM gateway_requests WHERE '+clause+' GROUP BY destination ORDER BY attempts DESC,destination LIMIT 12',args)]
        trends=[dict(r) for r in c.execute("SELECT date(created_at+14400,'unixepoch') day,count(*) attempts,coalesce(sum(decision='BLOCK'),0) blocked,coalesce(sum(state='FORWARDED_CONFIRMED'),0) confirmed FROM gateway_requests WHERE "+clause+" GROUP BY day ORDER BY day",args)]
    totals['other_states']=max(0,totals['attempts']-totals['blocked']-totals['confirmed']-totals['unconfirmed'])
    types=Counter();classifications=Counter()
    for r in rows:
        snapshot=json.loads(r['snapshot_json'])
        types.update({f['type'] for f in snapshot.get('structured_findings',[]) if f.get('type')!='STRUCTURED_INSPECTION_LIMIT'})
        classifications[snapshot.get('security_tags',{}).get('sensitivity','unclassified')]+=1
    live=app.live_subjects([s for s in app.snapshot['subjects'] if not uid or s['subject_id']==uid])
    high=[s for s in live if s['live_context']['score']>=70]
    app.refresh_case_signals(now=now)
    with app.cases.db() as c:
        case_clause=' WHERE subject_id=?' if uid else '';case_args=[uid] if uid else []
        cases=dict(c.execute("SELECT count(*) total,coalesce(sum(status='OPEN'),0) open,coalesce(sum(status='IN_REVIEW'),0) in_review,coalesce(sum(status='RESOLVED'),0) resolved FROM behavior_cases"+case_clause,case_args).fetchone())
    observed_read_where='timestamp>=? AND timestamp<=?'+(' AND subject_id=?' if uid else '')
    with app.db() as c:
        reads=c.execute("SELECT count(*) FROM audit WHERE kind='document_read' AND "+observed_read_where,[datetime.fromtimestamp(start,timezone.utc).isoformat(),datetime.fromtimestamp(now,timezone.utc).isoformat()]+([uid] if uid else [])).fetchone()[0]
    advice=[]
    if totals['unconfirmed']:advice.append('Reconcile unconfirmed deliveries; do not automatically resend uncertain requests.')
    if high:advice.append('Review high-priority identities against their source evidence. Priority is not proof of compromise.')
    if cases['open']:advice.append('Assign an analyst to unreviewed behavior cases and record a disposition.')
    if not advice:advice.append('Continue collecting source coverage and review new evidence; a quiet period does not prove safety.')
    endpoint=app.endpoint.view(uid or 'lab-001');health=endpoint.get('status',{}).get('health',{}).get('state','not_mapped')
    return {'generated_at':now,'window':{'days':days,'start':start,'end':now,'chart_timezone':'AZT (UTC+04)'},'scope':{'subject_id':uid,'label':('User '+uid[4:] if uid and uid.startswith('lab-') else uid) or 'All authorized identities'},'metrics':{**totals,'high_priority_identities':len(high),'document_accesses':reads,'registered_sources':len(app.catalog_view())},'cases':cases,'trend':trends,'routes':routes,'detectors':[{'name':k,'count':v} for k,v in types.most_common(10)],'classifications':[{'name':k,'count':v} for k,v in classifications.most_common()], 'high_priority':[{'subject_id':s['subject_id'],'live_priority':s['live_context']['score'],'active_rules':s['live_context']['active_rule_ids']} for s in high[:20]],'coverage':[{'name':'Gateway ledger','state':'observed','note':'Recorded transfer decisions, not all company traffic'},{'name':'Local Windows sensor','state':health,'note':'Explicit local test identity and scoped metadata only'},{'name':'Personal behavior baseline','state':str(sum(s['live_context']['personal_baseline']['status']=='sufficient' for s in live))+' supported / '+str(len(live))+' assessed','note':'Missing history is not a normal baseline'},{'name':'External CERT research','state':'separate evaluation','note':'File-only v1 failed gate; multichannel v2 unmeasured'}],'recommended_actions':advice,'data_quality':{'detail_rows':len(rows),'detail_limit':5000,'detail_truncated':totals['attempts']>len(rows),'totals_are_full_window_sql':True},'definitions':['Blocked attempts are policy decisions, not confirmed prevented breaches or monetary loss.','Confirmed means the gateway observed a matching delivery result; unknown remains unresolved.','High priority counts current observed live rules, not the synthetic completed-day model.','Case counts are current retained review status, independent of the selected request window.','Document access counts cover this application endpoint; authenticated external collector reports are separate.','Detector/classification breakdowns use at most the latest 5000 requests; period totals and daily trend use the complete window.','Registered corpus and dated daily models are synthetic demonstration data; no enterprise efficacy is asserted.']}


class Reports:
    def __init__(self,path):
        self.path=str(path)
        with self.db() as c:c.execute('CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY,owner TEXT NOT NULL,subject TEXT,created REAL NOT NULL,template TEXT NOT NULL,payload TEXT NOT NULL,sha256 TEXT NOT NULL)')
    @contextmanager
    def db(self):
        c=sqlite3.connect(self.path,timeout=10);c.row_factory=sqlite3.Row
        try:
            with c:yield c
        finally:c.close()
    def listing(self,session):
        query='' if session['role']=='analyst' else ' WHERE owner=? AND subject=?'
        args=[] if session['role']=='analyst' else [principal(session),scope(session)]
        with self.db() as c:return [dict(r) for r in c.execute('SELECT id,created,template,subject,sha256 FROM reports'+query+' ORDER BY created DESC LIMIT 100',args)]
    def create(self,app,session,body):
        if set(body)!={'template','days','subject_id'} or not isinstance(body['template'],str) or body['template'] not in TEMPLATES or not isinstance(body['subject_id'],str):raise ValueError('Known template, days and optional subject ID required')
        if session['role']!='analyst' and body['template']!='activity':raise PermissionError('Executive and security reports require Analyst access')
        snapshot=aggregate(app,session,body['days'],body['subject_id'] or None)
        uid=secrets.token_hex(16);payload={'id':uid,'title':TEMPLATES[body['template']],'template':body['template'],'snapshot':snapshot};raw=canonical(payload);digest=hashlib.sha256(raw.encode()).hexdigest()
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute('SELECT count(*) FROM reports WHERE owner=? AND created>?',(principal(session),time.time()-60)).fetchone()[0]>=5:raise ValueError('Report generation limited to five snapshots per minute')
            c.execute('INSERT INTO reports VALUES(?,?,?,?,?,?,?)',(uid,principal(session),snapshot['scope']['subject_id'],snapshot['generated_at'],body['template'],raw,digest))
        return payload|{'sha256':digest}
    def get(self,session,uid):
        if not isinstance(uid,str) or not __import__('re').fullmatch('[0-9a-f]{32}',uid):raise ValueError('Valid report identifier required')
        with self.db() as c:r=c.execute('SELECT * FROM reports WHERE id=?',(uid,)).fetchone()
        if not r or (session['role']!='analyst' and (r['owner']!=principal(session) or r['subject']!=scope(session))):raise KeyError('Report not available in this scope')
        payload=json.loads(r['payload'])
        if hashlib.sha256(canonical(payload).encode()).hexdigest()!=r['sha256']:raise ValueError('Report integrity check failed')
        return payload|{'sha256':r['sha256']}


def export_csv(report):
    s=io.StringIO();w=csv.writer(s);w.writerow(['Section','Metric','Value'])
    x=report['snapshot']
    for key,value in [('Report ID',report['id']),('Title',report['title']),('Scope',x['scope']['label']),('Window days',x['window']['days']),('Window start UTC',datetime.fromtimestamp(x['window']['start'],timezone.utc).isoformat()),('Window end UTC',datetime.fromtimestamp(x['window']['end'],timezone.utc).isoformat()),('Chart timezone',x['window']['chart_timezone'])]:w.writerow(['Report metadata',key,value])
    for k,v in report['snapshot']['metrics'].items():w.writerow(['Selected period',k,v])
    for k,v in report['snapshot']['cases'].items():w.writerow(['Current retained cases',k,v])
    for r in report['snapshot']['trend']:w.writerow(['Daily attempts',r['day'],r['attempts']])
    for note in x['definitions']:w.writerow(['Interpretation','Definition',note])
    w.writerow(['Integrity','Snapshot SHA-256',report['sha256']])
    return s.getvalue().encode('utf-8-sig')


def export_pdf(report):
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
    from reportlab.lib.enums import TA_LEFT
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,PageBreak,KeepTogether
    from reportlab.lib.pagesizes import A4
    from reportlab.graphics.shapes import Drawing,Rect,String
    b=io.BytesIO();styles=getSampleStyleSheet();styles.add(ParagraphStyle('Note',parent=styles['BodyText'],fontSize=8,leading=12,textColor=colors.HexColor('#526171')))
    styles['Title'].fontSize=25;styles['Title'].leading=30;styles['Title'].alignment=TA_LEFT
    teal=colors.HexColor('#20796d');navy=colors.HexColor('#182832');ink=colors.HexColor('#273644');pale=colors.HexColor('#eff5f3')
    def p(v,style='BodyText'):return Paragraph(html.escape(str(v)),styles[style])
    doc=SimpleDocTemplate(b,pagesize=A4,leftMargin=42,rightMargin=42,topMargin=49,bottomMargin=45,title=report['title'],author='SEDRA')
    x=report['snapshot'];m=x['metrics'];window=x['window'];story=[p('SEDRA / SECURITY INTELLIGENCE','Heading3'),p(report['title'],'Title'),p('Observed operations. Evidence, decisions and actions for leadership.','Note'),Spacer(1,16)]
    dates=datetime.fromtimestamp(window['start'],TZ).strftime('%d %b %Y %H:%M')+' to '+datetime.fromtimestamp(window['end'],TZ).strftime('%d %b %Y %H:%M')+' AZT'
    story.extend([p(dates,'Note'),p('Scope: '+x['scope']['label'],'Note'),Spacer(1,17)])
    cells=[]
    for label,key in [('Transfer attempts','attempts'),('Blocked attempts','blocked'),('Confirmed deliveries','confirmed'),('Unconfirmed deliveries','unconfirmed'),('Active identities','active_identities'),('High-priority identities (live)','high_priority_identities')]:
        cells.append([p(str(m[key]),'Heading1'),p(label,'Note')])
    grid=Table([[Table([[v] for v in cells[i]],colWidths=[154]),Table([[v] for v in cells[i+1]],colWidths=[154]),Table([[v] for v in cells[i+2]],colWidths=[154])] for i in (0,3)],colWidths=[170]*3,hAlign='LEFT')
    grid.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),pale),('BOX',(0,0),(-1,-1),.5,colors.HexColor('#d7e3df')),('INNERGRID',(0,0),(-1,-1),.5,colors.white),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),9),('TOPPADDING',(0,0),(-1,-1),9),('BOTTOMPADDING',(0,0),(-1,-1),9)]));story.extend([grid,Spacer(1,20),p('Delivery outcomes','Heading2')])
    chart=Drawing(505,100);top=max(1,m['attempts'])
    for i,(label,key,color) in enumerate([('Blocked','blocked','#20796d'),('Confirmed','confirmed','#486587'),('Unconfirmed','unconfirmed','#b98634')]):
        y=78-i*30;chart.add(String(0,y+4,label,fontName='Helvetica',fontSize=9,fillColor=ink));chart.add(Rect(105,y,330,15,fillColor=colors.HexColor('#eef1f3'),strokeColor=None));chart.add(Rect(105,y,330*m[key]/top,15,fillColor=colors.HexColor(color),strokeColor=None));chart.add(String(450,y+4,str(m[key]),fontSize=10,fillColor=ink))
    story.extend([chart,p('Counts describe recorded gateway attempts. Other retained states: '+str(m['other_states'])+'. These are not breaches or financial losses avoided.','Note'),Spacer(1,14),p('Recommended actions','Heading2')])
    story.extend(p(str(i+1)+'. '+a) for i,a in enumerate(x['recommended_actions']))
    story.extend([Spacer(1,13),p('Current case queue: '+str(x['cases']['open'])+' open, '+str(x['cases']['in_review'])+' in review, '+str(x['cases']['resolved'])+' resolved. These statuses are retained independently of live signal expiry.','Note'),PageBreak(),p('Evidence and coverage','Heading1')])
    rows=[[p('Observed source','Heading4'),p('Status and limits','Heading4')]]+[[p(c['name']),p(c['state']+' - '+c['note'],'Note')] for c in x['coverage']]
    table=Table(rows,colWidths=[155,355],repeatRows=1,hAlign='LEFT');table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),pale),('GRID',(0,0),(-1,-1),.4,colors.HexColor('#dbe3e7')),('VALIGN',(0,0),(-1,-1),'TOP'),('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)]));story.extend([table,Spacer(1,16),p('Top sensitive-pattern detections','Heading2')])
    if x['detectors']:
        for r in x['detectors']:story.append(p(r['name'].replace('_',' ')+' - '+str(r['count'])+' request(s)','Note'))
    else:story.append(p('No supported sensitive-pattern detections in the sampled detail rows.','Note'))
    if report['template']=='security':
        story.extend([Spacer(1,14),p('Destination review','Heading2')])
        for r in x['routes']:story.append(p(r['route']+' - '+str(r['attempts'])+' attempts, '+str(r['blocked'])+' blocked','Note'))
        if not x['routes']:story.append(p('No destination activity recorded in this window.','Note'))
        story.append(p('Current observed high-priority identities','Heading2'))
        for r in x['high_priority']:story.append(p(r['subject_id']+' - '+str(r['live_priority'])+'/100; '+', '.join(r['active_rules']),'Note'))
        if not x['high_priority']:story.append(p('No current qualifying live rule above the review threshold.','Note'))
    elif report['template']=='activity':
        story.extend([Spacer(1,14),p('Daily gateway activity (AZT)','Heading2')])
        for r in x['trend']:story.append(p(r['day']+' - '+str(r['attempts'])+' attempts, '+str(r['blocked'])+' blocked, '+str(r['confirmed'])+' confirmed','Note'))
        if not x['trend']:story.append(p('No gateway attempts recorded in this window.','Note'))
    story.extend([Spacer(1,14),p('Interpretation and integrity','Heading2')]);story.extend(p('- '+s,'Note') for s in x['definitions']);story.extend([Spacer(1,12),p('Snapshot SHA-256: '+report['sha256'],'Note'),p('Report ID: '+report['id'],'Note'),p('The digest checks this local snapshot; it is not an independent attestation or protection against an operating-system administrator.','Note')])
    def frame(c,d):
        c.setFillColor(teal);c.rect(0,A4[1]-8,A4[0],8,fill=1,stroke=0);c.setFont('Helvetica',8);c.setFillColor(ink);c.drawString(42,26,'SEDRA | Private operational report');c.drawRightString(A4[0]-42,26,'Page '+str(d.page))
    doc.build(story,onFirstPage=frame,onLaterPages=frame);return b.getvalue()
