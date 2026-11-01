"""Owner-scoped dashboard layouts. Widgets select bounded observed aggregates only."""
import json,re,secrets,sqlite3,time
from contextlib import contextmanager

class DashboardConflict(Exception):pass

METRICS={'attempts':'Transfer attempts','blocked':'Stopped by policy','confirmed':'Confirmed deliveries','unconfirmed':'Unconfirmed deliveries','active_identities':'Active identities','high_priority_identities':'High live priority','document_accesses':'Application document accesses','registered_sources':'Registered sources'}
WIDGETS={'kpi':'Metric card','trend':'Daily activity','detectors':'Sensitive-pattern detections','routes':'Destinations','classifications':'Classification snapshots','cases':'Case review status','coverage':'Source coverage','actions':'Recommended actions'}

def actor(session):
    if session.get('role')!='analyst':raise PermissionError('Analyst access required')
    return session.get('principal') or 'analyst'

def text(value,maximum,empty=False):
    if not isinstance(value,str) or len(value)>maximum or any(ord(c)<32 for c in value) or (not empty and not value.strip()):raise ValueError('Bounded plain-text dashboard labels required')
    return value.strip()

class Dashboards:
    def __init__(self,path):
        self.path=str(path)
        with self.db() as c:
            c.execute('CREATE TABLE IF NOT EXISTS dashboards(id TEXT PRIMARY KEY,owner TEXT NOT NULL,name TEXT NOT NULL,description TEXT NOT NULL,days INTEGER NOT NULL,widgets TEXT NOT NULL,revision INTEGER NOT NULL,archived INTEGER NOT NULL,created REAL NOT NULL,updated REAL NOT NULL)')
            c.execute('CREATE INDEX IF NOT EXISTS dashboard_owner ON dashboards(owner,archived)')
    @contextmanager
    def db(self):
        c=sqlite3.connect(self.path,timeout=10);c.row_factory=sqlite3.Row
        try:
            with c:yield c
        finally:c.close()
    @staticmethod
    def decode(row):
        return {k:row[k] for k in ('id','name','description','days','revision','archived','created','updated')}|{'widgets':json.loads(row['widgets'])}
    def listing(self,session,archived=False):
        owner=actor(session)
        with self.db() as c:return [self.decode(r) for r in c.execute('SELECT * FROM dashboards WHERE owner=? AND archived=? ORDER BY created,id',(owner,int(archived)))]
    def save(self,session,b):
        owner=actor(session);action=b.get('action')
        if action not in ('create','update','archive','restore'):raise ValueError('Supported dashboard action required')
        expected={'action','name','description','days','widgets'} if action=='create' else {'action','id','expected_revision'}|({'name','description','days','widgets'} if action=='update' else set())
        if set(b)!=expected:raise ValueError('Closed dashboard schema required')
        if action!='create' and (not isinstance(b['id'],str) or not re.fullmatch('[0-9a-f]{32}',b['id']) or type(b['expected_revision']) is not int or b['expected_revision']<1):raise ValueError('Valid dashboard ID and revision required')
        if action in ('create','update'):
            name=text(b['name'],60);description=text(b['description'],240,True)
            if type(b['days']) is not int or b['days'] not in (1,7,30):raise ValueError('Choose 1, 7 or 30 days')
            if not isinstance(b['widgets'],list) or len(b['widgets'])>16:raise ValueError('At most 16 widgets per dashboard')
            widgets=[];ids=set()
            for w in b['widgets']:
                if not isinstance(w,dict) or not isinstance(w.get('type'),str) or w['type'] not in WIDGETS:raise ValueError('Supported widget type required')
                keys={'id','type','title','width'}|({'metric'} if w['type']=='kpi' else set())
                if set(w)!=keys or not isinstance(w['id'],str) or not re.fullmatch('[0-9a-f]{12}',w['id']) or w['id'] in ids or w['width'] not in ('half','full'):raise ValueError('Unique widget IDs and bounded layout required')
                if w['type']=='kpi' and (not isinstance(w['metric'],str) or w['metric'] not in METRICS):raise ValueError('Supported observed metric required')
                ids.add(w['id']);widgets.append(w|{'title':text(w['title'],70)})
        now=time.time();uid=secrets.token_hex(16) if action=='create' else b['id']
        with self.db() as c:
            c.execute('BEGIN IMMEDIATE')
            if action=='create' and c.execute('SELECT count(*) FROM dashboards WHERE owner=?',(owner,)).fetchone()[0]>=100:raise ValueError('At most 100 saved dashboards including archived layouts')
            if action in ('create','restore') and c.execute('SELECT count(*) FROM dashboards WHERE owner=? AND archived=0',(owner,)).fetchone()[0]>=20:raise ValueError('At most 20 active saved dashboards')
            if action=='create':c.execute('INSERT INTO dashboards VALUES(?,?,?,?,?,?,1,0,?,?)',(uid,owner,name,description,b['days'],json.dumps(widgets),now,now))
            else:
                row=c.execute('SELECT * FROM dashboards WHERE id=? AND owner=?',(uid,owner)).fetchone()
                if not row:raise KeyError('Dashboard not available in this account')
                if row['revision']!=b['expected_revision']:raise DashboardConflict('Dashboard changed in another window. Reload the saved version before retrying.')
                if action=='update':
                    if row['archived']:raise DashboardConflict('Restore the dashboard before editing')
                    c.execute('UPDATE dashboards SET name=?,description=?,days=?,widgets=?,revision=revision+1,updated=? WHERE id=?',(name,description,b['days'],json.dumps(widgets),now,uid))
                else:
                    archived=int(action=='archive')
                    if row['archived']==archived:raise DashboardConflict('Dashboard status already changed; refresh the list')
                    c.execute('UPDATE dashboards SET archived=?,revision=revision+1,updated=? WHERE id=?',(archived,now,uid))
            return self.decode(c.execute('SELECT * FROM dashboards WHERE id=?',(uid,)).fetchone())
