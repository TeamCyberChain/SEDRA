"""Append-only application audit metadata. Not a privileged-host tamper-proof store."""
import json, sqlite3, time
from contextlib import contextmanager

UI_EVENTS={'navigation','theme_light','theme_dark','control','selection','client_error','page_open'}
CONTROLS={'overview','alerts','investigation','inventory','transfers','integrations','audit','portal','refresh','submit','review','revoke','configure','document','endpoint','filter','identity','other'}
class AuditLog:
 def __init__(self,path):
  self.path=str(path);self.write_failures=0
  with self.db() as c:
   c.execute('CREATE TABLE IF NOT EXISTS platform_audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, source TEXT NOT NULL, actor TEXT NOT NULL, event TEXT NOT NULL, metadata TEXT NOT NULL)')
   c.execute('CREATE INDEX IF NOT EXISTS platform_audit_source_seq ON platform_audit(source,seq)')
 @contextmanager
 def db(self):
  c=sqlite3.connect(self.path,timeout=10);c.row_factory=sqlite3.Row
  try:
   with c:yield c
  finally:c.close()
 def append(self,source,actor,event,metadata):
  try:
   with self.db() as c:c.execute('INSERT INTO platform_audit(at,source,actor,event,metadata) VALUES(?,?,?,?,?)',(time.time(),source,actor,event,json.dumps(metadata,allow_nan=False)))
  except (sqlite3.Error,OSError):self.write_failures+=1
 def ui(self,actor,body):
  if set(body)!={'event','control'} or body['event'] not in UI_EVENTS or body['control'] not in CONTROLS:raise ValueError('Supported metadata-only UI event required')
  with self.db() as c:
   c.execute('BEGIN IMMEDIATE')
   if c.execute("SELECT COUNT(*) FROM platform_audit WHERE source='UI' AND actor=? AND at>=?",(actor,time.time()-60)).fetchone()[0]>=120:raise ValueError('UI reporting limit reached')
   c.execute('INSERT INTO platform_audit(at,source,actor,event,metadata) VALUES(?,?,?,?,?)',(time.time(),'UI',actor,body['event'],json.dumps({'control':body['control'],'provenance':'client_reported'})))
 def page(self,before=None,source='',event='',limit=100):
  if source not in ('','API','HTTP','UI','APPLICATION') or not 1<=limit<=200 or (before is not None and before<1) or len(event)>60:raise ValueError('Invalid audit filter')
  where=[];args=[]
  for clause,value in [('seq < ?',before),('source = ?',source or None),('event = ?',event or None)]:
   if value is not None:where.append(clause);args.append(value)
  sql=' WHERE '+' AND '.join(where) if where else ''
  with self.db() as c:
   total=c.execute('SELECT COUNT(*) FROM platform_audit'+sql,args).fetchone()[0]
   rows=c.execute('SELECT * FROM platform_audit'+sql+' ORDER BY seq DESC LIMIT ?',args+[limit]).fetchall()
  items=[dict(r)|{'metadata':json.loads(r['metadata'])} for r in rows]
  return {'items':items,'matching':total,'next_before':items[-1]['seq'] if len(items)==limit else None,'write_failures_since_start':self.write_failures,'scope':'Server HTTP/API response statuses and application events; UI events are bounded client reports, not independent proof. No headers, query strings, bodies, prompts or key values. Retained across activity reset. Collection starts with this version; historical coverage is not implied.'}
