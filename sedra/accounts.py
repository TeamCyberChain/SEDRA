"""Local accounts with persisted RBAC profiles; no default password."""
import hashlib,hmac,json,re,secrets,sqlite3,time
from contextlib import contextmanager
BASES={'administrator','analyst','user'}
class Accounts:
 def __init__(self,path):
  self.path=str(path)
  with self.db() as c:
   c.executescript("CREATE TABLE IF NOT EXISTS roles(id TEXT PRIMARY KEY,name TEXT UNIQUE,base TEXT NOT NULL); CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT UNIQUE,role_id TEXT,subject TEXT,salt TEXT,hash TEXT,active INTEGER); CREATE TABLE IF NOT EXISTS login_attempts(at REAL,identity TEXT);")
   for base in BASES:c.execute('INSERT OR IGNORE INTO roles VALUES(?,?,?)',(base,base.title(),base))
 @contextmanager
 def db(self):
  c=sqlite3.connect(self.path,timeout=10);c.row_factory=sqlite3.Row
  try:
   with c:yield c
  finally:c.close()
 @property
 def enabled(self):
  with self.db() as c:return bool(c.execute('SELECT 1 FROM users LIMIT 1').fetchone())
 def password(self,value,salt):
  if not isinstance(value,str) or not 12<=len(value)<=256:raise ValueError('Password must contain 12–256 characters')
  return hashlib.pbkdf2_hmac('sha256',value.encode(),bytes.fromhex(salt),600000).hex()
 def claims(self,uid):
  with self.db() as c:r=c.execute('SELECT u.id,u.username,u.subject,u.active,r.name,r.base FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?',(uid,)).fetchone()
  if not r or not r['active']:return None
  return {'account_id':r['id'],'username':r['username'],'account_role':r['name'],'access_profile':r['base'],'role':'employee' if r['base']=='user' else 'analyst','subject_id':r['subject'] if r['base']=='user' else None,'principal':'account:'+r['id'],'can_manage_users':r['base']=='administrator'}
 def listing(self):
  with self.db() as c:return {'roles':[dict(r) for r in c.execute('SELECT * FROM roles ORDER BY name')],'users':[dict(r) for r in c.execute('SELECT u.id,u.username,u.role_id,u.subject,u.active,r.name role_name,r.base FROM users u JOIN roles r ON u.role_id=r.id ORDER BY username')]}
 def create_role(self,b):
  if set(b)!={'name','base'} or not isinstance(b['name'],str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9 _-]{1,49}',b['name']) or not isinstance(b['base'],str) or b['base'] not in BASES:raise ValueError('Role name and supported access profile required')
  uid=secrets.token_hex(12)
  try:
   with self.db() as c:c.execute('INSERT INTO roles VALUES(?,?,?)',(uid,b['name'],b['base']))
  except sqlite3.IntegrityError:raise ValueError('Role name already exists') from None
  return uid
 def create_user(self,b,known,bootstrap=False):
  if set(b)!={'username','password','role_id','subject'} or not isinstance(b['username'],str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{2,63}',b['username']):raise ValueError('Username: 3–64 letters, digits, dot, underscore or dash')
  if any(not isinstance(b[k],str) or len(b[k])>100 for k in ('role_id','subject')):raise ValueError('Bounded role and subject identifiers required')
  salt=secrets.token_hex(16);digest=self.password(b['password'],salt);uid=secrets.token_hex(12)
  try:
   with self.db() as c:
    c.execute('BEGIN IMMEDIATE')
    if bootstrap and c.execute('SELECT 1 FROM users LIMIT 1').fetchone():raise PermissionError('Administrator already initialized')
    role=c.execute('SELECT * FROM roles WHERE id=?',(b['role_id'],)).fetchone()
    if not role or (bootstrap and role['base']!='administrator'):raise ValueError('Valid role required')
    if role['base']=='user' and b['subject'] not in known:raise ValueError('User account requires a known UEBA subject binding')
    c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,1)',(uid,b['username'].lower(),b['role_id'],b['subject'] if role['base']=='user' else None,salt,digest))
  except sqlite3.IntegrityError:raise ValueError('Username already exists') from None
  return uid
 def update_user(self,b,known):
  if set(b)!={'id','role_id','subject','active'} or type(b['active']) is not bool:raise ValueError('Closed account update schema required')
  if any(not isinstance(b[k],str) or len(b[k])>100 for k in ('id','role_id','subject')):raise ValueError('Bounded account identifiers required')
  with self.db() as c:
   c.execute('BEGIN IMMEDIATE');old=c.execute('SELECT u.*,r.base FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?',(b['id'],)).fetchone();role=c.execute('SELECT * FROM roles WHERE id=?',(b['role_id'],)).fetchone()
   if not old or not role:raise ValueError('Known account and role required')
   if role['base']=='user' and b['subject'] not in known:raise ValueError('Known UEBA subject required')
   count=c.execute("SELECT COUNT(*) FROM users u JOIN roles r ON u.role_id=r.id WHERE u.active=1 AND r.base='administrator'").fetchone()[0]
   if old['active'] and old['base']=='administrator' and (not b['active'] or role['base']!='administrator') and count<=1:raise ValueError('The last active Administrator cannot be disabled or demoted')
   c.execute('UPDATE users SET role_id=?,subject=?,active=? WHERE id=?',(b['role_id'],b['subject'] if role['base']=='user' else None,int(b['active']),b['id']))
 def login(self,b):
  if set(b)!={'username','password'} or not isinstance(b['username'],str) or not isinstance(b['password'],str) or len(b['username'])>64 or len(b['password'])>256:raise PermissionError('Invalid username or password')
  identity=hashlib.sha256(b['username'].lower().encode()).hexdigest();now=time.time()
  with self.db() as c:
   c.execute('BEGIN IMMEDIATE');c.execute('DELETE FROM login_attempts WHERE at<?',(now-60,))
   if c.execute('SELECT COUNT(*) FROM login_attempts WHERE identity=?',(identity,)).fetchone()[0]>=5 or c.execute('SELECT COUNT(*) FROM login_attempts').fetchone()[0]>=30:raise PermissionError('Sign-in temporarily limited; try again in one minute')
   c.execute('INSERT INTO login_attempts VALUES(?,?)',(now,identity));r=c.execute('SELECT * FROM users WHERE username=?',(b['username'].lower(),)).fetchone()
  salt=r['salt'] if r else '00'*16
  # Same work for unknown accounts; password never appears in an error/audit record.
  digest=hashlib.pbkdf2_hmac('sha256',b['password'].encode(),bytes.fromhex(salt),600000).hex()
  if not r or not r['active'] or not hmac.compare_digest(digest,r['hash']):raise PermissionError('Invalid username or password')
  return r['id']
