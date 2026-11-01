"""Local accounts with persisted RBAC profiles; no default password."""
import hashlib,hmac,json,re,secrets,sqlite3,time
from contextlib import contextmanager
BASES={'administrator','analyst','user'}
ACCOUNT_PERMISSIONS={'accounts.read','accounts.create','accounts.update','accounts.reset_password'}
class Accounts:
 def __init__(self,path):
  self.path=str(path)
  with self.db() as c:
   c.executescript("CREATE TABLE IF NOT EXISTS roles(id TEXT PRIMARY KEY,name TEXT UNIQUE,base TEXT NOT NULL); CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT UNIQUE,role_id TEXT,subject TEXT,salt TEXT,hash TEXT,active INTEGER); CREATE TABLE IF NOT EXISTS login_attempts(at REAL,identity TEXT);")
   if 'permissions' not in {r['name'] for r in c.execute('PRAGMA table_info(roles)')}:c.execute("ALTER TABLE roles ADD COLUMN permissions TEXT NOT NULL DEFAULT '[]'")
   if 'auth_version' not in {r['name'] for r in c.execute('PRAGMA table_info(users)')}:c.execute('ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0')
   for base in BASES:c.execute('INSERT OR IGNORE INTO roles(id,name,base) VALUES(?,?,?)',(base,base.title(),base))
  from .mfa import MFA
  self.mfa=MFA(self)
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
  with self.db() as c:r=c.execute('SELECT u.id,u.username,u.subject,u.active,u.auth_version,r.name,r.base,r.permissions FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?',(uid,)).fetchone()
  if not r or not r['active']:return None
  permissions=sorted(ACCOUNT_PERMISSIONS|{'roles.manage'}) if r['base']=='administrator' else json.loads(r['permissions'])
  return {'account_id':r['id'],'auth_version':r['auth_version'],'username':r['username'],'account_role':r['name'],'access_profile':r['base'],'role':'employee' if r['base']=='user' else 'analyst','subject_id':r['subject'] if r['base']=='user' else None,'principal':'account:'+r['id'],'permissions':permissions,'can_manage_users':'accounts.read' in permissions,'can_manage_roles':r['base']=='administrator'}
 def listing(self):
  with self.db() as c:
   roles=[dict(r) for r in c.execute('SELECT * FROM roles ORDER BY name')]
   for r in roles:r['permissions']=sorted(ACCOUNT_PERMISSIONS|{'roles.manage'}) if r['base']=='administrator' else json.loads(r['permissions']);r['builtin']=r['id'] in BASES
   return {'roles':roles,'permission_catalog':sorted(ACCOUNT_PERMISSIONS),'users':[dict(r) for r in c.execute('SELECT u.id,u.username,u.role_id,u.subject,u.active,r.name role_name,r.base,EXISTS(SELECT 1 FROM mfa WHERE uid=u.id) mfa_enrolled FROM users u JOIN roles r ON u.role_id=r.id ORDER BY username')]}
 def create_role(self,b):
  update=b.get('action')=='update'
  expected={'action','id','name','permissions'} if update else {'name','base'}
  if not update and 'permissions' in b:expected.add('permissions')
  if set(b)!=expected or not isinstance(b.get('name'),str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9 _-]{1,49}',b['name']):raise ValueError('Role name and closed role schema required')
  perms=b.get('permissions',[])
  if not isinstance(perms,list) or len(perms)>len(ACCOUNT_PERMISSIONS) or any(not isinstance(p,str) or p not in ACCOUNT_PERMISSIONS for p in perms) or len(set(perms))!=len(perms):raise ValueError('Supported unique account permissions required')
  if perms and 'accounts.read' not in perms:raise ValueError('Account actions require accounts.read')
  uid=secrets.token_hex(12)
  try:
   with self.db() as c:
    if update:
     if not isinstance(b['id'],str) or b['id'] in BASES:raise ValueError('Built-in roles cannot be edited')
     old=c.execute('SELECT * FROM roles WHERE id=?',(b['id'],)).fetchone()
     if not old:raise ValueError('Known role required')
     base=old['base'];uid=b['id']
    else:base=b.get('base')
    if not isinstance(base,str) or base not in BASES:raise ValueError('Supported access profile required')
    if perms and base!='analyst':raise ValueError('Delegated account permissions require an Analyst access profile')
    if update:c.execute('UPDATE roles SET name=?,permissions=? WHERE id=?',(b['name'],json.dumps(sorted(perms)),uid))
    else:c.execute('INSERT INTO roles(id,name,base,permissions) VALUES(?,?,?,?)',(uid,b['name'],base,json.dumps(sorted(perms))))
  except sqlite3.IntegrityError:raise ValueError('Role name already exists') from None
  return uid
 def authorize_target(self,c,actor,permission,target=None,role=None):
  if actor is None:return  # Trusted bootstrap/test provisioning, never an HTTP caller.
  if permission not in actor.get('permissions',[]):raise PermissionError('Account permission required: '+permission)
  if actor.get('access_profile')=='administrator':return
  if target and (target['id']==actor['account_id'] or target['base']=='administrator' or json.loads(target['permissions'])):raise PermissionError('Delegated operators cannot modify themselves or privileged accounts')
  if role and (role['base']=='administrator' or json.loads(role['permissions'])):raise PermissionError('Only Administrators can assign privileged roles')
 def create_user(self,b,known,bootstrap=False,actor=None):
  if set(b)!={'username','password','role_id','subject'} or not isinstance(b['username'],str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{2,63}',b['username']):raise ValueError('Username: 3–64 letters, digits, dot, underscore or dash')
  if any(not isinstance(b[k],str) or len(b[k])>100 for k in ('role_id','subject')):raise ValueError('Bounded role and subject identifiers required')
  salt=secrets.token_hex(16);digest=self.password(b['password'],salt);uid=secrets.token_hex(12)
  try:
   with self.db() as c:
    c.execute('BEGIN IMMEDIATE')
    if bootstrap and c.execute('SELECT 1 FROM users LIMIT 1').fetchone():raise PermissionError('Administrator already initialized')
    role=c.execute('SELECT * FROM roles WHERE id=?',(b['role_id'],)).fetchone()
    if not role or (bootstrap and role['base']!='administrator'):raise ValueError('Valid role required')
    self.authorize_target(c,actor,'accounts.create',role=role)
    if role['base']=='user' and b['subject'] not in known:raise ValueError('User account requires a known UEBA subject binding')
    c.execute('INSERT INTO users(id,username,role_id,subject,salt,hash,active) VALUES(?,?,?,?,?,?,1)',(uid,b['username'].lower(),b['role_id'],b['subject'] if role['base']=='user' else None,salt,digest))
  except sqlite3.IntegrityError:raise ValueError('Username already exists') from None
  return uid
 def update_user(self,b,known,actor=None):
  if set(b)!={'id','role_id','subject','active'} or type(b['active']) is not bool:raise ValueError('Closed account update schema required')
  if any(not isinstance(b[k],str) or len(b[k])>100 for k in ('id','role_id','subject')):raise ValueError('Bounded account identifiers required')
  with self.db() as c:
   c.execute('BEGIN IMMEDIATE');old=c.execute('SELECT u.*,r.base,r.permissions FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?',(b['id'],)).fetchone();role=c.execute('SELECT * FROM roles WHERE id=?',(b['role_id'],)).fetchone()
   if not old or not role:raise ValueError('Known account and role required')
   self.authorize_target(c,actor,'accounts.update',target=old,role=role)
   if role['base']=='user' and b['subject'] not in known:raise ValueError('Known UEBA subject required')
   count=c.execute("SELECT COUNT(*) FROM users u JOIN roles r ON u.role_id=r.id WHERE u.active=1 AND r.base='administrator'").fetchone()[0]
   if old['active'] and old['base']=='administrator' and (not b['active'] or role['base']!='administrator') and count<=1:raise ValueError('The last active Administrator cannot be disabled or demoted')
   c.execute('UPDATE users SET role_id=?,subject=?,active=?,auth_version=auth_version+? WHERE id=?',(b['role_id'],b['subject'] if role['base']=='user' else None,int(b['active']),int(bool(old['active'])!=b['active']),b['id']))
 def reset_password(self,b,actor):
  if set(b)!={'id','password'} or not isinstance(b['id'],str) or len(b['id'])>100:raise ValueError('Account ID and new password required')
  salt=secrets.token_hex(16);digest=self.password(b['password'],salt)
  with self.db() as c:
   c.execute('BEGIN IMMEDIATE');target=c.execute('SELECT u.id,r.base,r.permissions FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?',(b['id'],)).fetchone()
   if not target:raise ValueError('Known account required')
   self.authorize_target(c,actor,'accounts.reset_password',target=target)
   c.execute('UPDATE users SET salt=?,hash=?,auth_version=auth_version+1 WHERE id=?',(salt,digest,b['id']))
 def login(self,b,with_claims=False):
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
  claims=self.claims(r['id'])
  if not claims or claims['auth_version']!=r['auth_version']:raise PermissionError('Account changed during sign-in; try again')
  # A reset after this read leaves an old-version session, rejected on its next request.
  return claims if with_claims else r['id']
