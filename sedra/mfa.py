"""Mandatory local-account TOTP with sealed seeds, one-use recovery and replay protection."""
import base64,ctypes,hashlib,hmac,io,json,os,re,secrets,sqlite3,struct,time,urllib.parse
from pathlib import Path
from contextlib import closing
from cryptography.fernet import Fernet


def totp(seed,at=None,digits=6):
    counter=int((time.time() if at is None else at)//30)
    raw=hmac.new(base64.b32decode(seed),struct.pack('>Q',counter),hashlib.sha1).digest()
    offset=raw[-1]&15
    return str((struct.unpack('>I',raw[offset:offset+4])[0]&0x7fffffff)%(10**digits)).zfill(digits)


def protect(data,decrypt=False):
    """Windows DPAPI user scope; portable key file mode 0600 on other hosts."""
    class Blob(ctypes.Structure):
        _fields_=[('size',ctypes.c_ulong),('data',ctypes.POINTER(ctypes.c_ubyte))]
    buffer=ctypes.create_string_buffer(data);source=Blob(len(data),ctypes.cast(buffer,ctypes.POINTER(ctypes.c_ubyte)));target=Blob()
    if decrypt:ok=ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(source),None,None,None,None,1,ctypes.byref(target))
    else:ok=ctypes.windll.crypt32.CryptProtectData(ctypes.byref(source),None,None,None,None,1,ctypes.byref(target))
    if not ok:raise OSError('MFA key protection failed')
    try:return ctypes.string_at(target.data,target.size)
    finally:ctypes.windll.kernel32.LocalFree(target.data)


class MFA:
    def __init__(self,accounts):
        self.accounts=accounts
        with accounts.db() as c:
            c.executescript('CREATE TABLE IF NOT EXISTS mfa(uid TEXT PRIMARY KEY,seed BLOB NOT NULL,last_counter INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS mfa_recovery(uid TEXT,hash TEXT,used INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(uid,hash)); CREATE TABLE IF NOT EXISTS mfa_attempts(uid TEXT,at REAL);')
            existing=bool(c.execute('SELECT 1 FROM mfa LIMIT 1').fetchone())
        path=Path(accounts.path+'.mfa.key')
        if not path.exists():
            if existing:raise ValueError('MFA key missing; restore the protected key backup before starting')
            key=Fernet.generate_key();data=b'DPAPI1\n'+protect(key) if os.name=='nt' else b'LOCAL1\n'+key
            try:
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as stream:stream.write(data)
            except FileExistsError:pass
        data=path.read_bytes()
        if data.startswith(b'DPAPI1\n'):
            if os.name!='nt':raise ValueError('Windows-protected MFA key requires its original Windows identity')
            key=protect(data[7:],True)
        elif data.startswith(b'LOCAL1\n') and os.name!='nt':key=data[7:]
        else:raise ValueError('Unsupported MFA key protection')
        self.cipher=Fernet(key)

    def status(self,uid):
        with self.accounts.db() as c:
            enabled=bool(c.execute('SELECT 1 FROM mfa WHERE uid=?',(uid,)).fetchone())
            remaining=c.execute('SELECT count(*) FROM mfa_recovery WHERE uid=? AND used=0',(uid,)).fetchone()[0]
        return {'required':True,'enrolled':enabled,'recovery_codes_remaining':remaining}

    def seed(self,uid):
        # Internal use only. No endpoint returns an enrolled authenticator seed.
        with self.accounts.db() as c:r=c.execute('SELECT seed FROM mfa WHERE uid=?',(uid,)).fetchone()
        return self.cipher.decrypt(bytes(r['seed'])).decode() if r else None

    def enrollment(self,username):
        seed=base64.b32encode(secrets.token_bytes(20)).decode()
        uri='otpauth://totp/'+urllib.parse.quote('SEDRA:'+username,safe='')+'?'+urllib.parse.urlencode({'secret':seed,'issuer':'SEDRA','algorithm':'SHA1','digits':6,'period':30})
        import qrcode,qrcode.image.svg
        qr=qrcode.make(uri,image_factory=qrcode.image.svg.SvgPathImage,box_size=5,border=4)
        stream=io.BytesIO();qr.save(stream)
        return {'secret':seed,'uri':uri,'qr_data_url':'data:image/svg+xml;base64,'+base64.b64encode(stream.getvalue()).decode()}

    def verify(self,uid,version,code,*,enrollment_seed=None,now=None):
        now=time.time() if now is None else now
        if not isinstance(code,str) or not 6<=len(code)<=64:raise PermissionError('Valid authenticator or recovery code required')
        code=code.strip();error=None;recovery=None
        with self.accounts.db() as c:
            c.execute('BEGIN IMMEDIATE')
            user=c.execute('SELECT active,auth_version FROM users WHERE id=?',(uid,)).fetchone()
            if not user or not user['active'] or user['auth_version']!=version:raise PermissionError('Account changed; restart sign-in')
            c.execute('DELETE FROM mfa_attempts WHERE at<?',(now-300,))
            if c.execute('SELECT count(*) FROM mfa_attempts WHERE uid=?',(uid,)).fetchone()[0]>=5:raise PermissionError('MFA temporarily limited; restart sign-in after five minutes')
            c.execute('INSERT INTO mfa_attempts VALUES(?,?)',(uid,now))
            row=c.execute('SELECT * FROM mfa WHERE uid=?',(uid,)).fetchone()
            if row and enrollment_seed is not None:raise PermissionError('Authenticator already registered; restart sign-in')
            seed=self.cipher.decrypt(bytes(row['seed'])).decode() if row else enrollment_seed
            if not seed:raise PermissionError('Authenticator enrollment required')
            counter=int(now//30);last=row['last_counter'] if row else -1;matched=None
            if re.fullmatch(r'[0-9]{6}',code):
                for candidate in (counter-1,counter,counter+1):
                    if candidate>=0 and candidate>last and hmac.compare_digest(totp(seed,candidate*30),code):matched=candidate;break
            recovered=False
            if row and matched is None:
                hashed=hashlib.sha256(code.upper().replace('-','').encode()).hexdigest()
                recovered=c.execute('UPDATE mfa_recovery SET used=1 WHERE uid=? AND hash=? AND used=0',(uid,hashed)).rowcount==1
            if matched is None and not recovered:error='Invalid, expired or already used MFA code'
            elif row:
                if matched is not None:c.execute('UPDATE mfa SET last_counter=? WHERE uid=?',(matched,uid))
            else:
                c.execute('INSERT INTO mfa VALUES(?,?,?)',(uid,self.cipher.encrypt(seed.encode()),matched))
                c.execute('UPDATE users SET auth_version=auth_version+1 WHERE id=?',(uid,))
                recovery=[secrets.token_hex(8).upper() for _ in range(10)]
                c.executemany('INSERT INTO mfa_recovery(uid,hash) VALUES(?,?)',[(uid,hashlib.sha256(x.encode()).hexdigest()) for x in recovery])
        if error:raise PermissionError(error)
        return {'claims':self.accounts.claims(uid),'recovery_codes':recovery or [],'used_recovery':recovered}
