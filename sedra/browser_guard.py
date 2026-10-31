"""Scoped browser policy inspection; never sends data to an AI provider.

Page enforcement is reported by an authenticated extension, not independently
attested. Allowed releases remain delivery-unknown and counted conservatively.
"""
import base64
import binascii
from contextlib import closing
from hashlib import sha256
from io import BytesIO
from pathlib import PurePosixPath
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
import zipfile

AI_HOSTS={'gemini.google.com','chatgpt.com','chat.openai.com','claude.ai'}
EXTENSION_ORIGIN='chrome-extension://akncbelkcijoipfcfnhpcaajcfagkijm'
TEXT_SUFFIXES={'.txt','.md','.csv','.tsv','.json','.xml','.yaml','.yml','.log','.ini','.cfg','.py','.js','.sql'}
MAX_FILE=512*1024
MAX_TEXT=65536
FAILURES={'FILE_TOO_LARGE','UNSUPPORTED_FILE','LOCAL_INSPECTION_FAILED','BACKEND_UNAVAILABLE','UNSUPPORTED_COMPOSER'}


class InspectionFailure(ValueError):pass


def extract_file(name,raw):
    """Bounded UTF text / OOXML only. Unknown, encrypted and embedded content blocks."""
    suffix=PurePosixPath(name.lower()).suffix
    if len(raw)>MAX_FILE:raise InspectionFailure('FILE_TOO_LARGE')
    if suffix in TEXT_SUFFIXES:
        if raw.startswith((b'PK',b'%PDF',b'\x89PNG',b'\xff\xd8')):raise InspectionFailure('UNSUPPORTED_FILE')
        try:
            text=raw.decode('utf-16') if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else raw.decode('utf-8-sig')
        except UnicodeError:raise InspectionFailure('UNSUPPORTED_FILE') from None
        if '\x00' in text or any(ord(c)<32 and c not in '\r\n\t' for c in text):raise InspectionFailure('UNSUPPORTED_FILE')
    elif suffix in {'.docx','.xlsx'}:
        try:
            with zipfile.ZipFile(BytesIO(raw)) as archive:
                members=archive.infolist()
                if len(members)>256 or sum(m.file_size for m in members)>4*1024*1024:raise InspectionFailure('FILE_TOO_LARGE')
                required='word/document.xml' if suffix=='.docx' else 'xl/workbook.xml'
                if required not in archive.namelist():raise InspectionFailure('UNSUPPORTED_FILE')
                texts=[]
                for m in members:
                    p=PurePosixPath(m.filename)
                    if p.is_absolute() or '..' in p.parts or ':' in m.filename or '\\' in m.filename:raise InspectionFailure('UNSUPPORTED_FILE')
                    if m.is_dir():continue
                    if m.flag_bits&1 or m.file_size>512*1024 or m.file_size>100*max(1,m.compress_size):raise InspectionFailure('UNSUPPORTED_FILE')
                    if not m.filename.endswith(('.xml','.rels')):raise InspectionFailure('UNSUPPORTED_FILE')
                    source=archive.read(m).decode('utf-8-sig')
                    if re.search(r'<!\s*(?:DOCTYPE|ENTITY)',source,re.I):raise InspectionFailure('UNSUPPORTED_FILE')
                    root=ET.fromstring(source)
                    # Preserve words split across Word text runs; keep paragraph boundaries.
                    if suffix=='.docx' and m.filename.startswith('word/'):
                        paragraphs=list(root.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'))
                        texts.extend(''.join(n.text or '' for n in p.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t')) for p in paragraphs)
                    else:texts.extend(t for t in root.itertext() if t.strip())
                    texts.extend(v for n in root.iter() for v in n.attrib.values())
                    if sum(len(t.encode('utf-8')) for t in texts)>MAX_TEXT:raise InspectionFailure('FILE_TOO_LARGE')
                text='\n'.join(texts)
        except InspectionFailure:raise
        except (OSError,ValueError,UnicodeError,ET.ParseError,zipfile.BadZipFile,RuntimeError,NotImplementedError):
            raise InspectionFailure('UNSUPPORTED_FILE') from None
    else:raise InspectionFailure('UNSUPPORTED_FILE')
    if len(text.encode('utf-8'))>MAX_TEXT:raise InspectionFailure('FILE_TOO_LARGE')
    return text


class BrowserGuard:
    def __init__(self,app):
        self.app=app
        self.path=app.data_dir/'browser_lab.sqlite'
        with closing(sqlite3.connect(self.path)) as c,c:
            c.execute('CREATE TABLE IF NOT EXISTS receipts(seq INTEGER PRIMARY KEY,at REAL,sha256 TEXT,utf8_bytes INTEGER,kind TEXT)')

    def inspect(self,body,key,source='AUTHENTICATED_BROWSER_REPORT'):
        if set(body)-{'request_id','host','operation','mode','text','files','failure'}:raise ValueError('Unknown browser fields')
        if len(key['subjects'])!=1:raise PermissionError('Exactly one bound browser subject required')
        host=body.get('host');operation=body.get('operation');mode=body.get('mode')
        if host not in AI_HOSTS|{'sedra-browser-lab'}:raise ValueError('Unsupported AI destination')
        if operation not in {'paste','draft','send','file','drop','offline'} or mode not in {'preview','release'}:raise ValueError('Declared browser operation and mode required')
        if operation in {'draft','paste'} and mode!='preview':raise ValueError('Draft and paste checks cannot release data')
        rid=body.get('request_id')
        if not isinstance(rid,str) or not re.fullmatch(r'br-[A-Za-z0-9_-]{8,96}',rid):raise ValueError('Bounded browser request ID required')
        text=body.get('text','');files=body.get('files',[]);failure=body.get('failure')
        if not isinstance(text,str) or not isinstance(files,list) or len(files)>2:raise ValueError('Text and at most two files required')
        if failure is not None and failure not in FAILURES:raise ValueError('Unknown inspection failure')
        if operation=='offline' and (mode!='preview' or failure!='BACKEND_UNAVAILABLE' or text or files):raise ValueError('Offline reports contain failure metadata only')
        metadata=[];parts=[text]
        if len(text.encode('utf-8'))>MAX_TEXT:failure='FILE_TOO_LARGE';parts=['[Oversized browser prompt]']
        for f in files:
            if not isinstance(f,dict) or set(f)!={'name','data'} or not isinstance(f['name'],str) or len(f['name'])>200 or not isinstance(f['data'],str):raise ValueError('Closed attachment schema required')
            if len(f['data'])>4*((MAX_FILE+2)//3):failure='FILE_TOO_LARGE';continue
            try:raw=base64.b64decode(f['data'],validate=True)
            except (ValueError,binascii.Error):raise ValueError('Strict Base64 attachment encoding required') from None
            item={'suffix':PurePosixPath(f['name'].lower()).suffix,'bytes':len(raw),'sha256':sha256(raw).hexdigest()}
            try:parts.append(extract_file(f['name'],raw));item['inspection']='text_extracted'
            except InspectionFailure as error:failure=str(error);item['inspection']='uninspectable'
            metadata.append(item)
        combined='\n'.join(parts)
        if len(combined.encode('utf-8'))>MAX_TEXT:failure='FILE_TOO_LARGE';combined='[Combined browser payload exceeds inspection bound]'
        # Bind idempotency to attachment bytes and operation as well as extracted text.
        import json
        binding=sha256(json.dumps({'body':body,'source':source},sort_keys=True,allow_nan=False).encode()).hexdigest()
        uid=key['subjects'][0]
        with self.app.guard:
            try:prior=self.app.gateway.get_request(subject_id=uid,request_id=rid)
            except KeyError:prior=None
            if prior and prior.get('behavior_context',{}).get('browser',{}).get('binding')!=binding:raise ValueError('Browser request ID reused with changed facts')
            subject=self.app.live_subject(self.app.subjects[uid])
            context={k:subject[k] for k in ('live_context','model_context','policy_context','endpoint_context')}
            context['browser']={'profile':'sedra-browser-guard-v1','origin':source,'operation':operation,'mode':mode,
                'host':host,'files':metadata,'binding':binding,'inspection_failure':failure,
                'enforcement':'Extension-reported; not independently attested' if source=='AUTHENTICATED_BROWSER_REPORT' else 'Local DOM harness; no installed-extension attestation'}
            verdict=self.app.gateway.evaluate(uid,rid,combined,subject['behavior_score'],destination='browser:'+host,behavior_context=context,
                preview=mode=='preview',inspection_block='BROWSER_'+failure if failure else None)
            if verdict['decision']=='ALLOW' and mode=='release':
                if verdict.get('idempotent_replay'):return {'decision':'BLOCK','reason_codes':['BROWSER_RELEASE_ALREADY_USED'],'request_id':rid,'replay':True}
                self.app.gateway.claim_send(rid,uid)
                verdict=self.app.gateway.mark_unknown(rid,uid)
            if verdict['decision']=='BLOCK' or mode=='release':self.app.capture_case(uid)
            return {'decision':verdict['decision'],'reason_codes':verdict['reason_codes'],'request_id':rid,'state':verdict['state'],
                'behavior_score':verdict['behavior_score'],'finding_types':[f['type'] for f in verdict['structured_findings']],
                'alert_ids':verdict.get('alert_ids',[]),'delivery_confirmed':False,'inspection_failure':failure}

    def lab_receive(self,body):
        if set(body)!={'text','kind'} or not isinstance(body['text'],str) or body['kind'] not in {'prompt','file'}:raise ValueError('Lab text/kind required')
        raw=body['text'].encode('utf-8')
        if len(raw)>MAX_TEXT:raise ValueError('Lab input bound')
        with closing(sqlite3.connect(self.path)) as c,c:
            cur=c.execute('INSERT INTO receipts(at,sha256,utf8_bytes,kind) VALUES(?,?,?,?)',(time.time(),sha256(raw).hexdigest(),len(raw),body['kind']))
            return {'receipt':cur.lastrowid,'sha256':sha256(raw).hexdigest(),'utf8_bytes':len(raw)}

    def lab_receipts(self):
        with closing(sqlite3.connect(self.path)) as c:
            c.row_factory=sqlite3.Row
            return {'items':[dict(r) for r in c.execute('SELECT * FROM receipts ORDER BY seq DESC LIMIT 100')]}
