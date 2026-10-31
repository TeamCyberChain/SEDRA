"""Opt-in local Windows sensor. No remote hosts, arbitrary ingest or OS policy changes."""
from contextlib import contextmanager
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from .ueba import epoch

ROOT=Path(__file__).resolve().parents[1]
ORIGIN='REAL_LOCAL_OBSERVATION'


class EndpointSensor:
    def __init__(self,data_dir):
        self.folder=Path(data_dir)/'endpoint-lab';self.path=Path(data_dir)/'endpoint.sqlite'
        self.lock=threading.RLock();self.stop_event=threading.Event();self.threads=[]
        self.running=False;self.files={};self.probe=None;self.probe_run=None;self.probe_started=None;self.on_change=None
        self.status={'enabled':False,'mapped_subject':'lab-001','identity_binding':'Explicit local test mapping, not enterprise identity',
            'security':'not_collected','session_log':'not_collected','usb':'not_collected','process':'not_collected',
            'files':'not_collected','usb_present':0,'poll_seconds':5,'scope':'Current Windows identity, attached-device metadata, owned child process and endpoint-lab file metadata only'}
        with self.db() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS endpoint_events(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,source_id TEXT NOT NULL,origin TEXT NOT NULL,
                channel TEXT NOT NULL,kind TEXT NOT NULL,at REAL NOT NULL,observed_at REAL NOT NULL,
                detail TEXT NOT NULL, UNIQUE(origin,channel,source_id));
                CREATE INDEX IF NOT EXISTS endpoint_time ON endpoint_events(at);
                CREATE TABLE IF NOT EXISTS endpoint_state(key TEXT PRIMARY KEY,value TEXT NOT NULL);''')
            row=db.execute("SELECT value FROM endpoint_state WHERE key='salt'").fetchone()
            self.salt=row[0] if row else secrets.token_hex(32)
            db.execute("INSERT OR IGNORE INTO endpoint_state VALUES('salt',?)",(self.salt,))

    @contextmanager
    def db(self):
        db=sqlite3.connect(self.path,timeout=10);db.row_factory=sqlite3.Row
        try:
            with db:yield db
        finally:db.close()

    def record(self,source_id,channel,kind,at,detail,*,origin=ORIGIN,now=None):
        now=time.time() if now is None else now;at=epoch(at)
        if at is None or at>now+2 or at<now-8*86400:return False
        if channel not in ('logon','usb','process','file') or origin not in (ORIGIN,'SYNTHETIC_TEST'):raise ValueError('Declared telemetry source required')
        if len(source_id)>200 or len(json.dumps(detail))>4096:raise ValueError('Telemetry metadata bound exceeded')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM endpoint_events WHERE origin=? AND channel=? AND source_id=?',(origin,channel,source_id)).fetchone():return False
            cur=db.execute('INSERT INTO endpoint_events(source_id,origin,channel,kind,at,observed_at,detail) VALUES(?,?,?,?,?,?,?)',
                (source_id,origin,channel,kind,at,now,json.dumps(detail,sort_keys=True)))
            return bool(cur.rowcount)

    def notify_change(self):
        if not self.on_change:return
        try:
            self.on_change()
            with self.lock:self.status['case_capture_error']=None
        except Exception:
            with self.lock:self.status['case_capture_error']='Behavior case capture pending; next observer cycle retries'

    def apply_windows(self,payload,now=None):
        now=time.time() if now is None else now
        changed=False
        for e in payload.get('events',[])[:401]:
            changed=self.record(e['source_id'],e['channel'],e['kind'],e['at'],e['detail'],now=now) or changed
        with self.db() as db:
            previous=db.execute("SELECT value FROM endpoint_state WHERE key='usb'").fetchone()
            saved=json.loads(previous[0]) if previous else None
            usb_available=payload.get('coverage',{}).get('usb')!='unavailable'
            devices=sorted(set(payload.get('usb_devices',[])))[:100] if usb_available else (saved['devices'] if saved else [])
            # First scan / long downtime is a presence baseline, not a new plug event.
            recent=saved and 0<=now-saved['at']<=30 and usb_available
            before=set(saved['devices']) if recent or (saved and not usb_available) else set()
            for device in set(devices)-before:
                changed=self.record('usb:'+device+':'+str(int(now*1000)),'usb','usb_arrival_observed' if recent else 'usb_presence_baseline',now,
                    {'device_fingerprint':device,'method':'CIM presence polling; no drive contents read'},now=now) or changed
            if recent:
                for device in before-set(devices):changed=self.record('usb-left:'+device+':'+str(int(now*1000)),'usb','usb_removal_observed',now,{'device_fingerprint':device},now=now) or changed
            if usb_available:db.execute("INSERT OR REPLACE INTO endpoint_state VALUES('usb',?)",(json.dumps({'at':now,'devices':devices}),))
        # Match only the exact controlled child PID, never let an unrelated process earn a lab signal.
        for p in payload.get('processes',[]):
            created=epoch(p.get('created'))
            if self.probe and self.probe.poll() is None and p['pid']==self.probe.pid and created is not None and self.probe_started is not None and self.probe_started-.05<=created<=now:
                changed=self.record('process:'+str(p['pid'])+':'+p['created'],'process','controlled_process_observed',p['created'],
                    {'pid':p['pid'],'probe_run':self.probe_run,'provider':'Windows CIM Win32_Process','scope':'SEDRA-owned test child'},now=now) or changed
        with self.lock:
            self.status.update(payload.get('coverage',{}));self.status.update({'last_windows_poll':now,'identity_fingerprint':payload.get('identity'),
                'host_fingerprint':payload.get('host_id'),'usb_present':len(devices),'last_error':None,'windows_error':None})
        return changed

    def collect_windows(self):
        if os.name!='nt':
            with self.lock:self.status['last_error']='Windows APIs unavailable on this operating system'
            return
        env=os.environ.copy();env.update({'SEDRA_SENSOR_SALT':self.salt,'SEDRA_SERVER_PID':str(os.getpid())})
        try:
            shell=shutil.which('pwsh.exe') or shutil.which('powershell.exe')
            if not shell:raise OSError('No installed PowerShell executable available')
            result=subprocess.run([shell,'-NoProfile','-NonInteractive','-File',str(ROOT/'scripts/collect_local_endpoint.ps1')],
                capture_output=True,timeout=18,env=env,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            if result.returncode or len(result.stdout)>1024*1024:raise ValueError('Local Windows query failed or exceeded its output bound')
            changed=False
            with self.lock:
                if not self.stop_event.is_set():changed=self.apply_windows(json.loads(result.stdout.decode('utf-8-sig')))
            if changed:self.notify_change()
        except (OSError,ValueError,subprocess.TimeoutExpired):
            with self.lock:
                self.status['windows_error']='Local Windows collector unavailable'
                self.status['last_error']='Local Windows collector unavailable; file observer remains scoped and separate'

    def snapshot_files(self):
        result={}
        if not self.folder.exists():return result
        for p in self.folder.glob('sedra-lab-*.txt'):
            if p.is_symlink() or not p.is_file() or p.resolve().parent!=self.folder.resolve():continue
            if len(result)>=200:
                with self.lock:self.status['files']='input_bound_reached'
                break
            st=p.stat();result[p.name]=(st.st_size,st.st_mtime_ns)
        return result

    def collect_files(self):
        changed=False
        with self.lock:
            current=self.snapshot_files()
            for name,value in current.items():
                if self.files.get(name)==value:continue
                alias=hashlib.sha256((self.salt+name).encode()).hexdigest()[:20]
                run=self.probe_run if self.probe_run and name.startswith('sedra-lab-'+self.probe_run+'-') else None
                changed=self.record('file:'+alias+':'+str(value[1]),'file','scoped_file_created' if name not in self.files else 'scoped_file_modified',time.time(),
                    {'file_fingerprint':alias,'bytes':value[0],'probe_run':run,'provider':'Local filesystem metadata polling','scope':'endpoint-lab / sedra-lab-*.txt; contents not read'}) or changed
            self.files=current;self.status['last_file_poll']=time.time();self.status['file_error']=None
        if changed or self.status.get('case_capture_error'):self.notify_change()

    def start(self):
        with self.lock:
            if self.running:return self.view()
            if any(t.is_alive() for t in self.threads):raise ValueError('Previous sensor query is stopping; retry after it finishes')
            self.folder.mkdir(parents=True,exist_ok=True);self.files=self.snapshot_files()
            self.stop_event.clear();self.running=True;self.status.update({'enabled':True,'files':'connected_scoped_metadata_polling'})
            def loop(interval,action):
                while not self.stop_event.is_set():
                    try:action()
                    except (OSError,sqlite3.Error):
                        with self.lock:self.status['last_error']='Local observer read failed; inspect coverage'
                    self.stop_event.wait(interval)
            self.threads=[threading.Thread(target=loop,args=(1,self.collect_files),daemon=True),threading.Thread(target=loop,args=(5,self.collect_windows),daemon=True)]
            for thread in self.threads:thread.start()
        return self.view()

    def stop(self):
        with self.lock:
            self.stop_event.set();self.running=False;self.status['enabled']=False
        return self.view()

    def run_probe(self):
        self.start()
        with self.lock:
            if self.probe and self.probe.poll() is None:raise ValueError('A controlled endpoint probe is already running')
            if len(self.files)>185:raise ValueError('Named lab folder reached its retained-file bound; use a fresh data directory')
            self.probe_run=uuid.uuid4().hex
            self.probe_started=time.time()
            self.probe=subprocess.Popen([sys.executable,str(ROOT/'scripts/endpoint_probe.py'),str(self.folder),self.probe_run],
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            return {'started':True,'probe_run':self.probe_run,'pid':self.probe.pid,'scope':'Real owned child creates ten synthetic files in endpoint-lab only; no USB or authentication is fabricated'}

    def view(self,subject='lab-001',now=None):
        now=time.time() if now is None else now
        if subject!='lab-001':return {'mapped':False,'enabled':False,'events':[],'rules':[],'score':0,'status':{'scope':'This sensor maps only its current Windows identity to lab-001'}}
        with self.db() as db:
            rows=db.execute('SELECT * FROM endpoint_events WHERE at>? AND at<=? ORDER BY at DESC,seq DESC LIMIT 501',(now-1800,now)).fetchall()
            history=db.execute("SELECT * FROM endpoint_events WHERE channel='logon' AND kind!='current_session_snapshot' AND at<=? AND at>? ORDER BY at DESC LIMIT 10",(now-1800,now-7*86400)).fetchall()
        events=[dict(r)|{'detail':json.loads(r['detail'])} for r in rows[:500]]
        real=[e for e in events if e['origin']==ORIGIN]
        short=[e for e in real if e['at']>now-120]
        files=[e for e in short if e['channel']=='file']
        def distinct(items):
            values={}
            for e in sorted(items,key=lambda e:(e['at'],e['seq']),reverse=True):
                key=e['detail'].get('file_fingerprint')
                if key and key not in values:values[key]=e
            return list(values.values())
        unique_files=distinct(files)
        processes=[e for e in short if e['kind']=='controlled_process_observed']
        arrivals=[e for e in real if e['kind']=='usb_arrival_observed']
        logon=[e for e in real if e['kind'] in ('session_logon','session_reconnect','logon_success')]
        rules=[]
        def rule(key,title,score,active,items,note):
            rules.append({'rule_id':key,'title':title,'score':score if active else 0,'active':bool(active),'observed':len(items),
                'evidence_ids':['endpoint:'+str(e['seq']) for e in items[:12]],'note':note})
        rule('endpoint_scoped_write_burst','Scoped endpoint file-write burst',75,len(unique_files)>=8,unique_files,'At least 8 distinct named files in 120s; repeated edits of one file do not multiply this signal.')
        correlated=[]
        for run in {p['detail'].get('probe_run') for p in processes if p['detail'].get('probe_run')}:
            group=distinct([e for e in files if e['detail'].get('probe_run')==run and any(p['detail'].get('probe_run')==run and p['at']<=e['at'] for p in processes)])
            if len(group)>=8:correlated.extend(group)
        matching_processes=[p for p in processes if any(p['detail'].get('probe_run')==e['detail'].get('probe_run') for e in correlated)]
        rule('endpoint_owned_process_file_sequence','Owned process followed by lab file changes',90,len(correlated)>=8,matching_processes+correlated,'CIM confirms the owned process; at least 8 distinct later files carry the same server-issued probe run. Controlled lab evidence, not compromise.')
        usb_sequence=distinct([e for e in files if any(a['at']<=e['at'] for a in arrivals)])
        rule('endpoint_usb_then_writes','USB arrival followed by scoped file changes',90,len(usb_sequence)>=8,arrivals+usb_sequence,'Presence polling detects arrival between polls. Correlation does not prove the files were copied to USB.')
        auth_sequence=distinct([e for e in files if any(a['at']<=e['at'] for a in logon)])
        rule('endpoint_logon_then_writes','Observed logon followed by lab file changes',80,len(auth_sequence)>=8,logon+auth_sequence,'Actual current-identity session log records only; session snapshots never trigger this rule.')
        with self.lock:status=dict(self.status)
        ages={key:max(0,now-status[key]) if status.get(key) is not None else None for key in ('last_windows_poll','last_file_poll')}
        health='stopped' if not self.running else 'pending' if any(v is None for v in ages.values()) else 'stale' if max(ages.values())>30 else 'partial' if status.get('windows_error') or status.get('file_error') or status.get('files')=='input_bound_reached' else 'fresh'
        status['health']={'state':health,'ages_seconds':ages,'stale_after_seconds':30,'note':'Coverage freshness, not employee confidence or maliciousness'}
        return {'mapped':True,'enabled':self.running,'origin':ORIGIN,'profile':'sedra-local-endpoint-v2','score':max(r['score'] for r in rules),'rules':rules,
            'events':events[:60],'events_total_30m':len(events),'truncated':len(rows)>500,'status':status,
            'historical_logons':[dict(r)|{'detail':json.loads(r['detail'])} for r in history],
            'scope_note':'Real local observations of controlled test activity. Synthetic-origin fixtures never affect the real endpoint score. No network destinations or other users are collected.'}

    def reset(self):
        with self.lock:
            if self.probe and self.probe.poll() is None:raise ValueError('Wait for the owned endpoint probe before resetting')
            with self.db() as db:db.execute('DELETE FROM endpoint_events')
            self.files=self.snapshot_files()

    def close(self):
        self.stop()
        for thread in self.threads:thread.join(timeout=20)
        if self.probe and self.probe.poll() is None:
            try:self.probe.wait(timeout=18)
            except subprocess.TimeoutExpired:self.probe.terminate();self.probe.wait(timeout=5)
        self.running=False


def augment(subject,endpoint):
    result=dict(subject);result['endpoint_context']=endpoint
    if not endpoint.get('mapped'):return result
    live=dict(subject['live_context']);policy=dict(subject['policy_context']);u=dict(subject['ueba'])
    policy['app_component']=live['score'];policy['endpoint_component']=endpoint['score']
    live['score']=max(live['score'],endpoint['score']);live['endpoint_rule_ids']=[r['rule_id'] for r in endpoint['rules'] if r['active']]
    live['active_rule_ids']=[*live['active_rule_ids'],*live['endpoint_rule_ids']]
    if endpoint.get('enabled'):live['source']='observed_application_and_local_endpoint_events'
    policy['live_component']=live['score'];result['behavior_score']=max(result['behavior_score'],endpoint['score'])
    policy['effective_score']=result['behavior_score'];policy['mode']='tightened' if result['behavior_score']>=70 else 'standard'
    policy['active_24h_4gram_limit']=.1 if result['behavior_score']>=70 else .2
    if endpoint.get('enabled'):
        status=endpoint['status']
        u['coverage']=[*u['coverage'][:2],{'channel':'Windows logon / session','status':status.get('session_log','pending')},
            {'channel':'USB / removable presence','status':status.get('usb','pending')},
            {'channel':'Endpoint lab file metadata / owned process','status':status.get('files','pending')}]
    result.update({'live_context':live,'policy_context':policy,'ueba':u})
    return result
