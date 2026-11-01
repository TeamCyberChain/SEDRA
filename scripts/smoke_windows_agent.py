"""Real built Windows agent -> scoped API -> case and policy. Isolated runtime only."""
from pathlib import Path
import sys,os,json,time,tempfile,subprocess,threading,csv,hashlib,socket,argparse
from http.server import ThreadingHTTPServer
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from sedra.app import AppState,handler_for
from sedra.corpus import catalog
from test_app import LocalClient
p=argparse.ArgumentParser();p.add_argument('--service',action='store_true');p.add_argument('--output',default='artifacts/windows_agent_smoke_v1.json');a=p.parse_args()
if os.name!='nt':raise SystemExit('Real Windows execution required')
binary=ROOT/'windows-agent/bin/Sedra.Agent.exe';assert binary.exists()
with tempfile.TemporaryDirectory(prefix='sedra-native-agent-',dir=ROOT/'work') as temp:
 root=Path(temp);watch=root/'watched';watch.mkdir();runtime=root/'agent';runtime.mkdir();app=AppState(root/'server');Base=handler_for(app)
 stage={'value':0 if not a.service else 2,'unavailable_responses':0,'lost_ack':0}
 class Handler(Base):
  def do_POST(self):
   if self.path=='/api/v1/endpoint/events' and stage['value']==0:
    self.rfile.read(int(self.headers.get('Content-Length','0')));stage['value']=1;stage['unavailable_responses']+=1
    return self.respond(503,{'error':'Controlled availability failure'})
   return super().do_POST()
  def respond(self,status,data,content_type='application/json; charset=utf-8',cookie=None):
   if self.path=='/api/v1/endpoint/events' and status==200 and isinstance(data,dict) and data.get('accepted',0)>=8 and stage['value']==1:
    stage['value']=2;stage['lost_ack']+=1;self.close_connection=True
    try:self.connection.shutdown(socket.SHUT_RDWR)
    except OSError:pass
    return
   return super().respond(status,data,content_type,cookie)
 server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
 base='http://127.0.0.1:'+str(server.server_port);admin=LocalClient(base).login('analyst');user=LocalClient(base).login('lab-001')
 status,key=admin.request('/api/integrations/keys',{'name':'Native Windows functional test','scopes':['endpoint:write'],'subjects':['lab-001'],'ttl_hours':1});assert status==200
 sid=list(csv.reader(subprocess.check_output(['whoami','/user','/fo','csv','/nh'],text=True).strip().splitlines()))[0][-1]
 config={'server_url':base+'/','device_id':key['device_id'],'subject_id':'lab-001','target_user_sid':sid,'watch_directories':[str(watch)],'process_names':[],'poll_seconds':5,'allow_loopback_http':True,'collect_usb':True,'collect_session':True}
 path=root/'config.json';path.write_text(json.dumps(config),encoding='utf-8');process=None;service_name=None
 quote=next(f['text'] for f in catalog()[0]['fragments'] if f['label']=='Context comparison excerpt')
 before=user.request('/api/transfer',{'request_id':'native-agent-before','text':quote})[1];assert before['decision']=='ALLOW'
 try:
  if a.service:
   service_name='SEDRAAgent-Test-'+os.urandom(4).hex();install=root/'installed';runtime=root/'service-data'
   keyfile=root/'fixture-key.private';keyfile.write_text(key['token']);runner=root/'install-fixture.ps1'
   runner.write_text("$ErrorActionPreference='Stop'\n$secret=ConvertTo-SecureString ([IO.File]::ReadAllText('"+str(keyfile).replace("'","''")+"')) -AsPlainText -Force\n& '"+str(ROOT/'windows-agent/Install-Agent.ps1').replace("'","''")+"' -ConfigPath '"+str(path).replace("'","''")+"' -EnrollmentKey $secret -ServiceName '"+service_name+"' -InstallDirectory '"+str(install).replace("'","''")+"' -DataDirectory '"+str(runtime).replace("'","''")+"' -Start\n",encoding='utf-8')
   result=subprocess.run(['pwsh','-NoProfile','-NonInteractive','-File',str(runner)],capture_output=True,text=True,timeout=60)
   if result.returncode:raise AssertionError('SCM install/start failed: '+result.stderr[-1500:])
   probe=subprocess.run(['pwsh','-NoProfile','-NonInteractive','-Command',"$s=Get-CimInstance Win32_Service -Filter \"Name='"+service_name+"'\";@{state=$s.State;account=$s.StartName;start=$s.StartMode}|ConvertTo-Json -Compress"],capture_output=True,text=True,timeout=10)
   scm=json.loads(probe.stdout);assert scm['state']=='Running' and scm['account'].lower()=='nt authority\\localservice' and scm['start']=='Auto',scm
  else:
   r=subprocess.run([str(binary),'provision',str(runtime),str(path)],input=key['token']+'\n',text=True,capture_output=True,timeout=10);assert r.returncode==0,r.stderr
   assert key['token'].encode() not in (runtime/'credential.dpapi').read_bytes()
   # Identity changes must fail before touching the existing encrypted enrollment.
   changed=config|{'device_id':'f'*32};other=root/'different.json';other.write_text(json.dumps(changed));original=(runtime/'credential.dpapi').read_bytes()
   r=subprocess.run([str(binary),'provision',str(runtime),str(other)],input=key['token']+'\n',text=True,capture_output=True,timeout=10);assert r.returncode!=0 and (runtime/'credential.dpapi').read_bytes()==original
   unsafe=config|{'server_url':'http://external.invalid/'};bad=root/'unsafe.json';bad.write_text(json.dumps(unsafe))
   r=subprocess.run([str(binary),'provision',str(root/'refused'),str(bad)],input=key['token']+'\n',text=True,capture_output=True,timeout=10);assert r.returncode!=0
   process=subprocess.Popen([str(binary),'--console',str(runtime),'42'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,creationflags=subprocess.CREATE_NO_WINDOW)
  until=time.monotonic()+25
  while not (runtime/'status.json').exists():
   if process and process.poll() is not None:raise AssertionError('Native agent exited before collection')
   if time.monotonic()>until:raise AssertionError('Agent status unavailable')
   time.sleep(.2)
  initial=json.loads((runtime/'status.json').read_text());assert initial['coverage']['files']=='connected',initial
  for i in range(10):(watch/('synthetic-'+str(i)+'.txt')).write_text('Synthetic Windows agent test only.')
  until=time.monotonic()+55;seen_queued=False
  while True:
   try:state=json.loads((runtime/'status.json').read_text())
   except (OSError,json.JSONDecodeError):time.sleep(.2);continue
   seen_queued|=state['queued']>=8
   live=admin.request('/api/ueba?subject=lab-001')[1]
   if live.get('agent_context',{}).get('score')==75 and state['transport']=='connected' and state['queued']==0:break
   if time.monotonic()>until:raise AssertionError('Agent delivery/ack did not finish: '+json.dumps(state))
   time.sleep(.4)
  after=user.request('/api/transfer',{'request_id':'native-agent-after','text':quote})[1];assert after['decision']=='BLOCK' and after['body_sha256']==before['body_sha256']
  assert after['behavior_context']['agent_context']['score']==75
  cases=admin.request('/api/ueba/cases')[1];assert cases['counts']['total']>=1
  with app.integrations.db() as c:
   count=c.execute('SELECT count(*) FROM agent_events').fetchone()[0];distinct=c.execute("SELECT count(DISTINCT json_extract(detail,'$.file_fingerprint')) FROM agent_events WHERE kind='file_changed'").fetchone()[0]
  assert distinct==10
  for f in (runtime/'spool').glob('*.json'):assert key['token'] not in f.read_text()
  report={'successful':True,'mode':'actual Windows SCM LocalService' if a.service else 'actual Windows native foreground agent','service_installed_tested':a.service,'scm_configuration':scm if a.service else None,'compiled_native_exe_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'real_distinct_file_observations':distinct,'accepted_event_rows':count,'origin':'AUTHENTICATED_ENDPOINT_REPORT','priority_before':0,'agent_priority_after':75,'before':before['decision'],'after':after['decision'],'same_original_hash':True,'receiver_receipts':len(app.receiver.list()),'case_opened':True,'dpapi_credential':True,'real_physical_usb_tested':False,'session_or_process_event_generated':False,'coverage':state['coverage'],'offline_queue_observed':seen_queued,'controlled_503':stage['unavailable_responses'],'lost_ack_after_server_commit':stage['lost_ack'],'spool_drained':state['queued']==0,'raw_contents_paths_command_lines_sent':False,'scope':'Isolated loopback server, explicit watched temporary directory, ten synthetic files. No main service, real account or OS security policy modified.'}
  if not a.service:assert seen_queued and stage['lost_ack']==1 and stage['unavailable_responses']==1
  admin.request('/api/integrations/keys',{'action':'revoke','id':key['id']})
 finally:
  if a.service and service_name:
   result=subprocess.run(['pwsh','-NoProfile','-NonInteractive','-File',str(ROOT/'windows-agent/Uninstall-Agent.ps1'),'-ServiceName',service_name,'-InstallDirectory',str(root/'installed')],capture_output=True,text=True,timeout=60)
   if result.returncode:raise AssertionError('SCM cleanup failed: '+result.stderr[-1000:])
  if process:
   stdout,stderr=process.communicate(timeout=50);assert process.returncode==0,stderr
  server.shutdown();server.server_close();thread.join(3);app.close()
 Path(a.output).parent.mkdir(parents=True,exist_ok=True);Path(a.output).write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,indent=2))
