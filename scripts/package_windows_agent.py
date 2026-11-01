"""Package only an exact native binary with successful foreground and SCM proof."""
from pathlib import Path
import argparse,hashlib,json,subprocess,zipfile

ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--proof-dir',required=True);p.add_argument('--output',required=True);a=p.parse_args()
 binary=Path(a.binary);proof=Path(a.proof_dir);out=Path(a.output);out.mkdir(parents=True,exist_ok=True)
 digest=hashlib.sha256(binary.read_bytes()).hexdigest()
 files={'Sedra.Agent.exe':binary}
 for name in ('windows_agent_smoke_v1.json','windows_agent_service_v1.json'):
  source=proof/name;report=json.loads(source.read_text(encoding='utf-8'))
  assert report['successful'] and report['compiled_native_exe_sha256']==digest,'Exact binary must match executed native/SCM proof'
  if 'service_' in name:assert report['service_installed_tested'] and report['scm_configuration']['account'].lower()=='nt authority\\localservice'
  files['verification/'+name]=source
 for name in ('Install-Agent.ps1','Uninstall-Agent.ps1','Build-Agent.ps1','Sedra.Agent.cs','agent.example.json','Caddyfile.example'):files[name]=ROOT/'windows-agent'/name
 files['README.md']=ROOT/'docs/WINDOWS_AGENT.md'
 manifest={'product':'SEDRA Windows Agent','version':'0.20.0','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'native_sha256':digest,'authenticode':'Unsigned; organization approval/signing required','requirements':'Windows 10/11 or Server equivalent, .NET Framework 4.8+, Administrator for installation','contains_credentials':False,'files':{name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in files.items()}}
 target=out/'SEDRA-Windows-Agent-0.20.0.zip'
 with zipfile.ZipFile(target,'x',zipfile.ZIP_DEFLATED) as z:
  for name,path in files.items():z.write(path,name)
  z.writestr('manifest.json',json.dumps(manifest,indent=2)+'\n')
 with zipfile.ZipFile(target) as z:assert z.testzip() is None
 (out/'package-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
 print(json.dumps({'package':str(target),'files':len(files)+1,'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'exact_native_and_service_binary_verified':True}))
if __name__=='__main__':main()
