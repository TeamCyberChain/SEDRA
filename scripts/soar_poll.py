"""Example one-poll SOAR consumer. Key from environment; checkpoint after handling."""
import json,os,sys,urllib.request,urllib.error
from pathlib import Path
BASE='http://127.0.0.1:8765'
p=Path('data/soar-checkpoint.json');state=json.loads(p.read_text()) if p.exists() else {'after':0}
def pull(state):
 from urllib.parse import urlencode
 req=urllib.request.Request(BASE+'/api/v1/cases/changes?'+urlencode(state),headers={'Authorization':'Bearer '+os.environ['SEDRA_API_KEY']})
 with urllib.request.urlopen(req,timeout=10) as r:return json.load(r)
try:feed=pull(state)
except urllib.error.HTTPError as e:
 if e.code!=409:raise
 e.close();feed=pull({'after':0})
for event in feed['items']:
 # Replace with your connector's durable, idempotent downstream handler.
 print(json.dumps(event))
sys.stdout.flush()
p.parent.mkdir(exist_ok=True);tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps({'after':feed['next_cursor'],'generation':feed['generation']}));tmp.replace(p)
