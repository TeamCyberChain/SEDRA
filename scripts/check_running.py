"""Exit zero only for the expected already-running local SADD build."""
import json
import sys
import urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sadd import __version__
try:
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://127.0.0.1:8765/health',timeout=1) as response:
        state=json.load(response)
    success=state.get('mode')=='local_lab' and state.get('build_version')==__version__ and state.get('product')=='SEDRA'
except (OSError,ValueError):
    success=False
raise SystemExit(0 if success else 1)
