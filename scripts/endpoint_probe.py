"""Controlled real process/file activity in the named local sensor sandbox only."""
from pathlib import Path
import sys
import time
import uuid

target=Path(sys.argv[1]).resolve()
if target.name!='endpoint-lab':raise SystemExit('Named endpoint-lab folder required')
target.mkdir(parents=True,exist_ok=True)
run=sys.argv[2] if len(sys.argv)>2 else uuid.uuid4().hex[:12]
if not run.isalnum() or len(run)>40:raise SystemExit('Bounded probe run identifier required')
time.sleep(2)
for i in range(10):
    (target/f'sedra-lab-{run}-{i}.txt').write_text(f'SEDRA synthetic local telemetry fixture {run} {i}\n',encoding='utf-8')
    time.sleep(.12)
time.sleep(12)
