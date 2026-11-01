"""Local SEDRA workbench. This development HTTP server is not production ingress."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import hmac
import json
import mimetypes
import os
import secrets
import sqlite3
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__
from .audit_log import AuditLog
from .accounts import Accounts
from .analytics import Reports,aggregate,export_csv,export_pdf
from .behavior import build_demo_snapshot
from .corpus import DOCUMENTS, catalog
from .gateway import Gateway
from .receiver import start_receiver
from .ai_portal import AIPortal
from .labels import BUSINESS_TAGS, OWNERS, PROFILE as LABEL_PROFILE
from .data_types import detector_catalog
from .alerts import AlertConflict
from .ueba import assess, INPUT_LIMIT, HISTORY_DAYS, RULE_EVIDENCE_LIMIT
from .endpoint import EndpointSensor, augment
from .behavior_cases import CaseStore, CaseConflict
from .policy_explain import counterfactual
from .integrations import Integrations,OIDC,AuthError,Conflict,RateLimit
from .browser_guard import BrowserGuard,EXTENSION_ORIGIN

ROOT = Path(__file__).resolve().parent.parent
AUDIT_ROUTES = {'/api/dashboards','/api/reports','/workbench.js','/workbench.css','/api/account/mfa/enroll','/api/account/mfa/verify','/api/accounts/password','/api/account/context','/api/account/bootstrap','/api/account/login','/api/accounts','/api/accounts/users','/api/accounts/roles','/settings.js','/settings.css','/login','/login.js','/alerts.js','/app.js','/audit.js','/browser-harness-transport.js','/browser-harness.html','/browser-lab.html','/browser-lab.js','/cases.js','/console.css','/endpoint.js','/index.html','/integrations.html','/integrations.js','/openapi.json','/portal.css','/portal.html','/portal.js','/presentation.js','/sedra.css','/style.css','/theme.css','/theme.js','/ueba.js','/api/audit/context','/api/reset', '/api/integrations/keys', '/api/logout', '/browser-lab', '/api/v1/ueba', '/api/state', '/api/ueba/counterfactual', '/health', '/api/audit', '/api/document', '/api/v1/cases', '/browser-harness', '/api/session', '/portal', '/api/v1/alerts/action', '/api/reconcile', '/api/endpoint/action', '/api/alerts', '/api/v1/telemetry', '/api/endpoint', '/api/transfer', '/api/ueba/cases', '/api/portal/status', '/api/portal/configure', '/auth/callback', '/api/v1/alerts', '/api/portal/chat', '/', '/api/v1/cases/changes', '/auth/login', '/api/catalog/labels', '/integrations', '/alert', '/api/v1/browser/inspect', '/api/v1/cases/action', '/api/alerts/action', '/api/ueba', '/api/audit/ui', '/api/ueba/cases/action'}


def utcnow():
    return datetime.now(timezone.utc).isoformat()


class AppState:
    def __init__(self, data_dir=None):
        self.data_dir = Path(data_dir or ROOT / "data" / "runtime")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.accounts = Accounts(self.data_dir / 'accounts.sqlite')
        if os.getenv('SEDRA_OIDC_CONFIG') and self.accounts.enabled:raise ValueError('Select local accounts or OIDC; do not enable both identity stores together')
        self.platform_audit = AuditLog(self.data_dir / 'platform_audit.sqlite')
        self.reports=Reports(self.data_dir/'reports.sqlite')
        self.snapshot = build_demo_snapshot(seed=42)
        (self.data_dir / "lab_evaluation.json").write_text(json.dumps(self.snapshot, indent=2, ensure_ascii=False), encoding="utf-8")
        self.subjects = {s["subject_id"]: s for s in self.snapshot["subjects"]}
        self.gateway = Gateway(str(self.data_dir / "gateway.sqlite"), DOCUMENTS)
        self.receiver_key = secrets.token_urlsafe(32)
        self.receiver_server, self.receiver = start_receiver(self.data_dir / "receiver.sqlite", self.receiver_key)
        self.receiver_url = f"http://127.0.0.1:{self.receiver_server.server_port}"
        # Localhost calls must remain localhost even in a proxied development environment.
        self.local_http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.integrations=Integrations(self.data_dir/'integrations.sqlite')
        config=os.getenv('SEDRA_OIDC_CONFIG')
        self.oidc=OIDC(json.loads(Path(config).read_text(encoding='utf-8'))) if config else None
        self.sessions = {}
        self.guard = threading.RLock()
        self.active_transfers = 0
        self._benchmark_cache = None
        self._benchmark_mtime = None
        with self.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, timestamp TEXT, subject_id TEXT, kind TEXT, detail TEXT)")
            db.execute('CREATE INDEX IF NOT EXISTS audit_subject_time ON audit(subject_id,timestamp)')
        self.endpoint = EndpointSensor(self.data_dir)
        self.cases=CaseStore(str(self.data_dir/'behavior_cases.sqlite'))
        self.case_capture_error=None
        self.portal = AIPortal(self)
        self.endpoint.on_change=lambda:self.capture_case('lab-001')
        self.browser_guard=BrowserGuard(self)

    @contextmanager
    def db(self):
        db = sqlite3.connect(str(self.data_dir / "audit.sqlite"), timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def audit(self, subject_id, kind, detail):
        with self.db() as db:
            db.execute("INSERT INTO audit(timestamp,subject_id,kind,detail) VALUES (?,?,?,?)", (utcnow(), subject_id, kind, json.dumps(detail, ensure_ascii=False)))
        self.platform_audit.append('APPLICATION',subject_id,kind,{k:v for k,v in detail.items() if k in ('request_id','doc_id','doc_version','classification','sha256','utf8_bytes','receiver_contacted','fault_injection')})
        if hasattr(self,'cases') and subject_id in self.subjects:self.capture_case(subject_id)

    def capture_case(self,subject_id):
        # Review-case storage must never roll back a completed gateway delivery.
        try:self.live_subject(self.subjects[subject_id])
        except Exception:self.case_capture_error='UEBA case capture failed; source evidence and gateway enforcement remain separate'

    def events(self, subject_id=None):
        with self.db() as db:
            rows = db.execute("SELECT * FROM audit " + ("WHERE subject_id=? " if subject_id else "") + "ORDER BY id DESC LIMIT 200", (subject_id,) if subject_id else ()).fetchall()
            return [{"id": r["id"], "timestamp": r["timestamp"], "subject_id": r["subject_id"], "kind": r["kind"], "detail": json.loads(r["detail"])} for r in rows]

    def new_session(self, identity="analyst"):
        session_id = secrets.token_urlsafe(32)
        session = {"role": "analyst" if identity == "analyst" else "employee", "subject_id": None if identity == "analyst" else identity, "csrf_token": secrets.token_urlsafe(32), "created_at": time.time()}
        if self.accounts.enabled:session.update(role='unauthenticated',subject_id=None)
        with self.guard:
            self.sessions[session_id] = session
        return session_id, session

    def request_view(self, row):
        result = dict(row)
        result["state"] = result.get("state", result.get("request_state"))
        result["matches"] = result.get("matched_documents", [])
        result["reasoncodes"] = result.get("reason_codes", [])
        subject = self.subjects.get(result.get("subject_id"), {})
        if not result.get('behavior_context'):
            result["behavior_context"] = {k: subject.get(k) for k in ("as_of", "model_version", "provenance", "behavior_score", "rule_score", "ml_score")}
        result["model_version"] = self.snapshot.get("model_version")
        result["provenance"] = "synthetic_lab"
        return result

    def live_subject(self,subject,now=None):
        return self.live_subjects([subject],now=now)[0]

    def live_subjects(self,subjects,now=None):
        """Read bounded metadata per actor; share connections across the console batch."""
        now=time.time() if now is None else float(now)
        lower=now-HISTORY_DAYS*86400
        lower_iso=datetime.fromtimestamp(lower,timezone.utc).isoformat()
        upper_iso=datetime.fromtimestamp(now,timezone.utc).isoformat()
        result=[]
        with self.guard,self.db() as audit,self.gateway._connection() as ledger:
            for subject in subjects:
                uid=subject['subject_id']
                raw=audit.execute("SELECT * FROM audit WHERE subject_id=? AND kind='document_read' AND timestamp>=? AND timestamp<=? ORDER BY timestamp DESC,id DESC LIMIT ?",
                    (uid,lower_iso,upper_iso,INPUT_LIMIT+1)).fetchall()
                requests=ledger.execute('''SELECT row_id,subject_id,request_id,created_at,decision,state,destination,body_bytes,body_sha256,snapshot_json
                    FROM gateway_requests WHERE subject_id=? AND created_at>=? AND created_at<=?
                    ORDER BY created_at DESC,row_id DESC LIMIT ?''',(uid,lower,now,INPUT_LIMIT+1)).fetchall()
                reads=[dict(r)|{'detail':json.loads(r['detail'])} for r in raw[:INPUT_LIMIT]]
                external=self.integrations.reads(uid,lower,now,INPUT_LIMIT+1)
                for e in external:
                    e.update(subject_id=uid,kind='document_read')
                    e['detail']['classification']=next(d['classification'] for d in DOCUMENTS if d['id']==e['detail']['doc_id'])
                reads=sorted(reads+external,key=lambda r:r['timestamp'],reverse=True)
                input_truncated=len(reads)>INPUT_LIMIT
                reads=reads[:INPUT_LIMIT]
                metadata=[]
                for row in requests[:INPUT_LIMIT]:
                    item=dict(row);snapshot=json.loads(item.pop('snapshot_json'))
                    if snapshot.get('behavior_context',{}).get('browser',{}).get('operation')=='offline':continue
                    item['detector_types']=[f['type'] for f in snapshot.get('structured_findings',[])]
                    item['reason_codes']=snapshot.get('reason_codes',[])
                    item['matched_document_ids']=[d['doc_id'] for d in snapshot.get('matched_documents',[]) if d.get('confirmed')]
                    metadata.append(item)
                assessed=assess(subject,reads,metadata,self.snapshot['history'],now,
                    truncated=input_truncated or len(raw)>INPUT_LIMIT or len(requests)>INPUT_LIMIT)
                assessed=augment(assessed,self.endpoint.view(uid,now=now))
                refs={key for rule in assessed['live_context']['rules'] if rule['active'] for key in rule['evidence_ids']}
                referenced=[r for r in metadata if 'gateway:'+str(r['row_id']) in refs][:RULE_EVIDENCE_LIMIT]
                assessed['ueba']['request_evidence']=referenced+[r for r in metadata if 'gateway:'+str(r['row_id']) not in refs][:max(0,RULE_EVIDENCE_LIMIT-len(referenced))]
                try:
                    assessed['behavior_case']=self.cases.observe(assessed,now=now);self.case_capture_error=None
                except sqlite3.Error:
                    assessed['behavior_case']=None;self.case_capture_error='UEBA case store unavailable; the current behavioral score is still evaluated'
                result.append(assessed)
        return result

    def endpoint_action(self,session,body):
        if session['role']!='analyst':raise PermissionError('Only Analyst can control the scoped local endpoint sensor')
        if set(body)!={'action'} or body['action'] not in ('start','probe','stop'):
            raise ValueError('Choose start, stop or probe; arbitrary telemetry or targets are not accepted')
        with self.guard:
            return self.endpoint.start() if body['action']=='start' else self.endpoint.stop() if body['action']=='stop' else self.endpoint.run_probe()

    def refresh_case_signals(self,now=None):
        """Cool persisted live priorities for pull consumers without a console.

        Only the latest nonzero case per known laboratory actor is assessed.
        Source observation callbacks still capture new activity immediately.
        This is read-time maintenance, not an autonomous expiry scheduler.
        """
        now=time.time() if now is None else float(now)
        with self.guard:
            with self.cases.db() as db:
                rows=db.execute('''SELECT c.subject_id FROM behavior_cases c
                    WHERE c.current_score<>0 AND c.seq=(SELECT max(latest.seq)
                    FROM behavior_cases latest WHERE latest.subject_id=c.subject_id)''').fetchall()
            subjects=[self.subjects[row['subject_id']] for row in rows if row['subject_id'] in self.subjects]
            assessed=self.live_subjects(subjects,now=now) if subjects else []
            return {'evaluated_at':now,'subjects_evaluated':len(subjects),
                'status':'partial' if any(s['behavior_case'] is None for s in assessed) else 'current'}

    def case_view(self,session,case_id=None,packet=False):
        if session['role']!='analyst':raise PermissionError('Only Analyst can review UEBA cases')
        freshness=self.refresh_case_signals()
        result=self.cases.get(case_id,packet=packet) if case_id else self.cases.feed()
        return result|{'signal_refresh':freshness}

    def case_action(self,session,body):
        if session['role']!='analyst':raise PermissionError('Only Analyst can manage UEBA cases')
        return self.cases.action(body,actor=session.get('principal','analyst'))

    def explain_policy(self,session,body):
        if session['role']!='analyst':raise PermissionError('Only Analyst can preview frozen policy evidence')
        if set(body)-{'subject_id','request_id','exclude_rules','exclude_daily'} or not {'subject_id','request_id'}<=set(body):raise ValueError('Use recorded request identity and rule exclusions only')
        for key in ('subject_id','request_id'):
            if not isinstance(body[key],str) or not 1<=len(body[key])<=100:raise ValueError('Bounded request identity required')
        request=self.gateway.get_request(subject_id=body['subject_id'],request_id=body['request_id'])
        return counterfactual(request,body.get('exclude_rules',[]),body.get('exclude_daily',False))

    def ueba_view(self,session,subject_id):
        if subject_id not in self.subjects:raise ValueError('Unknown laboratory subject')
        if session['role']!='analyst' and session['subject_id']!=subject_id:
            raise PermissionError('Employee UEBA evidence is scoped to the current subject')
        return self.live_subject(self.subjects[subject_id])

    def benchmark_view(self, session):
        """Historical evaluation stays separate from the live subject namespace."""
        if session["role"] != "analyst":
            return {"dataset": "CERT r4.2", "status": "analyst_only", "measurement_status": "Historical benchmark review belongs to the analyst role"}
        report = ROOT / "artifacts" / "cert_benchmark.json"
        if not report.exists():
            return {"dataset": "CERT r4.2", "status": "pending_local_ingestion", "measurement_status": "CERT evaluation has not been loaded; live controls use the separate lab model"}
        modified = report.stat().st_mtime_ns
        with self.guard:
            if modified != self._benchmark_mtime:
                try:
                    candidate = json.loads(report.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    return {"dataset": "CERT r4.2", "status": "artifact_not_ready", "measurement_status": "Awaiting a complete benchmark artifact"}
                if not isinstance(candidate, dict) or candidate.get("profile") != "cert_daily_v1" or not isinstance(candidate.get("evaluation"), dict):
                    return {"dataset": "CERT r4.2", "status": "invalid_artifact", "measurement_status": "The supplied artifact does not satisfy the independent CERT profile contract"}
                self._benchmark_cache = candidate
                self._benchmark_mtime = modified
            result = {"dataset": "CERT r4.2 — file-only v1 (failed gate)", "status": "measured", **{
                key: value for key, value in self._benchmark_cache.items()
                if key not in ("records", "history")
            }}
            result["full_history_artifact"] = "artifacts/cert_benchmark.json"
            result["historical_score_rows"] = len(self._benchmark_cache.get("history", []))
        return result

    def multichannel_view(self, session):
        if session['role'] != 'analyst':
            return {'status':'analyst_only'}
        path = ROOT/'artifacts/cert_v2_benchmark.json'
        if not path.exists():
            progress_path=ROOT/'artifacts/research_progress.json'
            try:
                progress=json.loads(progress_path.read_text(encoding='utf-8')) if progress_path.exists() else {}
            except (ValueError,OSError):
                progress={}
            archive=ROOT/'data/cert/r4.2.tar.bz2'
            partial=ROOT/'data/cert/r4.2.tar.bz2.part'
            try:
                downloaded=(archive if archive.exists() else partial).stat().st_size
            except OSError:
                downloaded=0
            return {'status':'pending_execution','dataset':'CERT r4.2 multichannel v2','progress':progress,
                    'source_download_bytes':downloaded,'expected_source_bytes':4824287500,
                    'measurement_status':'No multichannel result yet; never substitute fixture metrics'}
        try:
            value = json.loads(path.read_text(encoding='utf-8'))
            if value.get('profile') != 'cert_multichannel_calendar_v2' or not value.get('evaluation'):
                raise ValueError('Invalid report profile')
            return value
        except (ValueError,OSError):
            return {'status':'artifact_not_ready'}

    @staticmethod
    def validate_receipt(receipt, request):
        """A receipt proves this exact original request, not just an ID lookup."""
        if not isinstance(receipt, dict):
            raise ValueError("Receiver acknowledgment is not an object")
        expected = {
            "subject_id": request["subject_id"],
            "request_id": request["request_id"],
            "sha256": request["body_sha256"],
            "utf8_bytes": request["body_bytes"],
        }
        if type(receipt.get("utf8_bytes")) is not int or any(receipt.get(key) != value for key, value in expected.items()):
            raise ValueError("Receiver acknowledgment identity, digest or byte-count mismatch")
        return receipt

    def view(self, session):
        self.gateway.expire_unused()
        actor = session["subject_id"] if session["role"] == "employee" else None
        requests = [self.request_view(r) for r in self.gateway.requests(subject_id=actor)]
        receipts = self.receiver.list(actor)
        for receipt in receipts:
            if session["role"] == "analyst":
                receipt["preview"] = "[Content masked for analyst; SHA-256 and byte count retained]"
        return {
            "session": {k: v for k, v in session.items() if k != "created_at"},
            "demo_identities": [session['subject_id']] if actor is not None else ["analyst", "lab-001", "lab-002"],
            "subjects": self.live_subjects([s for s in self.snapshot["subjects"] if actor is None or s["subject_id"] == actor]),
            "evaluation": self.snapshot["evaluation"] if session['role']=='analyst' else {},
            "documents": self.catalog_view(), "requests": requests, "events": self.events(actor), "receiver": receipts,
            "label_schema": {'profile':LABEL_PROFILE, 'business_tags': BUSINESS_TAGS, 'owners': OWNERS},
            "data_types": detector_catalog(),
            "alerts": self.gateway.alerts_feed() if session['role']=='analyst' else {'available':False,'reason':'Analyst role required'},
            "behavior_cases": self.cases.feed() if session['role']=='analyst' else {'available':False},
            "case_capture_error":self.case_capture_error if session['role']=='analyst' else None,
            "label_history": self.gateway.label_history() if session['role'] == 'analyst' else [],
            "counts": {"attempted": len(requests), "forwarded": sum(r.get("state") == "FORWARDED_CONFIRMED" for r in requests), "blocked": sum(r.get("decision") == "BLOCK" for r in requests), "unknown": sum(r.get("state") in ("DELIVERY_UNKNOWN", "SENDING") for r in requests)},
            "provenance": "synthetic_lab", "profile": self.snapshot.get("profile"),
            "benchmark": self.benchmark_view(session),
            "benchmark_v2": self.multichannel_view(session),
            "capabilities": {"minimum_candidate_tokens": 2, "coverage_unit": "separate 4-gram and anchored distinctive-token coverage", "normal_threshold": 0.20, "high_behavior_threshold": 0.10, "high_behavior_boundary": 70, "reservation_ttl_seconds": 30, "window_hours": 24, "long_window_days":30, "auth_mode": "accounts" if self.accounts.enabled else "local_demo_identities", "receiver_mode": "independent_local_http_receiver"},
        }

    def catalog_view(self):
        labels = self.gateway.catalog_labels()
        return [doc | {'metadata': labels[doc['id']]} for doc in catalog()]

    def alerts_view(self,session,alert_id=None,before=None):
        if session['role']!='analyst':
            raise PermissionError('Only the Analyst demo role may review security alerts')
        return self.gateway.alert_detail(alert_id) if alert_id else self.gateway.alerts_feed(before=before)

    def update_alert(self,session,body):
        if session['role']!='analyst':
            raise PermissionError('Only the Analyst demo role may manage security alerts')
        return self.gateway.update_alert(body,actor=session.get('principal','analyst'))

    def update_labels(self, session, body):
        if session['role'] != 'analyst':
            raise PermissionError('Only the analyst demo role may govern document labels')
        return self.gateway.update_labels(body, actor='analyst')

    def transfer(self, session, body):
        if session["role"] != "employee":
            raise PermissionError("Choose an employee demo identity to submit a transfer")
        if "subject_id" in body or "behavior_score" in body:
            raise ValueError("Identity and behavior context are derived by the server")
        subject_id = session["subject_id"]
        text = body.get("text")
        request_id = body.get("request_id")
        if not isinstance(text, str) or not text.strip() or len(text.encode("utf-8")) > 65536:
            raise ValueError("Enter between 1 and 65536 UTF-8 bytes")
        if not isinstance(request_id, str) or not 8 <= len(request_id) <= 100 or any(not (c.isalnum() or c in "-_") for c in request_id):
            raise ValueError("A request identifier of 8–100 letters, digits, '-' or '_' is required")
        if body.get("destination", "public_ai") != "public_ai":
            raise ValueError("This lab exposes only the configured public_ai demo route")
        if not isinstance(body.get("simulate_ack_loss", False), bool):
            raise ValueError("simulate_ack_loss must be a boolean")
        subject = self.live_subject(self.subjects[subject_id])
        context = {k:subject[k] for k in ('as_of','model_version','provenance','behavior_score',
                   'rule_score','ml_score','completed_day_score','live_context','model_context','policy_context','endpoint_context','behavior_case') if k in subject}
        with self.guard:
            self.active_transfers += 1
        try:
            result = self.gateway.evaluate(subject_id=subject_id, request_id=request_id, text=text, behavior_score=subject["behavior_score"], destination="public_ai", behavior_context=context)
            if result.get("idempotent_replay") or result["decision"] == "BLOCK":
                if not result.get("idempotent_replay"):
                    self.audit(subject_id, "transfer_blocked", {"request_id": request_id, "reason_codes": result.get("reason_codes", []), "receiver_contacted": False})
                return self.request_view(result)
            self.gateway.claim_send(subject_id=subject_id, request_id=request_id)
            payload = json.dumps({"subject_id": subject_id, "request_id": request_id, "text": text}, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(self.receiver_url + "/receive", data=payload, method="POST", headers={"Content-Type": "application/json", "X-SEDRA-Receiver-Key": self.receiver_key})
            try:
                with self.local_http.open(req, timeout=3) as response:
                    receipt = json.load(response)
                self.validate_receipt(receipt, result)
                if body.get("simulate_ack_loss"):
                    # Deliberate fault injection: discard acknowledgment after receiver accepted.
                    raise TimeoutError("Lab fault injection: acknowledgment discarded")
                result = self.gateway.confirm_forwarded(subject_id=subject_id, request_id=request_id)
                self.audit(subject_id, "receiver_confirmed", {"request_id": request_id, "sha256": receipt["sha256"], "utf8_bytes": receipt["utf8_bytes"]})
            except (OSError, ValueError, urllib.error.URLError) as exc:
                result = self.gateway.mark_unknown(subject_id=subject_id, request_id=request_id)
                self.audit(subject_id, "delivery_unknown", {"request_id": request_id, "reason": str(exc), "fault_injection": bool(body.get("simulate_ack_loss"))})
            return self.request_view(result)
        finally:
            with self.guard:
                self.active_transfers -= 1

    def reconcile(self, session, body):
        # Reset must not clear the ledger between the receipt lookup and update.
        with self.guard:
            self.active_transfers += 1
        try:
            return self._reconcile(session, body)
        finally:
            with self.guard:
                self.active_transfers -= 1

    def _reconcile(self, session, body):
        request_id = body.get("request_id")
        visible = self.gateway.requests(subject_id=session["subject_id"] if session["role"] == "employee" else None)
        matches = [r for r in visible if r.get("request_id") == request_id]
        if len(matches) != 1:
            raise ValueError("Exactly one visible request must match")
        row = matches[0]
        if row.get('destination') in ('openai_api','local_ai'):
            cached = self.portal.outcome(row['subject_id'], request_id)
            if cached and cached.get('ai') and row['state'] in ('SENDING', 'DELIVERY_UNKNOWN'):
                row = self.gateway.confirm_forwarded(request_id, row['subject_id'])
            return self.request_view(row) | {'reconciliation_note':
                'AI route: only an already persisted model response can confirm delivery. No resend or independent receipt lookup.'}
        query = urllib.parse.urlencode({"subject_id": row["subject_id"], "request_id": request_id})
        req = urllib.request.Request(self.receiver_url + "/receipt?" + query, headers={"X-SEDRA-Receiver-Key": self.receiver_key})
        try:
            with self.local_http.open(req, timeout=3) as response:
                receipt = json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                # Absence at one instant is not evidence that an in-flight send cannot arrive.
                return self.request_view(row) | {"reconciliation_note": "No receipt yet; possible exposure remains reserved"}
            raise
        self.validate_receipt(receipt, row)
        result = self.gateway.reconcile(subject_id=row["subject_id"], request_id=request_id, delivered=True)
        self.audit(row["subject_id"], "delivery_reconciled", {"request_id": request_id, "sha256": receipt["sha256"]})
        return self.request_view(result)

    def reset(self):
        with self.guard:
            if self.active_transfers:
                raise ValueError("Wait for active transfers before resetting the demonstration")
            if self.endpoint.probe and self.endpoint.probe.poll() is None:
                raise ValueError('Wait for the controlled endpoint probe before resetting')
            self.gateway.reset_demo()
            self.receiver.clear()
            self.portal.reset()
            self.endpoint.reset()
            self.cases.reset()
            with self.integrations.db() as external:external.execute('DELETE FROM external_events')
            with self.db() as db:
                db.execute("DELETE FROM audit")

    def close(self):
        self.endpoint.close()
        self.receiver_server.shutdown()
        self.receiver_server.server_close()


def handler_for(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SEDRA-Local-Lab"

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def handle_one_request(self):
            self._audit_actor='anonymous';self._audit_operation=None;self._audit_outcome={};self._audit_start=time.monotonic()
            self._audit_request_id=secrets.token_hex(12)
            super().handle_one_request()

        def send_response(self,code,message=None):
            try:path=urllib.parse.urlsplit(getattr(self,'path','')).path
            except ValueError:path='/unmatched'
            safe=path if path in AUDIT_ROUTES else '/unmatched'
            app.platform_audit.append('API' if path.startswith('/api/') else 'HTTP',self._audit_actor,'http_response',{'method':self.command if self.command in ('GET','POST','OPTIONS','HEAD') else 'OTHER','route':safe,'status':code,'operation':self._audit_operation,'outcome':self._audit_outcome,'duration_ms':round((time.monotonic()-self._audit_start)*1000,2),'request_id':self._audit_request_id})
            super().send_response(code,message)
            self.send_header('X-SEDRA-Request-ID',self._audit_request_id)

        def log_message(self, format, *args):
            # Log route and status, never cookies, prompt bodies or credentials.
            pass

        def session(self):
            cookie = SimpleCookie()
            try:
                cookie.load(self.headers.get("Cookie", ""))
            except Exception:
                cookie = SimpleCookie()
            cookie_name = f'sedra_session_{self.server.server_port}'
            session_id = cookie[cookie_name].value if cookie_name in cookie else ""
            with app.guard:
                session = app.sessions.get(session_id)
            if session and time.time() - session["created_at"] < 8 * 3600 and time.time()<session.get("expires_at",float("inf")):
                if app.accounts.enabled:
                    claims=app.accounts.claims(session.get('account_id',''))
                    if claims and session.get('mfa_verified') and claims['auth_version']==session.get('auth_version'):session.update(claims)
                    else:session.update(role='unauthenticated',subject_id=None,can_manage_users=False,can_manage_roles=False,permissions=[],account_id=None,username=None,account_role=None,access_profile=None,principal=None)
                    if session.get('mfa_uid'):
                        pending=app.accounts.claims(session['mfa_uid'])
                        if not pending or pending['auth_version']!=session.get('mfa_version') or not 0<=time.time()-session.get('mfa_started',0)<300:
                            for key in ('mfa_uid','mfa_version','mfa_started','mfa_enrollment'):session.pop(key,None)
                self._audit_actor=session.get('principal') or session.get('subject_id') or session['role']
                return session_id, session, False
            session_id, session = app.new_session()
            if app.oidc:session['role']='unauthenticated'
            self._audit_actor=session.get('subject_id') or session['role']
            return session_id, session, True

        def local_origin(self):
            # Prevent an unrelated DNS name from rebinding to the loopback lab.
            host = self.headers.get('Host','').lower()
            try:
                name = urllib.parse.urlsplit('http://'+host).hostname
            except ValueError:
                return False
            if name not in ('127.0.0.1','localhost','::1'):
                return False
            origin = self.headers.get('Origin')
            extension_request=urllib.parse.urlsplit(self.path).path=='/api/v1/browser/inspect' and origin==EXTENSION_ORIGIN
            return origin is None or origin == 'http://'+host or extension_request

        def respond(self, status, data, content_type="application/json; charset=utf-8", cookie=None):
            if isinstance(data,dict):
                result=data.get('request',data)
                if isinstance(result,dict):
                    for field,values in [('decision',('ALLOW','BLOCK','REVIEW')),('state',('BLOCKED','SENDING','RESERVED','FORWARDED','DELIVERY_UNKNOWN','EXPIRED'))]:
                        if isinstance(result.get(field),str) and result[field] in values:self._audit_outcome[field]=result[field]
            encoded = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            if urllib.parse.urlsplit(self.path).path=='/api/v1/browser/inspect' and self.headers.get('Origin')==EXTENSION_ORIGIN:
                self.send_header('Access-Control-Allow-Origin',EXTENSION_ORIGIN)
                self.send_header('Vary','Origin')
                self.send_header('Access-Control-Allow-Methods','POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers','Authorization, Content-Type')
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'")
            if cookie:
                self.send_header("Set-Cookie", f"sedra_session_{self.server.server_port}={cookie}; Path=/; HttpOnly; SameSite={'Lax' if app.oidc else 'Strict'}")
            self.end_headers()
            self.wfile.write(encoded)

        def redirect(self,url,cookie):
            self.send_response(302);self.send_header('Location',url);self.send_header('Cache-Control','no-store')
            self.send_header('Set-Cookie',f"sedra_session_{self.server.server_port}={cookie}; Path=/; HttpOnly; SameSite=Lax")
            self.send_header('Content-Length','0');self.end_headers()

        def machine(self,path,body=None):
            route=path.path;params=urllib.parse.parse_qs(path.query)
            routes={'/api/v1/alerts':'alerts:read','/api/v1/alerts/action':'alerts:write','/api/v1/cases':'cases:read','/api/v1/cases/changes':'cases:read','/api/v1/ueba':'ueba:read','/api/v1/cases/action':'cases:write','/api/v1/telemetry':'telemetry:write','/api/v1/browser/inspect':'browser:inspect'}
            try:
                if route not in routes:return self.respond(404,{'error':'Unknown integration route'})
                writing=route in ('/api/v1/cases/action','/api/v1/alerts/action','/api/v1/telemetry','/api/v1/browser/inspect')
                if writing!=(body is not None):return self.respond(405,{'error':'Method not allowed'})
                key=app.integrations.authorize(self.headers.get('Authorization'),routes[route])
                self._audit_actor='api:'+key['id']
                if route=='/api/v1/browser/inspect':return self.respond(200,app.browser_guard.inspect(body,key))
                if route=='/api/v1/alerts':result=app.gateway.alerts_feed(before=int(params['before'][0]) if params.get('before') else None)
                elif route=='/api/v1/alerts/action':result=app.gateway.update_alert(body,actor='api:'+key['id'])
                elif route=='/api/v1/cases':result=app.case_view({'role':'analyst'})
                elif route=='/api/v1/ueba':result=app.ueba_view({'role':'analyst'},params.get('subject',['lab-001'])[0])
                elif route=='/api/v1/cases/action':
                    result=app.cases.action(body,actor='api:'+key['id'])
                elif route=='/api/v1/telemetry':
                    with app.guard:
                        result=app.integrations.ingest(body,key,{d['id'] for d in DOCUMENTS})
                        for uid in key['subjects']:app.capture_case(uid)
                else:
                    after=int(params.get('after',['0'])[0]);limit=int(params.get('limit',['100'])[0])
                    if after<0 or not 1<=limit<=100:raise ValueError('Bounded cursor/limit required')
                    freshness=app.refresh_case_signals()
                    with app.cases.db() as c:
                        c.execute('BEGIN');generation=c.execute("SELECT value FROM behavior_case_meta WHERE key='generation'").fetchone()[0]
                        if ('generation' not in params and after) or int(params.get('generation',[str(generation)])[0])!=generation:raise Conflict('Case generation changed; restart from after=0')
                        rows=c.execute('SELECT h.rowid cursor,h.payload_json,b.subject_id FROM behavior_case_history h JOIN behavior_cases b USING(case_id) WHERE h.rowid>? ORDER BY h.rowid LIMIT ?',(after,limit)).fetchall()
                    items=[]
                    for row in rows:
                        p=json.loads(row['payload_json']);snap=p.get('snapshot',{})
                        items.append({'cursor':row['cursor'],'case_id':p['case_id'],'subject_id':row['subject_id'],'revision':p['revision'],'action':p['action'],'actor':p['actor'],'at':p['at'],'priority':snap.get('priority',p.get('current_live_priority')),'channels':snap.get('channels',[]),'source_count':len(snap.get('trigger_source_ids',[]))})
                    result={'items':items,'generation':generation,'next_cursor':items[-1]['cursor'] if items else after,'delivery':'Consumer checkpoints only after processing; retry same cursor for at-least-once consumption','signal_refresh':freshness}
                return self.respond(200,result)
            except AuthError:return self.respond(401,{'error':'Valid scoped bearer key required'})
            except PermissionError as e:return self.respond(403,{'error':str(e)})
            except RateLimit as e:return self.respond(429,{'error':str(e)})
            except (Conflict,CaseConflict,AlertConflict) as e:return self.respond(409,{'error':str(e)})
            except (ValueError,KeyError,TypeError) as e:return self.respond(400,{'error':str(e)})

        def do_GET(self):
            if not self.local_origin():
                return self.respond(403, {'error':'Loopback origin required'})
            path_check=urllib.parse.urlparse(self.path)
            if path_check.path.startswith('/api/v1/'):return self.machine(path_check)
            session_id, session, fresh = self.session()
            path = urllib.parse.urlparse(self.path)
            cookie = session_id if fresh else None
            try:
                deployment_files={'/browser-deployment/updates.xml':('updates.xml','application/xml'),
                                  '/browser-deployment/sedra-browser-guard.crx':('sedra-browser-guard.crx','application/x-chrome-extension')}
                if path.path in deployment_files:
                    name,kind=deployment_files[path.path]
                    file=ROOT/'data/browser-deployment/public'/name
                    if not file.is_file():return self.respond(404,{'error':'Browser deployment package not prepared'})
                    return self.respond(200,file.read_bytes(),kind)
                if path.path=='/api/browser-lab/receipts':
                    if session['role']!='analyst':raise PermissionError('Analyst required')
                    return self.respond(200,app.browser_guard.lab_receipts(),cookie=cookie)
                if path.path=='/auth/login' and app.accounts.enabled:return self.redirect('/login',session_id)
                if path.path=='/api/account/context':
                    mfa=app.accounts.mfa.status(session.get('mfa_uid') or session.get('account_id') or '')
                    mfa['pending']=bool(session.get('mfa_uid'))
                    return self.respond(200,{'csrf_token':session['csrf_token'],'enabled':app.accounts.enabled,'mfa':mfa,'account':{k:session.get(k) for k in ('account_id','username','account_role','access_profile','subject_id','can_manage_users','can_manage_roles','permissions')},'bootstrap_allowed':not app.accounts.enabled and not app.oidc and session['role']=='analyst'},cookie=cookie)
                if path.path=='/api/accounts':
                    if 'accounts.read' not in session.get('permissions',[]):raise PermissionError('Account directory permission required')
                    return self.respond(200,app.accounts.listing()|{'subjects':sorted(app.subjects)},cookie=cookie)
                if path.path=='/auth/login' and app.oidc:
                    with app.guard:url=app.oidc.begin(session_id)
                    return self.redirect(url,session_id)
                if path.path=='/auth/callback' and app.oidc:
                    with app.guard:
                        identity,claims=app.oidc.finish(urllib.parse.parse_qs(path.query),session_id)
                        new_id,new_session=app.new_session(identity);new_session.update(principal=claims['iss']+'|'+claims['sub'],expires_at=claims['exp'])
                        app.sessions.pop(session_id,None)
                    return self.redirect('/',new_id)
                # A late background request can carry the revoked pre-MFA cookie.
                # Never overwrite a newly authenticated browser cookie on a 401.
                if (app.oidc or app.accounts.enabled) and path.path.startswith('/api/') and session['role']=='unauthenticated':return self.respond(401,{'error':'Sign-in and MFA required','login_url':'/auth/login'})
                if app.accounts.enabled and session['role']=='unauthenticated' and path.path in ('/','/index.html','/portal','/portal/','/integrations','/alert'):
                    return self.redirect('/login',session_id)
                if path.path=='/api/audit/context':
                    return self.respond(200,{'csrf_token':session['csrf_token']},cookie=cookie)
                if path.path=='/api/audit':
                    if session['role']!='analyst':raise PermissionError('Analyst required')
                    params=urllib.parse.parse_qs(path.query)
                    return self.respond(200,app.platform_audit.page(int(params['before'][0]) if params.get('before') else None,params.get('source',[''])[0],params.get('event',[''])[0],int(params.get('limit',['100'])[0])),cookie=cookie)
                if path.path=='/api/integrations/keys':
                    if session['role']!='analyst':raise PermissionError('Analyst required')
                    return self.respond(200,{'keys':app.integrations.listing(),'sso_enabled':bool(app.oidc),'accounts_enabled':app.accounts.enabled},cookie=cookie)
                if path.path == "/api/state":
                    return self.respond(200, app.view(session), cookie=cookie)
                if path.path=='/api/dashboards':
                    if session['role']!='analyst':raise PermissionError('Analyst access required for executive dashboards')
                    days=int(urllib.parse.parse_qs(path.query).get('days',['7'])[0])
                    return self.respond(200,aggregate(app,session,days),cookie=cookie)
                if path.path=='/api/reports':
                    query=urllib.parse.parse_qs(path.query);uid=query.get('id',[None])[0]
                    if not uid:return self.respond(200,{'items':app.reports.listing(session)},cookie=cookie)
                    report=app.reports.get(session,uid);kind=query.get('format',['json'])[0]
                    if kind not in ('json','csv','pdf'):raise ValueError('Supported export format required')
                    app.platform_audit.append('APPLICATION',session.get('principal') or session.get('subject_id') or 'analyst','report_exported',{'id':uid,'format':kind})
                    if kind=='csv':return self.respond(200,export_csv(report),'text/csv; charset=utf-8',cookie=cookie)
                    if kind=='pdf':return self.respond(200,export_pdf(report),'application/pdf',cookie=cookie)
                    return self.respond(200,report,cookie=cookie)
                if path.path == '/api/alerts':
                    params=urllib.parse.parse_qs(path.query)
                    alert_id=params.get('id',[None])[0]
                    before=int(params['before'][0]) if params.get('before') else None
                    return self.respond(200,app.alerts_view(session,alert_id,before),cookie=cookie)
                if path.path == '/api/ueba':
                    uid=urllib.parse.parse_qs(path.query).get('subject',[session.get('subject_id')])[0]
                    return self.respond(200,app.ueba_view(session,uid),cookie=cookie)
                if path.path == '/api/endpoint':
                    return self.respond(200,app.endpoint.view(session.get('subject_id') or 'lab-001'),cookie=cookie)
                if path.path == '/api/ueba/cases':
                    params=urllib.parse.parse_qs(path.query)
                    return self.respond(200,app.case_view(session,params.get('id',[None])[0],params.get('packet',['0'])[0]=='1'),cookie=cookie)
                if path.path == '/api/portal/status':
                    return self.respond(200, {'session': {k:v for k,v in session.items() if k != 'created_at'},
                        'data_types':detector_catalog(),
                        'connection': app.portal.status(), 'subjects': app.live_subjects([s for s in app.snapshot['subjects']
                        if session['role'] == 'analyst' or s['subject_id'] == session['subject_id']])}, cookie=cookie)
                if path.path == "/api/document":
                    doc_id = urllib.parse.parse_qs(path.query).get("id", [""])[0]
                    doc = next((d for d in DOCUMENTS if d["id"] == doc_id), None)
                    if doc is None:
                        return self.respond(404, {"error": "Unknown registered lab document"}, cookie=cookie)
                    app.audit(session["subject_id"] or "analyst", "document_read", {"doc_id": doc["id"], "doc_version": doc["version"], "classification":doc['classification'], "source": "SEDRA document endpoint", "scope": "this application only"})
                    return self.respond(200, doc | {'metadata': app.gateway.catalog_labels()[doc_id]}, cookie=cookie)
                if path.path == "/health":
                    return self.respond(200, {"status": "ok", "product":"SEDRA", "mode": "local_lab", "build_version":__version__, "model_version": app.snapshot.get("model_version")})
                allowed = {"/": "index.html", "/index.html": "index.html", "/app.js": "app.js", "/workbench.js":"workbench.js", "/workbench.css":"workbench.css", "/alerts.js":"alerts.js", "/ueba.js":"ueba.js", "/endpoint.js":"endpoint.js", "/cases.js":"cases.js", "/openapi.json":"openapi.json", "/integrations":"index.html", "/alert":"index.html", "/console.css":"console.css", "/theme.js":"theme.js", "/settings.js":"settings.js", "/settings.css":"settings.css", "/login":"login.html", "/login.js":"login.js", "/theme.css":"theme.css", "/audit.js":"audit.js", "/presentation.js":"presentation.js", "/integrations.js":"integrations.js", "/style.css": "style.css", "/sedra.css": "sedra.css",
                           '/portal':'portal.html', '/portal/':'portal.html', '/portal.js':'portal.js', '/portal.css':'portal.css',
                           '/browser-lab':'browser-lab.html','/browser-lab.js':'browser-lab.js',
                           '/browser-harness':'browser-harness.html','/browser-harness-transport.js':'browser-harness-transport.js',
                           '/browser-test/core.js':'../browser-extension/core.js','/browser-test/guard.js':'../browser-extension/guard.js'}
                if path.path not in allowed:
                    return self.respond(404, {"error": "Not found"})
                file = ROOT / "static" / allowed[path.path]
                return self.respond(200, file.read_bytes(), (mimetypes.guess_type(file.name)[0] or "application/octet-stream") + "; charset=utf-8", cookie=cookie)
            except PermissionError as exc:
                return self.respond(403,{'error':str(exc)},cookie=cookie)
            except (ValueError,KeyError) as exc:
                return self.respond(404,{'error':str(exc)},cookie=cookie)
            except Exception:
                traceback.print_exc()
                return self.respond(500, {"error": "Local application error; inspect the terminal log"}, cookie=cookie)

        def do_OPTIONS(self):
            if urllib.parse.urlsplit(self.path).path!='/api/v1/browser/inspect' or not self.local_origin():
                return self.respond(403,{'error':'Extension origin required'})
            return self.respond(200,{})

        def do_POST(self):
            try:
                length = int(self.headers.get('Content-Length','0'))
            except ValueError:
                return self.respond(413, {'error':'Invalid request length'})
            limit=1600000 if urllib.parse.urlsplit(self.path).path=='/api/v1/browser/inspect' else 100000
            if not 0 < length <= limit:
                return self.respond(413, {'error':'Request body is too large or missing'})
            raw_body = self.rfile.read(length)
            if not self.local_origin():
                return self.respond(403, {'error':'Loopback origin required'})
            route_check=urllib.parse.urlparse(self.path)
            if route_check.path.startswith('/api/v1/'):
                try:
                    if self.headers.get('Content-Type','').split(';')[0]!='application/json':raise ValueError('JSON required')
                    body=json.loads(raw_body)
                    if not isinstance(body,dict):raise ValueError('Object required')
                except (ValueError,TypeError):return self.respond(400,{'error':'Valid JSON object required'})
                return self.machine(route_check,body)
            session_id, session, fresh = self.session()
            if (app.oidc or app.accounts.enabled) and session['role']=='unauthenticated' and route_check.path not in ('/api/account/login','/api/account/mfa/enroll','/api/account/mfa/verify','/api/logout'):return self.respond(401,{'error':'Sign-in and MFA required'})
            if fresh or not hmac.compare_digest(self.headers.get("X-CSRF-Token", "").encode(), session["csrf_token"].encode()):
                return self.respond(403, {"error": "Valid session and CSRF token required; refresh the workbench"})
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                return self.respond(415, {"error": "Use application/json"})
            try:
                body = json.loads(raw_body)
                if not isinstance(body, dict):
                    raise ValueError("A JSON object is required")
                route = urllib.parse.urlparse(self.path).path
                action=body.get('action')
                self._audit_operation=action if isinstance(action,str) and action in ('revoke','start','stop','probe','ACKNOWLEDGE','READ','RESOLVE','REOPEN') else 'submit'
                if route=='/api/reports':
                    report=app.reports.create(app,session,body)
                    app.platform_audit.append('APPLICATION',session.get('principal') or session.get('subject_id') or 'analyst','report_generated',{'id':report['id'],'template':report['template']})
                    return self.respond(200,report)
                if route=='/api/account/login':
                    claims=app.accounts.login(body,with_claims=True);new_id,new_session=app.new_session();new_session.update(mfa_uid=claims['account_id'],mfa_version=claims['auth_version'],mfa_started=time.time());self._audit_actor=claims['principal']
                    with app.guard:app.sessions.pop(session_id,None)
                    return self.respond(200,{'signed_in':False,'mfa_required':True,'enrollment_required':not app.accounts.mfa.status(claims['account_id'])['enrolled']},cookie=new_id)
                if route in ('/api/account/mfa/enroll','/api/account/mfa/verify'):
                    uid=session.get('mfa_uid')
                    if not uid:raise PermissionError('A current password-verified sign-in is required')
                    if route.endswith('/enroll'):
                        if body or app.accounts.mfa.status(uid)['enrolled']:raise PermissionError('Authenticator enrollment unavailable')
                        if not session.get('mfa_enrollment'):session['mfa_enrollment']=app.accounts.mfa.enrollment(app.accounts.claims(uid)['username'])
                        return self.respond(200,session['mfa_enrollment'])
                    if set(body)!={'code'}:raise ValueError('Authenticator or recovery code required')
                    enrolled=app.accounts.mfa.status(uid)['enrolled']
                    result=app.accounts.mfa.verify(uid,session['mfa_version'],body['code'],enrollment_seed=session.get('mfa_enrollment',{}).get('secret') if not enrolled else None)
                    new_id,new_session=app.new_session();new_session.update(result['claims'],mfa_verified=True);self._audit_actor=new_session['principal']
                    with app.guard:app.sessions.pop(session_id,None)
                    app.platform_audit.append('APPLICATION',new_session['principal'],'mfa_verified' if enrolled else 'mfa_enrolled',{'recovery_used':result['used_recovery']})
                    return self.respond(200,{'signed_in':True,'recovery_codes':result['recovery_codes']},cookie=new_id)
                if route=='/api/account/bootstrap':
                    if app.accounts.enabled or app.oidc or session['role']!='analyst':raise PermissionError('First Administrator setup unavailable')
                    uid=app.accounts.create_user(body,app.subjects,bootstrap=True)
                    with app.guard:app.sessions.clear()
                    claims=app.accounts.claims(uid);new_id,new_session=app.new_session();new_session.update(mfa_uid=uid,mfa_version=claims['auth_version'],mfa_started=time.time());self._audit_actor=claims['principal']
                    return self.respond(200,{'initialized':True,'mfa_required':True},cookie=new_id)
                if route in ('/api/accounts/users','/api/accounts/roles','/api/accounts/password'):
                    if route.endswith('/roles'):
                        if not session.get('can_manage_roles'):raise PermissionError('Administrator required for role permissions')
                        uid=app.accounts.create_role(body);event='role_updated' if body.get('action')=='update' else 'role_created'
                    elif route.endswith('/password'):
                        if 'accounts.reset_password' not in session.get('permissions',[]):raise PermissionError('Password reset permission required')
                        app.accounts.reset_password(body,session);uid=body['id'];event='account_password_reset'
                    elif body.get('action')=='update':app.accounts.update_user({k:v for k,v in body.items() if k!='action'},app.subjects,actor=session);uid=body['id'];event='account_updated'
                    else:uid=app.accounts.create_user(body,app.subjects,actor=session);event='account_created'
                    app.platform_audit.append('APPLICATION',session['principal'],event,{'id':uid})
                    return self.respond(200,{'saved':True})
                if route=='/api/audit/ui':
                    app.platform_audit.ui(session.get('subject_id') or session['role'],body)
                    return self.respond(200,{'recorded':True})
                if route=='/api/browser-lab/inspect':
                    if session['role']!='analyst':raise PermissionError('Analyst required for the explicit local DOM harness')
                    if body.get('host')!='sedra-browser-lab':raise ValueError('Local harness destination only')
                    return self.respond(200,app.browser_guard.inspect(body,{'subjects':['lab-001']},source='LOCAL_BROWSER_DOM_HARNESS'))
                if route=='/api/browser-lab/receive':return self.respond(200,app.browser_guard.lab_receive(body))
                if route=='/api/integrations/keys':
                    if session['role']!='analyst':raise PermissionError('Analyst required')
                    if body.get('action')=='revoke' and set(body)=={'action','id'}:return self.respond(200,app.integrations.revoke(body['id']))
                    return self.respond(200,app.integrations.create(body,app.subjects))
                if route=='/api/logout':
                    with app.guard:app.sessions.pop(session_id,None)
                    return self.respond(200,{'logged_out':True})
                if route == "/api/session":
                    if app.oidc or app.accounts.enabled:raise PermissionError('Identity switching is disabled with authenticated accounts')
                    identity = body.get("identity")
                    if identity not in ("analyst", "lab-001", "lab-002"):
                        raise ValueError("Choose a declared laboratory identity")
                    new_id, new_session = app.new_session(identity)
                    with app.guard:
                        app.sessions.pop(session_id, None)
                    return self.respond(200, {"session": {k: v for k, v in new_session.items() if k != "created_at"}}, cookie=new_id)
                if route == "/api/transfer":
                    return self.respond(200, app.transfer(session, body))
                if route == '/api/alerts/action':
                    return self.respond(200,app.update_alert(session,body))
                if route == '/api/endpoint/action':
                    return self.respond(200,app.endpoint_action(session,body))
                if route == '/api/ueba/cases/action':
                    return self.respond(200,app.case_action(session,body))
                if route == '/api/ueba/counterfactual':
                    return self.respond(200,app.explain_policy(session,body))
                if route == '/api/catalog/labels':
                    return self.respond(200, {'metadata': app.update_labels(session, body)})
                if route == '/api/portal/configure':
                    return self.respond(200, {'connection': app.portal.configure(session, body)})
                if route == '/api/portal/chat':
                    return self.respond(200, app.portal.chat(session, body))
                if route == "/api/reconcile":
                    return self.respond(200, app.reconcile(session, body))
                if route == "/api/reset":
                    if session["role"] != "analyst":
                        raise PermissionError("Only the analyst demo role may reset the laboratory")
                    app.reset()
                    return self.respond(200, {"reset": True})
                return self.respond(404, {"error": "Not found"})
            except (AlertConflict,CaseConflict) as exc:
                return self.respond(409,{'error':str(exc)})
            except PermissionError as exc:
                return self.respond(403, {"error": str(exc)})
            except (ValueError, TypeError, KeyError) as exc:
                return self.respond(400, {"error": str(exc)})
            except Exception:
                traceback.print_exc()
                return self.respond(500, {"error": "Local application error; inspect the terminal log"})
    return Handler


def main():
    parser = argparse.ArgumentParser(description="Run the offline SEDRA laboratory")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8765")))
    parser.add_argument("--data-dir", default=None)
    parser.add_argument("--start-local-sensor", action="store_true", help="Explicitly opt in to the scoped local Windows metadata sensor")
    args = parser.parse_args()
    if args.host not in ('127.0.0.1','localhost'):
        parser.error('This demonstration must bind to loopback: 127.0.0.1 or localhost')
    app = AppState(args.data_dir)
    try:
        server = ThreadingHTTPServer((args.host, args.port), handler_for(app))
    except OSError as exc:
        app.close()
        parser.exit(1,f'Cannot open local port {args.port}: {exc}. Use the existing lab or choose --port 8766.\n')
    if args.start_local_sensor:app.endpoint.start()
    print(f"SEDRA local service: http://{args.host}:{server.server_port}", flush=True)
    print("Synthetic live lab; simulated identities; independent local HTTP receiver. Historical CERT reports remain separate.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.close()


if __name__ == "__main__":
    main()
