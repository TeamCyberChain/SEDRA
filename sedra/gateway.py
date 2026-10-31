"""Durable, atomic gateway admission and honest delivery accounting.

This module does not perform network I/O. The caller must claim_send(), send the
unchanged message, and report the independently observed receiver outcome.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import json
import math
import sqlite3
import time
import uuid

from .mosaic import FragmentMatcher, MATCHING_PROFILE, NORMALIZATION_PROFILE, validate_text
from .labels import default_control, validate_control, catalog_metadata, request_labels
from .content_security import STRUCTURED_PROFILE
from .alerts import AlertStore
from .policy_explain import limits as policy_limits


POLICY_PROFILE = "sedra-dual-window-anchored-token-restricted-v2"
WINDOW_SECONDS = 86_400
LONG_WINDOW_SECONDS = 30 * WINDOW_SECONDS
LONG_NORMAL_THRESHOLD = .35
LONG_HIGH_THRESHOLD = .20
RESERVATION_TTL = 30
NORMAL_THRESHOLD = 0.20
HIGH_THRESHOLD = 0.10
HIGH_BEHAVIOR_SCORE = 70
_BUDGET_STATES = {"FORWARDED_CONFIRMED", "RESERVED", "SENDING", "DELIVERY_UNKNOWN"}


def _clock(now=None) -> float:
    value = time.time() if now is None else float(now)
    if not math.isfinite(value):
        raise ValueError("now must be finite Unix seconds")
    return value


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _key(doc_id: str, version: str) -> str:
    return doc_id + "\x00" + version


def _identifier(value, name):
    if not isinstance(value, str) or not value or len(value) > 200:
        raise ValueError(f"{name} must be nonempty text of at most 200 characters")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


class Gateway(AlertStore):
    def __init__(self, db_path, documents: list[dict]):
        self.matcher = FragmentMatcher(documents)
        self._anchor = None
        if str(db_path) == ":memory:":
            self._db_target = f"file:sedra-{uuid.uuid4().hex}?mode=memory&cache=shared"
            self._uri = True
            self._anchor = sqlite3.connect(self._db_target, uri=True)
        else:
            path = Path(db_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._db_target = str(path)
            self._uri = False
        with self._connection() as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript("""
                CREATE TABLE IF NOT EXISTS gateway_documents (
                    doc_id TEXT NOT NULL, version TEXT NOT NULL, source_sha256 TEXT NOT NULL,
                    manifest_json TEXT NOT NULL, PRIMARY KEY(doc_id, version)
                );
                CREATE TABLE IF NOT EXISTS gateway_requests (
                    row_id INTEGER PRIMARY KEY,
                    subject_id TEXT NOT NULL, request_id TEXT NOT NULL,
                    destination TEXT NOT NULL, trust_class TEXT NOT NULL,
                    body_sha256 TEXT NOT NULL, body_bytes INTEGER NOT NULL,
                    created_at REAL NOT NULL, updated_at REAL NOT NULL,
                    expires_at REAL, send_started_at REAL,
                    decision TEXT NOT NULL, state TEXT NOT NULL,
                    behavior_score REAL NOT NULL, threshold REAL NOT NULL,
                    reason_codes_json TEXT NOT NULL, fingerprints_json TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    UNIQUE(subject_id, request_id)
                );
                CREATE INDEX IF NOT EXISTS gateway_actor_window
                    ON gateway_requests(subject_id, trust_class, created_at);
                CREATE INDEX IF NOT EXISTS gateway_actor_time ON gateway_requests(subject_id,created_at);
                CREATE TABLE IF NOT EXISTS document_controls (
                    doc_id TEXT PRIMARY KEY, control_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS document_control_history (
                    id INTEGER PRIMARY KEY, doc_id TEXT NOT NULL, revision INTEGER NOT NULL,
                    at REAL NOT NULL, actor TEXT NOT NULL, before_json TEXT NOT NULL, after_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gateway_transitions (
                    transition_id INTEGER PRIMARY KEY, row_id INTEGER NOT NULL,
                    at REAL NOT NULL, old_state TEXT, new_state TEXT NOT NULL, reason TEXT NOT NULL,
                    FOREIGN KEY(row_id) REFERENCES gateway_requests(row_id)
                );
            """)
            self._init_alerts(con)
        with self._transaction() as con:
            self._backfill_alerts(con,time.time())
            for doc in self.matcher.documents.values():
                manifest = {name: doc[name] for name in (
                    "id", "title", "version", "language", "classification", "source_sha256",
                    "denominator", "token_count", "total_distinct_grams", "token_denominator"
                )}
                manifest['matching_profile'] = MATCHING_PROFILE
                prior = con.execute(
                    "SELECT manifest_json FROM gateway_documents WHERE doc_id=? AND version=?",
                    (doc["id"], doc["version"]),
                ).fetchone()
                if prior and prior["manifest_json"] != _json(manifest):
                    raise ValueError("document content or matching manifest changed without a version change")
                con.execute(
                    "INSERT OR IGNORE INTO gateway_documents VALUES (?,?,?,?)",
                    (doc["id"], doc["version"], doc["source_sha256"], _json(manifest)),
                )

    @contextmanager
    def _connection(self):
        con = sqlite3.connect(self._db_target, timeout=15, isolation_level=None, uri=self._uri)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA busy_timeout=15000")
        try:
            yield con
        finally:
            con.close()

    def _control(self, con, doc):
        row = con.execute('SELECT control_json FROM document_controls WHERE doc_id=?', (doc['id'],)).fetchone()
        return json.loads(row['control_json']) if row else default_control(doc)

    def catalog_labels(self):
        with self._connection() as con:
            return {doc['id']: catalog_metadata(doc, self._control(con, doc))
                    for doc in self.matcher.documents.values()}

    def update_labels(self, body, actor='analyst', now=None):
        """The HTTP layer authorizes the analyst. Serialize updates with admissions."""
        doc = self.matcher.documents.get(body.get('doc_id'))
        if doc is None:
            raise ValueError('Unknown registered document')
        changes = validate_control(doc, body)
        now = _clock(now)
        with self._transaction() as con:
            before = self._control(con, doc)
            if before['revision'] != body['expected_revision']:
                raise ValueError('Label revision changed; refresh before saving')
            after = {**before, **changes, 'revision': before['revision'] + 1,
                     'updated_at': now, 'updated_by': actor}
            con.execute('INSERT OR REPLACE INTO document_controls VALUES (?,?)', (doc['id'], _json(after)))
            con.execute('INSERT INTO document_control_history(doc_id,revision,at,actor,before_json,after_json) VALUES(?,?,?,?,?,?)',
                        (doc['id'], after['revision'], now, actor, _json(before), _json(after)))
            return catalog_metadata(doc, after)

    def label_history(self):
        with self._connection() as con:
            return [{'doc_id': r['doc_id'], 'revision': r['revision'], 'at': r['at'], 'actor': r['actor'],
                     'before': json.loads(r['before_json']), 'after': json.loads(r['after_json'])}
                    for r in con.execute('SELECT * FROM document_control_history ORDER BY id DESC LIMIT 100')]

    @contextmanager
    def _transaction(self):
        with self._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                yield con
                con.commit()
            except Exception:
                con.rollback()
                raise

    def _row(self, con, subject_id, request_id):
        row = con.execute(
            "SELECT * FROM gateway_requests WHERE subject_id=? AND request_id=?",
            (subject_id, request_id),
        ).fetchone()
        if row is None:
            raise KeyError("request not found for this subject")
        return row

    def _transition(self, con, row, state, now, reason):
        con.execute(
            "UPDATE gateway_requests SET state=?,updated_at=? WHERE row_id=?",
            (state, now, row["row_id"]),
        )
        con.execute("INSERT INTO gateway_transitions(row_id,at,old_state,new_state,reason) VALUES(?,?,?,?,?)",
                    (row["row_id"], now, row["state"], state, reason))
        if state=='DELIVERY_UNKNOWN':
            self._record_alert(con,self._row(con,row['subject_id'],row['request_id']),'DELIVERY_UNKNOWN',now)

    def _expire(self, con, now):
        expired, recovered = [], []
        for row in con.execute(
            "SELECT * FROM gateway_requests WHERE state='RESERVED' AND expires_at<=?", (now,)
        ).fetchall():
            self._transition(con, row, "EXPIRED_UNUSED", now, "UNUSED_RESERVATION_TTL")
            expired.append({"subject_id": row["subject_id"], "request_id": row["request_id"]})
        for row in con.execute(
            "SELECT * FROM gateway_requests WHERE state='SENDING' AND send_started_at<=?",
            (now - RESERVATION_TTL,),
        ).fetchall():
            self._transition(con, row, "DELIVERY_UNKNOWN", now, "STALE_SEND_REQUIRES_RECONCILIATION")
            recovered.append({"subject_id": row["subject_id"], "request_id": row["request_id"]})
        return {"expired_unused": expired, "recovered_unknown": recovered,
                "expired_count": len(expired), "unknown_count": len(recovered)}

    def _coverage(self, con, subject_id, trust_class, now, window_seconds=WINDOW_SECONDS):
        by_doc = {}
        rows = con.execute(
            "SELECT state,created_at,fingerprints_json FROM gateway_requests "
            "WHERE subject_id=? AND trust_class=? AND (created_at>=? OR state='DELIVERY_UNKNOWN')",
            (subject_id, trust_class, now - window_seconds),
        ).fetchall()
        for row in rows:
            for doc_key, values in json.loads(row["fingerprints_json"]).items():
                sets = by_doc.setdefault(doc_key, {name: set() for name in (
                    "attempted", "forwarded", "reserved", "unknown", "blocked"
                )})
                incoming = set(values)
                if row["created_at"] >= now - window_seconds:
                    sets["attempted"].update(incoming)
                state = row["state"]
                if state == "FORWARDED_CONFIRMED":
                    sets["forwarded"].update(incoming)
                elif state in ("RESERVED", "SENDING"):
                    sets["reserved"].update(incoming)
                elif state == "DELIVERY_UNKNOWN":
                    sets["unknown"].update(incoming)
                elif state == "BLOCKED":
                    sets["blocked"].update(incoming)
        return by_doc

    @staticmethod
    def _metric(doc, sets, prospective=None):
        denominator = doc["denominator"]
        def fraction(count):
            return count / denominator if denominator else 0.0
        coverage = {}
        for name in ("attempted", "forwarded", "reserved", "unknown", "blocked"):
            count = len(sets.get(name, set()))
            coverage[name] = {"count": count, "ratio": fraction(count)}
        committed = sets.get("forwarded", set()) | sets.get("reserved", set()) | sets.get("unknown", set())
        coverage["committed"] = {"count": len(committed), "ratio": fraction(len(committed))}
        if prospective is not None:
            coverage["prospective"] = {"count": len(prospective), "ratio": fraction(len(prospective))}
        return coverage

    def _response(self, con, row, now, replay=False):
        result = json.loads(row["snapshot_json"])
        result['alert_ids']=[a['alert_id'] for a in con.execute('SELECT alert_id FROM security_alerts WHERE request_row_id=? ORDER BY seq',(row['row_id'],))]
        result.update({
            "state": row["state"], "request_state": row["state"],
            "new_state": row["state"], "updated_at": row["updated_at"],
            "send_started_at": row["send_started_at"],
            "expires_at": row["expires_at"], "idempotent_replay": replay,
        })
        history = con.execute(
            "SELECT at,old_state,new_state,reason FROM gateway_transitions WHERE row_id=? ORDER BY transition_id",
            (row["row_id"],),
        ).fetchall()
        result["history"] = [dict(item) for item in history]
        result["old_state"] = history[-1]["old_state"] if history else None
        by_doc = self._coverage(con, row["subject_id"], row["trust_class"], now)
        for doc in result["matched_documents"]:
            sets = by_doc.get(_key(doc["doc_id"], doc["version"]), {})
            current = self._metric(doc, sets)
            doc["coverage"] = {**current, "prospective": doc["evaluation_coverage"]["prospective"]}
            for name in ("attempted", "forwarded", "reserved", "unknown", "blocked", "committed"):
                doc[f"{name}_coverage"] = current[name]["ratio"]
                doc[f"{name}_count"] = current[name]["count"]
        return result

    def evaluate(self, subject_id, request_id, text, behavior_score,
                 destination="public_ai", now=None, behavior_context=None, preview=False, inspection_block=None) -> dict:
        subject_id = _identifier(subject_id, "subject_id")
        request_id = _identifier(request_id, "request_id")
        destination = _identifier(destination, "destination")
        raw = validate_text(text)
        body_hash = sha256(raw).hexdigest()
        score = float(behavior_score)
        if not math.isfinite(score) or not 0 <= score <= 100:
            raise ValueError("behavior_score must be a finite value between 0 and 100")
        now = _clock(now)
        trust_class = "approved_ai" if destination == "approved_ai" else "unapproved_ai"
        inspected = self.matcher.inspect(text)
        budget=policy_limits(score)
        threshold=budget['threshold'];long_threshold=budget['long_threshold']
        token_threshold=budget['token_threshold'];long_token_threshold=budget['long_token_threshold']

        with self._transaction() as con:
            self._expire(con, now)
            prior = con.execute(
                "SELECT * FROM gateway_requests WHERE subject_id=? AND request_id=?", (subject_id, request_id)
            ).fetchone()
            if prior:
                if prior["body_sha256"] != body_hash or prior["destination"] != destination:
                    raise ValueError("idempotency key reused with a different body or destination")
                return self._response(con, prior, now, replay=True)

            coverage = self._coverage(con, subject_id, trust_class, now)
            long_coverage = self._coverage(con, subject_id, trust_class, now, LONG_WINDOW_SECONDS)
            block_reasons, info_reasons = ([inspection_block] if inspection_block else []), []
            if inspected["contains_demo_secret"]:
                block_reasons.append("KNOWN_DEMO_SECRET")
            for finding in inspected['structured_findings']:
                block_reasons.append('STRUCTURED_' + finding['type'])
            if inspected['mixed_script_tokens']:
                info_reasons.append('MIXED_SCRIPT_CONTENT_INSPECTED')
            if inspected["removed_default_ignorables"]:
                info_reasons.append("DEFAULT_IGNORABLES_NORMALIZED")
            matched = []
            request_grams = {}
            for found in inspected["matched_documents"]:
                doc = dict(found)
                source = self.matcher.documents[doc['doc_id']]
                control = self._control(con, source)
                doc['effective_sensitivity'] = control['sensitivity']
                doc['label_snapshot'] = control
                incoming = set(doc.pop("eligible_fingerprints"))
                token_incoming = set(doc.pop('token_fingerprints'))
                doc_key = _key(doc["doc_id"], doc["version"])
                request_grams[doc_key] = sorted(incoming)
                request_grams[doc_key + '\x00tokens-v2'] = sorted(token_incoming)
                sets = coverage.get(doc_key, {})
                prospective = (sets.get("forwarded", set()) | sets.get("reserved", set()) |
                               sets.get("unknown", set()) | incoming)
                evaluation = self._metric(doc, sets, prospective)
                doc["evaluation_coverage"] = evaluation
                doc["prospective_coverage"] = evaluation["prospective"]["ratio"]
                doc["prospective_count"] = evaluation["prospective"]["count"]
                doc["request_coverage"] = len(incoming) / doc["denominator"] if doc["denominator"] else 0.0
                token_doc = {'denominator':doc['token_denominator']}
                token_sets = coverage.get(doc_key + '\x00tokens-v2', {})
                long_sets = long_coverage.get(doc_key, {})
                long_token_sets = long_coverage.get(doc_key + '\x00tokens-v2', {})
                def committed(sets):
                    return sets.get('forwarded',set()) | sets.get('reserved',set()) | sets.get('unknown',set())
                token_metric = self._metric(token_doc, token_sets, committed(token_sets) | token_incoming)
                long_metric = self._metric(doc, long_sets, committed(long_sets) | incoming)
                long_token_metric = self._metric(token_doc, long_token_sets, committed(long_token_sets) | token_incoming)
                doc['token_evaluation_coverage'] = token_metric
                doc['long_evaluation_coverage'] = long_metric
                doc['long_token_evaluation_coverage'] = long_token_metric
                doc['token_prospective_coverage'] = token_metric['prospective']['ratio']
                doc['long_prospective_coverage'] = max(long_metric['prospective']['ratio'], long_token_metric['prospective']['ratio'])
                if (incoming or token_incoming) and control['sensitivity'] == 'restricted':
                    block_reasons.append("RESTRICTED_DOCUMENT_MATCH")
                    if doc['classification'] != 'restricted':
                        block_reasons.append('GOVERNED_RESTRICTED_LABEL')
                elif (incoming or token_incoming) and doc["classification"] == "controlled_excerpt" and trust_class == "unapproved_ai":
                    if doc["prospective_coverage"] >= threshold or doc['token_prospective_coverage'] >= token_threshold:
                        block_reasons.append("CUMULATIVE_DISCLOSURE_LIMIT")
                    if long_metric['prospective']['ratio'] >= long_threshold or long_token_metric['prospective']['ratio'] >= long_token_threshold:
                        block_reasons.append('CUMULATIVE_30D_DISCLOSURE_LIMIT')
                matched.append(doc)
            if not any(item["confirmed"] for item in matched):
                info_reasons.append("NO_ELIGIBLE_PROTECTED_MATCH")
            elif trust_class == "approved_ai":
                info_reasons.append("APPROVED_ROUTE_CONTROLLED_EXCERPT")
            elif not block_reasons:
                info_reasons.append("WITHIN_DISCLOSURE_BUDGET")
            if score >= HIGH_BEHAVIOR_SCORE:
                info_reasons.append("HIGH_BEHAVIOR_TIGHTENS_EXCERPT_LIMIT")

            decision = "BLOCK" if block_reasons else "ALLOW"
            state = "BLOCKED" if block_reasons else "RESERVED"
            reasons = list(dict.fromkeys(block_reasons + info_reasons))
            result = {
                "request_id": request_id, "subject_id": subject_id,
                "decision": decision, "request_state": state, "state": state,
                "reason_codes": reasons, "behavior_score": score, "threshold": threshold,
                "behavior_context": behavior_context or {},
                "long_threshold": long_threshold, "long_window_seconds": LONG_WINDOW_SECONDS,
                "token_threshold": token_threshold, "long_token_threshold": long_token_threshold,
                "structured_findings": inspected['structured_findings'],
                "security_tags": request_labels(matched, inspected['structured_findings']),
                "destination": destination, "destination_trust_class": trust_class,
                "matched_documents": matched,
                "model_profiles": {"normalization": NORMALIZATION_PROFILE,
                                   "structured": STRUCTURED_PROFILE,
                                   "matching": MATCHING_PROFILE, "policy": POLICY_PROFILE},
                "created_at": now, "body_sha256": body_hash, "body_bytes": len(raw),
                "minimum_candidate_tokens": 2,
                "token_counts": inspected["token_counts"],
                "normalization_flags": {"removed_default_ignorables": inspected["removed_default_ignorables"],
                                        "mixed_script_tokens": inspected['mixed_script_tokens']},
                "window_seconds": WINDOW_SECONDS,
            }
            if preview and decision == 'ALLOW':
                return result | {'state':'PREVIEW_ALLOWED','request_state':'PREVIEW_ALLOWED','idempotent_replay':False}
            expires = now + RESERVATION_TTL if state == "RESERVED" else None
            cursor = con.execute(
                "INSERT INTO gateway_requests(subject_id,request_id,destination,trust_class,body_sha256,body_bytes,"
                "created_at,updated_at,expires_at,decision,state,behavior_score,threshold,reason_codes_json,"
                "fingerprints_json,snapshot_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (subject_id, request_id, destination, trust_class, body_hash, len(raw), now, now, expires,
                 decision, state, score, threshold, _json(reasons), _json(request_grams), _json(result)),
            )
            con.execute("INSERT INTO gateway_transitions(row_id,at,old_state,new_state,reason) VALUES(?,?,?,?,?)",
                        (cursor.lastrowid, now, None, state, "POLICY_EVALUATION"))
            if decision=='BLOCK':
                self._record_alert(con,self._row(con,subject_id,request_id),'POLICY_BLOCK',now)
            return self._response(con, self._row(con, subject_id, request_id), now)

    def claim_send(self, request_id, subject_id, now=None) -> dict:
        now = _clock(now)
        with self._transaction() as con:
            self._expire(con, now)
            row = self._row(con, subject_id, request_id)
            if row["state"] != "RESERVED":
                raise ValueError(f"cannot claim send from {row['state']}")
            self._transition(con, row, "SENDING", now, "OUTBOUND_SEND_CLAIMED")
            con.execute("UPDATE gateway_requests SET send_started_at=? WHERE row_id=?", (now, row["row_id"]))
            return self._response(con, self._row(con, subject_id, request_id), now)

    def confirm_forwarded(self, request_id, subject_id, now=None) -> dict:
        now = _clock(now)
        with self._transaction() as con:
            row = self._row(con, subject_id, request_id)
            if row["state"] not in ("SENDING", "DELIVERY_UNKNOWN", "FORWARDED_CONFIRMED"):
                raise ValueError(f"cannot confirm forwarding from {row['state']}")
            if row["state"] != "FORWARDED_CONFIRMED":
                self._transition(con, row, "FORWARDED_CONFIRMED", now, "RECEIVER_ACKNOWLEDGED")
            return self._response(con, self._row(con, subject_id, request_id), now)

    def mark_unknown(self, request_id, subject_id, now=None) -> dict:
        now = _clock(now)
        with self._transaction() as con:
            row = self._row(con, subject_id, request_id)
            if row["state"] not in ("SENDING", "DELIVERY_UNKNOWN"):
                raise ValueError(f"cannot mark unknown from {row['state']}")
            if row["state"] != "DELIVERY_UNKNOWN":
                self._transition(con, row, "DELIVERY_UNKNOWN", now, "OUTBOUND_RESULT_UNCERTAIN")
            return self._response(con, self._row(con, subject_id, request_id), now)

    def reconcile(self, request_id, subject_id, delivered: bool, now=None) -> dict:
        if type(delivered) is not bool:
            raise ValueError("delivered must be a trusted boolean receiver result")
        now = _clock(now)
        wanted = "FORWARDED_CONFIRMED" if delivered else "NOT_SENT_CONFIRMED"
        with self._transaction() as con:
            row = self._row(con, subject_id, request_id)
            if row["state"] == wanted:
                return self._response(con, row, now, replay=True)
            if row["state"] not in ("SENDING", "DELIVERY_UNKNOWN"):
                raise ValueError(f"cannot reconcile {row['state']} to {wanted}")
            self._transition(con, row, wanted, now,
                             "TRUSTED_RECEIVER_CONFIRMED" if delivered else "TRUSTED_NO_SEND_CONFIRMED")
            return self._response(con, self._row(con, subject_id, request_id), now)

    def expire_unused(self, now=None) -> dict:
        now = _clock(now)
        with self._transaction() as con:
            return self._expire(con, now)

    def get_request(self, request_id, subject_id, now=None) -> dict:
        now = _clock(now)
        with self._transaction() as con:
            self._expire(con, now)
            return self._response(con, self._row(con, subject_id, request_id), now)

    def requests(self, subject_id=None, now=None) -> list[dict]:
        now = _clock(now)
        with self._transaction() as con:
            self._expire(con, now)
            if subject_id is None:
                rows = con.execute("SELECT * FROM gateway_requests ORDER BY created_at,row_id").fetchall()
            else:
                rows = con.execute("SELECT * FROM gateway_requests WHERE subject_id=? ORDER BY created_at,row_id",
                                   (subject_id,)).fetchall()
            return [self._response(con, row, now) for row in rows]

    def summary(self, subject_id, now=None) -> dict:
        now = _clock(now)
        with self._transaction() as con:
            self._expire(con, now)
            rows = con.execute("SELECT state FROM gateway_requests WHERE subject_id=?", (subject_id,)).fetchall()
            result = {"subject_id": subject_id, "as_of": now, "window_seconds": WINDOW_SECONDS,
                      "request_count": len(rows), "counts": dict(Counter(row["state"] for row in rows)),
                      "documents": [], "coverage_metric": "distinct eligible normalized source 4-grams"}
            manifests = con.execute("SELECT manifest_json FROM gateway_documents ORDER BY doc_id,version").fetchall()
            for trust_class in ("unapproved_ai", "approved_ai"):
                coverage = self._coverage(con, subject_id, trust_class, now)
                for record in manifests:
                    doc = json.loads(record["manifest_json"])
                    if doc["classification"] == "public":
                        continue
                    sets = coverage.get(_key(doc["id"], doc["version"]), {})
                    metric = self._metric(doc, sets)
                    item = {**doc, "doc_id": doc["id"], "destination_trust_class": trust_class,
                            "coverage": metric}
                    for name, values in metric.items():
                        item[f"{name}_coverage"] = values["ratio"]
                        item[f"{name}_count"] = values["count"]
                    result["documents"].append(item)
            return result

    def reset_demo(self) -> dict:
        """Explicit demo-only reset. Caller must authorize and quiesce senders.

        The HTTP application owns authorization and its active-transfer guard.
        This deletes only this gateway's synthetic request/transition ledger;
        the registered source manifest and matcher remain unchanged.
        """
        with self._transaction() as con:
            count = con.execute("SELECT count(*) AS n FROM gateway_requests").fetchone()["n"]
            con.execute('DELETE FROM security_alert_actions')
            con.execute('DELETE FROM security_alerts')
            con.execute("UPDATE security_alert_meta SET value=value+1 WHERE key='generation'")
            con.execute("DELETE FROM gateway_transitions")
            con.execute("DELETE FROM gateway_requests")
            return {"state": "DEMO_RESET", "request_state": "DEMO_RESET",
                    "deleted_requests": count, "documents_preserved": len(self.matcher.documents)}
