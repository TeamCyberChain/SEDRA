"""Independent localhost HTTP receiver: proof of actual delivery, not an LLM."""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
import hmac
import json
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def utcnow():
    return datetime.now(timezone.utc).isoformat()


class ReceiverStore:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS receipts (subject_id TEXT, request_id TEXT, received_at TEXT, sha256 TEXT, payload TEXT, PRIMARY KEY(subject_id,request_id))")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def receive(self, subject_id, request_id, text):
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT * FROM receipts WHERE subject_id=? AND request_id=?", (subject_id, request_id)).fetchone()
            if existing:
                if existing["sha256"] != digest:
                    raise ValueError("Receiver idempotency key reused with different payload")
                return self._public(existing)
            db.execute("INSERT INTO receipts VALUES (?,?,?,?,?)", (subject_id, request_id, utcnow(), digest, text))
            return self._public(db.execute("SELECT * FROM receipts WHERE subject_id=? AND request_id=?", (subject_id, request_id)).fetchone())

    @staticmethod
    def _public(row):
        return {k: row[k] for k in ("subject_id", "request_id", "received_at", "sha256")} | {"preview": row["payload"][:160], "utf8_bytes": len(row["payload"].encode("utf-8"))}

    def receipt(self, subject_id, request_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM receipts WHERE subject_id=? AND request_id=?", (subject_id, request_id)).fetchone()
            return self._public(row) if row else None

    def list(self, subject_id=None):
        with self.connect() as db:
            rows = db.execute("SELECT * FROM receipts " + ("WHERE subject_id=? " if subject_id else "") + "ORDER BY received_at DESC", (subject_id,) if subject_id else ()).fetchall()
            return [self._public(row) for row in rows]

    def clear(self):
        with self.connect() as db:
            db.execute("DELETE FROM receipts")


def start_receiver(path, token):
    store = ReceiverStore(path)

    class Handler(BaseHTTPRequestHandler):
        server_version = "SADD-Demo-Receiver"

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *args):
            pass

        def reply(self, status, obj):
            data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def authorized(self):
            return hmac.compare_digest(self.headers.get("X-SADD-Receiver-Key", "").encode(), token.encode())

        def do_GET(self):
            if not self.authorized():
                return self.reply(403, {"error": "Receiver authorization required"})
            if urlparse(self.path).path != "/receipt":
                return self.reply(404, {"error": "Unknown receiver route"})
            query = parse_qs(urlparse(self.path).query)
            receipt = store.receipt(query.get("subject_id", [""])[0], query.get("request_id", [""])[0])
            return self.reply(200 if receipt else 404, receipt or {"error": "No receipt"})

        def do_POST(self):
            # Drain a bounded body before early errors. Closing with unread bytes
            # can reset the TCP stream on Windows and hide the intended 403/404.
            try:
                length = int(self.headers.get('Content-Length','0'))
            except ValueError:
                return self.reply(413, {'error':'Invalid payload length'})
            if not 0 < length <= 100000:
                return self.reply(413, {'error':'Payload too large or missing'})
            raw_body = self.rfile.read(length)
            if not self.authorized():
                return self.reply(403, {"error": "Receiver authorization required"})
            if urlparse(self.path).path != "/receive":
                return self.reply(404, {"error": "Unknown receiver route"})
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                return self.reply(415, {"error": "Use application/json"})
            try:
                body = json.loads(raw_body)
                if not isinstance(body, dict) or not all(isinstance(body.get(k), str) for k in ("subject_id", "request_id", "text")):
                    raise ValueError("Invalid receiver schema")
                return self.reply(200, store.receive(body["subject_id"], body["request_id"], body["text"]))
            except (ValueError, TypeError, KeyError) as exc:
                return self.reply(409, {"error": str(exc)})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, store
