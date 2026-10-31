"""Actual localhost HTTP integration tests; no external service is contacted."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from hashlib import sha256
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from pathlib import Path
import json
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

from sadd.app import AppState, handler_for
from sadd.corpus import catalog


class LocalClient:
    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(CookieJar())
        )
        self.csrf = None

    def request(self, path, body=None, *, token=True):
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
            if token and self.csrf:
                headers["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(self.base + path, data=data, headers=headers)
        try:
            response = self.opener.open(req, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            payload = json.load(response)
            status = response.status
        if status == 200 and "session" in payload:
            self.csrf = payload["session"]["csrf_token"]
        return status, payload

    def login(self, identity):
        status, _ = self.request("/api/state")
        if status != 200:
            raise AssertionError("could not initialize demo session")
        if identity != "analyst":
            status, _ = self.request("/api/session", {"identity": identity})
            if status != 200:
                raise AssertionError("could not choose demo identity")
        return self


class ApplicationIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.app = AppState(Path(cls.directory.name) / "lab")
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(cls.app))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)
        cls.app.close()
        cls.directory.cleanup()

    def setUp(self):
        self.app.reset()
        self.employee = self.app.new_session("lab-001")[1]
        self.high_employee = self.app.new_session("lab-002")[1]
        self.analyst = self.app.new_session("analyst")[1]

    def transfer(self, key, text, *, session=None, **kwargs):
        return self.app.transfer(session or self.employee, {"request_id": key, "text": text, **kwargs})

    def test_real_receiver_observes_original_utf8_payload_and_digest(self):
        original = "Public receipt proof — ＡＲＡＺ; İŞIQ; visible\u200btext."
        result = self.transfer("original-body-001", original)
        receipt = self.app.receiver.receipt("lab-001", "original-body-001")
        self.assertEqual(result["state"], "FORWARDED_CONFIRMED")
        self.assertEqual(receipt["sha256"], sha256(original.encode("utf-8")).hexdigest())
        self.assertEqual(receipt["utf8_bytes"], len(original.encode("utf-8")))
        with closing(sqlite3.connect(self.app.receiver.path)) as db, db:
            payload = db.execute("SELECT payload FROM receipts WHERE subject_id=? AND request_id=?",
                                 ("lab-001", "original-body-001")).fetchone()[0]
        self.assertEqual(payload, original)

    def test_secret_block_never_reaches_receiver(self):
        result = self.transfer("blocked-secret-001", "SADD_SECRET_ABCDEFGHIJKLMNOP")
        self.assertEqual(result["state"], "BLOCKED")
        self.assertIn("KNOWN_DEMO_SECRET", result["reason_codes"])
        self.assertEqual(self.app.receiver.list(), [])
        event = self.app.events("lab-001")[0]
        self.assertFalse(event["detail"]["receiver_contacted"])

    def test_same_quote_passes_normal_context_and_blocks_high_context(self):
        self.assertLess(self.app.subjects["lab-001"]["behavior_score"], 70)
        self.assertGreaterEqual(self.app.subjects["lab-002"]["behavior_score"], 70)
        source = next(d for d in catalog() if d["id"] == "araz-plan")
        quote = next(f["text"] for f in source["fragments"] if f["label"] == "Context comparison excerpt")
        normal = self.transfer("context-normal-001", quote)
        high = self.transfer("context-high-001", quote, session=self.high_employee)
        self.assertEqual((normal["state"], high["state"]), ("FORWARDED_CONFIRMED", "BLOCKED"))
        self.assertEqual(len(self.app.receiver.list()), 1)
        self.assertEqual(normal["body_sha256"], high["body_sha256"])

    def test_real_document_endpoint_changes_live_context_without_client_score(self):
        client = LocalClient(self.base).login('lab-001')
        quote = catalog()[0]['fragments'][-1]['text']
        status, before = client.request('/api/transfer',{'request_id':'http-context-before','text':quote})
        self.assertEqual((status,before['decision']),(200,'ALLOW'))
        for _ in range(6):
            self.assertEqual(client.request('/api/document?id=araz-plan')[0],200)
        status, after = client.request('/api/transfer',{'request_id':'http-context-after','text':quote})
        self.assertEqual((status,after['decision']),(200,'BLOCK'))
        self.assertEqual(after['behavior_context']['live_context']['protected_document_reads'],6)
        self.assertEqual(after['behavior_context']['live_context']['source'],'observed_application_events')

    def test_loopback_rebinding_and_cross_origin_requests_are_denied(self):
        for headers in ({'Host':'unrelated.invalid'}, {'Origin':'https://unrelated.invalid'}):
            request = urllib.request.Request(self.base+'/api/state',headers=headers)
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with self.assertRaises(urllib.error.HTTPError) as caught:
                opener.open(request)
            self.assertEqual(caught.exception.code,403)

    def test_two_local_ports_keep_distinct_sessions_in_shared_browser_cookie_jar(self):
        with tempfile.TemporaryDirectory() as tmp:
            other=AppState(Path(tmp)/'other')
            server=ThreadingHTTPServer(('127.0.0.1',0),handler_for(other))
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                first=LocalClient(self.base).login('lab-001')
                second=LocalClient(f'http://127.0.0.1:{server.server_port}')
                second.opener=first.opener
                second.login('lab-002')
                self.assertEqual(first.request('/api/state')[1]['session']['subject_id'],'lab-001')
                self.assertEqual(second.request('/api/state')[1]['session']['subject_id'],'lab-002')
            finally:
                server.shutdown();server.server_close();thread.join(timeout=3);other.close()

    def test_cumulative_first_two_forward_third_blocks_with_distinct_evidence(self):
        source = next(d for d in catalog() if d["id"] == "araz-plan")
        selected = [item["text"] for item in source["fragments"][:3]]
        results = [self.transfer(f"cumulative-{i:04d}", text) for i, text in enumerate(selected)]
        self.assertEqual([r["state"] for r in results], ["FORWARDED_CONFIRMED", "FORWARDED_CONFIRMED", "BLOCKED"])
        self.assertEqual(len(self.app.receiver.list()), 2)
        evidence = next(d for d in results[-1]["matched_documents"] if d["id"] == source["id"])
        self.assertGreater(evidence["attempted_count"], evidence["forwarded_count"])
        self.assertGreaterEqual(evidence["prospective_coverage"], .20)

    def test_concurrent_same_request_id_is_forwarded_only_once(self):
        barrier = threading.Barrier(2)
        def submit(_):
            barrier.wait()
            return self.transfer("retry-race-0001", "Public retry race proof")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, (0, 1)))
        self.assertEqual(sum(bool(r["idempotent_replay"]) for r in results), 1)
        self.assertEqual(len(self.app.receiver.list()), 1)
        self.assertEqual(len(self.app.gateway.requests("lab-001")), 1)
        self.assertEqual(self.app.gateway.get_request(subject_id="lab-001", request_id="retry-race-0001")["state"],
                         "FORWARDED_CONFIRMED")

    def test_ack_loss_keeps_unknown_until_validated_receipt_reconciliation(self):
        result = self.transfer("lost-ack-0001", "Public lost acknowledgment proof", simulate_ack_loss=True)
        self.assertEqual(result["state"], "DELIVERY_UNKNOWN")
        self.assertEqual(len(self.app.receiver.list()), 1)
        replay = self.transfer("lost-ack-0001", "Public lost acknowledgment proof")
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["state"], "DELIVERY_UNKNOWN")
        self.assertEqual(len(self.app.receiver.list()), 1)
        result = self.app.reconcile(self.employee, {"request_id": "lost-ack-0001"})
        self.assertEqual(result["state"], "FORWARDED_CONFIRMED")

    def test_reconciliation_rejects_corrupt_digest_and_keeps_unknown_exposure(self):
        self.transfer("corrupt-ack-0001", "Public corrupt receipt proof", simulate_ack_loss=True)
        with closing(sqlite3.connect(self.app.receiver.path)) as db, db:
            db.execute("UPDATE receipts SET sha256=? WHERE request_id=?", ("0" * 64, "corrupt-ack-0001"))
        with self.assertRaisesRegex(ValueError, "mismatch"):
            self.app.reconcile(self.employee, {"request_id": "corrupt-ack-0001"})
        self.assertEqual(self.app.gateway.get_request(subject_id="lab-001", request_id="corrupt-ack-0001")["state"],
                         "DELIVERY_UNKNOWN")

    def test_wrong_byte_count_ack_is_unknown_then_real_receipt_reconciles(self):
        original_receive = self.app.receiver.receive
        def bad_ack(*args):
            receipt = original_receive(*args)
            receipt["utf8_bytes"] += 1
            return receipt
        with patch.object(self.app.receiver, "receive", side_effect=bad_ack):
            result = self.transfer("bad-byte-ack-0001", "Public byte count proof")
        self.assertEqual(result["state"], "DELIVERY_UNKNOWN")
        result = self.app.reconcile(self.employee, {"request_id": "bad-byte-ack-0001"})
        self.assertEqual(result["state"], "FORWARDED_CONFIRMED")

    def test_no_receipt_does_not_become_false_not_sent_confirmation(self):
        self.app.gateway.evaluate("lab-001", "no-receipt-0001", "Public absent receipt proof", 0)
        self.app.gateway.claim_send(subject_id="lab-001", request_id="no-receipt-0001")
        self.app.gateway.mark_unknown(subject_id="lab-001", request_id="no-receipt-0001")
        result = self.app.reconcile(self.employee, {"request_id": "no-receipt-0001"})
        self.assertEqual(result["state"], "DELIVERY_UNKNOWN")
        self.assertIn("No receipt yet", result["reconciliation_note"])

    def test_reset_rejects_active_transfer(self):
        entered, release = threading.Event(), threading.Event()
        original_receive = self.app.receiver.receive
        def delayed(*args):
            entered.set()
            if not release.wait(3):
                raise RuntimeError("test did not release receiver")
            return original_receive(*args)
        with patch.object(self.app.receiver, "receive", side_effect=delayed):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.transfer, "reset-race-0001", "Public reset race proof")
                try:
                    self.assertTrue(entered.wait(3))
                    with self.assertRaisesRegex(ValueError, "active transfers"):
                        self.app.reset()
                finally:
                    release.set()
                self.assertEqual(future.result(timeout=4)["state"], "FORWARDED_CONFIRMED")

    def test_reset_also_rejects_active_reconciliation(self):
        self.transfer("reset-reconcile-001", "Public reconciliation reset proof", simulate_ack_loss=True)
        entered, release = threading.Event(), threading.Event()
        original_receipt = self.app.receiver.receipt
        def delayed(*args):
            entered.set()
            if not release.wait(3):
                raise RuntimeError("test did not release receipt query")
            return original_receipt(*args)
        with patch.object(self.app.receiver, "receipt", side_effect=delayed):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.app.reconcile, self.employee, {"request_id": "reset-reconcile-001"})
                try:
                    self.assertTrue(entered.wait(3))
                    with self.assertRaisesRegex(ValueError, "active transfers"):
                        self.app.reset()
                finally:
                    release.set()
                self.assertEqual(future.result(timeout=4)["state"], "FORWARDED_CONFIRMED")

    def test_employee_view_contains_only_own_requests_receipts_events_and_subject(self):
        self.transfer("visibility-alice-001", "Public unique-alice-content-7539")
        self.transfer("visibility-bob-001", "Public unique-bob-content-2586", session=self.high_employee)
        employee = self.app.view(self.employee)
        for name in ("requests", "receiver", "events", "subjects"):
            self.assertTrue(employee[name])
            self.assertTrue(all(item["subject_id"] == "lab-001" for item in employee[name]), name)
        self.assertNotIn("unique-bob-content-2586", json.dumps(employee))
        analyst = self.app.view(self.analyst)
        self.assertEqual(len(analyst["receiver"]), 2)
        self.assertTrue(all("Content masked" in row["preview"] for row in analyst["receiver"]))
        self.assertNotIn("unique-alice-content-7539", json.dumps(analyst))

    def test_http_csrf_role_filter_and_client_context_override(self):
        employee = LocalClient(self.base).login("lab-001")
        body = {"request_id": "http-submit-0001", "text": "Public HTTP proof"}
        status, _ = employee.request("/api/transfer", body, token=False)
        self.assertEqual(status, 403)
        status, _ = employee.request("/api/transfer", body | {"subject_id": "lab-002"})
        self.assertEqual(status, 400)
        status, _ = employee.request("/api/transfer", body | {"behavior_score": 0})
        self.assertEqual(status, 400)
        status, _ = employee.request("/api/reset", {})
        self.assertEqual(status, 403)
        self.assertEqual(self.app.receiver.list(), [])
        analyst = LocalClient(self.base).login("analyst")
        status, _ = analyst.request("/api/transfer", body)
        self.assertEqual(status, 403)
        status, result = employee.request("/api/transfer", body)
        self.assertEqual(status, 200)
        self.assertEqual(result["state"], "FORWARDED_CONFIRMED")
        status, state = employee.request("/api/state")
        self.assertEqual(status, 200)
        self.assertEqual({r["subject_id"] for r in state["requests"]}, {"lab-001"})
        status, _ = analyst.request("/api/reset", {})
        self.assertEqual(status, 200)
        self.assertEqual(self.app.receiver.list(), [])

    def test_employee_cannot_reconcile_other_subject_request(self):
        self.transfer("other-reconcile-001", "Public other user reconciliation", session=self.high_employee,
                      simulate_ack_loss=True)
        with self.assertRaisesRegex(ValueError, "visible request"):
            self.app.reconcile(self.employee, {"request_id": "other-reconcile-001"})
        self.assertEqual(self.app.gateway.get_request(subject_id="lab-002", request_id="other-reconcile-001")["state"],
                         "DELIVERY_UNKNOWN")

    def test_receiver_http_requires_key_exact_route_and_object_body(self):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def send(path, body, key=None):
            headers = {"Content-Type": "application/json"}
            if key:
                headers["X-SADD-Receiver-Key"] = key
            req = urllib.request.Request(self.app.receiver_url + path,
                                         data=json.dumps(body).encode("utf-8"), headers=headers)
            try:
                response = opener.open(req, timeout=3)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                response.read()
                return response.status
        body = {"subject_id": "lab-001", "request_id": "receiver-direct-001", "text": "Public direct proof"}
        self.assertEqual(send("/receive", body), 403)
        self.assertEqual(send("/not-a-receiver-route", body, self.app.receiver_key), 404)
        self.assertEqual(send("/receive", [], self.app.receiver_key), 409)
        self.assertEqual(self.app.receiver.list(), [])


if __name__ == "__main__":
    unittest.main()
