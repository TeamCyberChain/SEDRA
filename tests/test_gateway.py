"""Behavioral contracts for the real admission ledger and bounded matcher."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from hashlib import sha256
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from sedra.gateway import Gateway, WINDOW_SECONDS
from sedra.mosaic import (
    DEFAULT_IGNORABLE_RANGES, FragmentMatcher, normalize_text, tokenize,
)


def document(text=None, classification="controlled_excerpt", doc_id="plan", language="en"):
    return {"id": doc_id, "title": "Synthetic plan", "version": "1", "language": language,
            "classification": classification,
            "text": text if text is not None else " ".join(f"word{i}" for i in range(80))}


def fragment(start, length):
    return " ".join(f"word{i}" for i in range(start, start + length))


class MatchingContractTests(unittest.TestCase):
    def test_three_tokens_have_separate_anchored_evidence(self):
        matcher = FragmentMatcher([document()])
        short = matcher.inspect(fragment(11, 3))["matched_documents"][0]
        self.assertEqual(short['eligible_match_count'], 0)
        self.assertEqual(short['token_match_count'], 3)
        found = matcher.inspect(fragment(11, 4))["matched_documents"][0]
        self.assertEqual(found["candidate_count"], 1)
        self.assertEqual(found["eligible_match_count"], 1)
        self.assertEqual(found["candidate_source_positions"], [11])

    def test_registered_public_phrase_is_candidate_not_protected_evidence(self):
        phrase = "general public welcome message"
        matcher = FragmentMatcher([
            document(phrase + " confidential shipment arrives tomorrow", "restricted"),
            document(phrase, "public", "public"),
        ])
        protected = next(d for d in matcher.inspect(phrase)["matched_documents"] if d["id"] == "plan")
        self.assertEqual(protected["candidate_count"], 1)
        self.assertEqual(protected["eligible_match_count"], 0)
        self.assertFalse(protected["confirmed"])

    def test_repeated_phrase_in_source_does_not_double_matched_coverage(self):
        matcher = FragmentMatcher([document("alpha beta gamma delta alpha beta gamma delta")])
        found = matcher.inspect("alpha beta gamma delta")["matched_documents"][0]
        self.assertEqual(found["candidate_source_positions"], [0, 4])
        self.assertEqual(found["candidate_count"], 1)
        self.assertEqual(found["eligible_match_count"], 1)
        self.assertEqual(found["denominator"], 4)

    def test_nfkc_and_default_ignorable_insertion_preserve_match(self):
        matcher = FragmentMatcher([document("alpha beta gamma delta")])
        inspected = matcher.inspect("ＡＬＰＨＡ be\u200bta gamma de\u034flta")
        self.assertEqual(inspected["matched_documents"][0]["eligible_match_count"], 1)
        self.assertEqual(inspected["removed_default_ignorables"], 2)

    def test_pinned_ignorables_are_not_the_cf_category(self):
        self.assertEqual(sum(end - start + 1 for start, end in DEFAULT_IGNORABLE_RANGES), 4174)
        self.assertEqual(normalize_text("a\u034fb"), "ab")  # Mn, but default-ignorable.
        self.assertIn("\U00013430", normalize_text("a\U00013430b"))  # Cf, but explicitly excluded.

    def test_az_dotted_and_dotless_i_and_canonical_form(self):
        self.assertEqual(normalize_text("IŞIQ İŞ", "az"), "ışıq iş")
        self.assertEqual(normalize_text("I\u0307Ş", "az"), "iş")
        self.assertEqual(normalize_text("I\u0323\u0307", "az"), normalize_text("i\u0323", "az"))
        self.assertNotEqual(normalize_text("I", "az"), normalize_text("i", "az"))
        self.assertEqual(normalize_text("INVITATION", "en"), "invitation")
        matcher = FragmentMatcher([document("IŞIQ İŞ BAKI ŞƏHƏRİ", language="az")])
        self.assertEqual(matcher.inspect("ışıq iş bakı şəhəri")["matched_documents"][0]["candidate_count"], 1)

    def test_tr39_confusable_resolves_to_same_source_evidence(self):
        matcher = FragmentMatcher([document("alpha beta gamma delta")])
        self.assertEqual(matcher.inspect("alphа beta gamma delta")["matched_documents"][0]['eligible_match_count'], 1)

    def test_invalid_scalar_and_size_are_rejected(self):
        matcher = FragmentMatcher([document()])
        with self.assertRaises(ValueError):
            matcher.inspect("\ud800")
        with self.assertRaises(ValueError):
            matcher.inspect("a" * 65_537)


class GatewayLedgerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "gateway.sqlite3"
        self.docs = [document()]
        self.gateway = Gateway(self.path, self.docs)
        self.now = 1_000_000.0

    def tearDown(self):
        self.directory.cleanup()

    def evaluate(self, key, text, score=0, **kwargs):
        return self.gateway.evaluate("alice", key, text, score, now=kwargs.pop("now", self.now), **kwargs)

    def deliver(self, key, now=None):
        now = self.now if now is None else now
        self.gateway.claim_send(subject_id="alice", request_id=key, now=now + 1)
        return self.gateway.confirm_forwarded(subject_id="alice", request_id=key, now=now + 2)

    def current_doc(self, now=None):
        return next(d for d in self.gateway.summary("alice", now=self.now if now is None else now)["documents"]
                    if d["id"] == "plan" and d["destination_trust_class"] == "unapproved_ai")

    def test_idempotency_freezes_behavior_and_never_adds_a_second_send_claim(self):
        first = self.evaluate("r1", fragment(0, 8), 5)
        replay = self.evaluate("r1", fragment(0, 8), 99)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(replay["behavior_score"], 5)
        self.assertEqual(replay["threshold"], first["threshold"])
        self.assertEqual(len(self.gateway.requests("alice", now=self.now)), 1)
        self.gateway.claim_send(request_id="r1", subject_id="alice", now=self.now + 1)
        with self.assertRaises(ValueError):
            self.gateway.claim_send(request_id="r1", subject_id="alice", now=self.now + 2)

    def test_idempotency_rejects_changed_body_or_destination(self):
        self.evaluate("r1", fragment(0, 8))
        with self.assertRaises(ValueError):
            self.evaluate("r1", fragment(1, 8))
        with self.assertRaises(ValueError):
            self.evaluate("r1", fragment(0, 8), destination="approved_ai")

    def test_duplicate_fragment_does_not_increase_unique_forwarded_coverage(self):
        self.evaluate("r1", fragment(0, 12))
        self.deliver("r1")
        repeated = self.evaluate("r2", fragment(0, 12), now=self.now + 3)
        self.assertEqual(repeated["decision"], "ALLOW")
        self.deliver("r2", now=self.now + 3)
        result = self.current_doc(now=self.now + 6)
        self.assertEqual(result["forwarded_count"], 9)
        self.assertEqual(result["attempted_count"], 9)

    def test_cumulative_attempted_forwarded_and_blocked_are_distinct(self):
        self.assertEqual(self.evaluate("r1", fragment(0, 12))["decision"], "ALLOW")
        self.deliver("r1")
        blocked = self.evaluate("r2", fragment(30, 12), now=self.now + 3)
        self.assertEqual(blocked["decision"], "BLOCK")
        self.assertIn("CUMULATIVE_DISCLOSURE_LIMIT", blocked["reason_codes"])
        doc = blocked["matched_documents"][0]
        self.assertEqual(doc["attempted_count"], 18)
        self.assertEqual(doc["forwarded_count"], 9)
        self.assertEqual(doc["blocked_count"], 9)
        self.assertEqual(doc["reserved_count"], 0)
        with self.assertRaises(ValueError):
            self.gateway.claim_send(request_id="r2", subject_id="alice", now=self.now + 4)

    def test_high_behavior_tightens_threshold_but_does_not_change_matching(self):
        low = self.evaluate("r1", fragment(0, 15), 69)
        high = self.gateway.evaluate("bob", "r1", fragment(0, 15), 70, now=self.now)
        self.assertEqual((low["threshold"], high["threshold"]), (0.2, 0.1))
        self.assertEqual((low["decision"], high["decision"]), ("ALLOW", "BLOCK"))
        self.assertEqual(low["matched_documents"][0]["eligible_match_count"],
                         high["matched_documents"][0]["eligible_match_count"])

    def test_restricted_and_demo_secret_cannot_be_bypassed_by_low_score_or_approved_route(self):
        restricted = document("confidential alpha beta gamma delta", "restricted", "restricted")
        g = Gateway(Path(self.directory.name) / "restricted.sqlite3", [restricted])
        blocked = g.evaluate("alice", "r", "alpha beta gamma delta", 0, destination="approved_ai", now=self.now)
        self.assertEqual(blocked["decision"], "BLOCK")
        self.assertIn("RESTRICTED_DOCUMENT_MATCH", blocked["reason_codes"])
        for i, score in enumerate((0, 100)):
            result = self.evaluate(str(i), "SEDRA_SECRET_ABCDEFGHIJKLMNOP", score, destination="approved_ai")
            self.assertEqual(result["decision"], "BLOCK")
            self.assertIn("KNOWN_DEMO_SECRET", result["reason_codes"])

    def test_concurrent_admission_reserves_before_another_request_is_evaluated(self):
        barrier = threading.Barrier(2)
        def submit(i):
            barrier.wait()
            return self.evaluate(f"concurrent-{i}", fragment(i * 30, 12))
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, (0, 1)))
        self.assertCountEqual([r["decision"] for r in results], ["ALLOW", "BLOCK"])
        self.assertEqual(self.current_doc()["reserved_count"], 9)

    def test_unused_expiry_prevents_stale_worker_send_and_frees_only_unused_budget(self):
        self.evaluate("r1", fragment(0, 12))
        expired = self.gateway.expire_unused(now=self.now + 30)
        self.assertEqual(expired["expired_count"], 1)
        with self.assertRaises(ValueError):
            self.gateway.claim_send(subject_id="alice", request_id="r1", now=self.now + 31)
        self.assertEqual(self.gateway.get_request(subject_id="alice", request_id="r1", now=self.now + 31)["state"],
                         "EXPIRED_UNUSED")
        self.assertEqual(self.evaluate("r2", fragment(30, 12), now=self.now + 31)["decision"], "ALLOW")

    def test_stale_sending_recovers_to_unknown_and_survives_lease_and_window_expiry(self):
        self.evaluate("r1", fragment(0, 12))
        self.gateway.claim_send(subject_id="alice", request_id="r1", now=self.now + 1)
        self.assertEqual(self.gateway.expire_unused(now=self.now + 31)["unknown_count"], 1)
        later = self.now + WINDOW_SECONDS + 100
        result = self.evaluate("r2", fragment(30, 12), now=later)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertEqual(result["matched_documents"][0]["unknown_count"], 9)
        self.assertEqual(self.gateway.get_request(subject_id="alice", request_id="r1", now=later)["state"],
                         "DELIVERY_UNKNOWN")

    def test_lost_ack_reconciliation_to_forwarded_does_not_double_count(self):
        self.evaluate("r1", fragment(0, 12))
        self.gateway.claim_send(subject_id="alice", request_id="r1", now=self.now + 1)
        unknown = self.gateway.mark_unknown(subject_id="alice", request_id="r1", now=self.now + 2)
        self.assertEqual(unknown["matched_documents"][0]["unknown_count"], 9)
        confirmed = self.gateway.reconcile(subject_id="alice", request_id="r1", delivered=True, now=self.now + 3)
        self.assertEqual(confirmed["state"], "FORWARDED_CONFIRMED")
        self.assertEqual(confirmed["matched_documents"][0]["forwarded_count"], 9)
        self.assertEqual(confirmed["matched_documents"][0]["unknown_count"], 0)
        with self.assertRaises(ValueError):
            self.gateway.reconcile(subject_id="alice", request_id="r1", delivered=False, now=self.now + 4)

    def test_trusted_not_sent_reconciliation_releases_unknown_budget(self):
        self.evaluate("r1", fragment(0, 12))
        self.gateway.claim_send(subject_id="alice", request_id="r1", now=self.now + 1)
        self.gateway.mark_unknown(subject_id="alice", request_id="r1", now=self.now + 2)
        result = self.gateway.reconcile(subject_id="alice", request_id="r1", delivered=False, now=self.now + 3)
        self.assertEqual(result["state"], "NOT_SENT_CONFIRMED")
        self.assertEqual(result["matched_documents"][0]["unknown_count"], 0)
        self.assertEqual(self.evaluate("r2", fragment(30, 12), now=self.now + 4)["decision"], "ALLOW")

    def test_confirmed_delivery_history_survives_window_expiry_and_restart(self):
        original = fragment(0, 12)
        self.evaluate("r1", original)
        self.deliver("r1")
        fresh = Gateway(self.path, self.docs)
        result = fresh.get_request(subject_id="alice", request_id="r1", now=self.now + WINDOW_SECONDS + 100)
        self.assertEqual(result["state"], "FORWARDED_CONFIRMED")
        self.assertEqual(result["body_sha256"], sha256(original.encode()).hexdigest())
        self.assertEqual(result["matched_documents"][0]["forwarded_coverage"], 0)  # active-window metric only.

    def test_three_token_requests_are_not_blindly_concatenated(self):
        a = self.evaluate("r1", fragment(0, 3))
        b = self.evaluate("r2", fragment(3, 3))
        self.assertEqual(a["matched_documents"][0]['eligible_match_count'], 0)
        self.assertEqual(b["matched_documents"][0]['eligible_match_count'], 0)
        self.assertEqual(b["matched_documents"][0]['token_evaluation_coverage']['prospective']['count'], 6)

    def test_collusion_is_not_falsely_aggregated_across_independent_users(self):
        alice = self.evaluate("r1", fragment(0, 12))
        bob = self.gateway.evaluate("bob", "r1", fragment(30, 12), 0, now=self.now)
        self.assertEqual((alice["decision"], bob["decision"]), ("ALLOW", "ALLOW"))

    def test_raw_prompt_not_persisted_and_matching_does_not_change_original_hash(self):
        raw = "Unique private memo ＷＯＲＤ０ word1 word2 word3 arbitrary-7539"
        evaluated = self.evaluate("r1", raw)
        self.assertEqual(evaluated["body_sha256"], sha256(raw.encode("utf-8")).hexdigest())
        with closing(sqlite3.connect(self.path)) as con:
            dump = "\n".join(con.iterdump())
        self.assertNotIn(raw, dump)
        self.assertNotIn("arbitrary-7539", dump)

    def test_document_version_binding_and_explicit_demo_reset(self):
        self.evaluate("r1", fragment(0, 8))
        changed = document()
        changed["text"] += " changed"
        with self.assertRaises(ValueError):
            Gateway(self.path, [changed])
        result = self.gateway.reset_demo()
        self.assertEqual(result["deleted_requests"], 1)
        self.assertEqual(result["documents_preserved"], 1)
        self.assertEqual(self.gateway.requests("alice", now=self.now), [])
        self.assertEqual(len(self.gateway.matcher.documents), 1)


if __name__ == "__main__":
    unittest.main()
