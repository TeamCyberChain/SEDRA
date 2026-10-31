import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import tarfile
import unittest

from sadd.behavior import (
    FEATURE_NAMES, budget_threshold, build_demo_snapshot, calibrate_ml_scores,
    evaluate_detector, extract_past_only_features, generate_demo_daily_records,
    score_daily_records,
)


class BehaviorContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = build_demo_snapshot(42)

    def test_explicit_synthetic_provenance_and_completed_time(self):
        s = self.snapshot
        self.assertEqual(s["provenance"], "synthetic_lab")
        self.assertTrue(s["dataset_generated"])
        self.assertEqual(s["profile"], "lab_daily_v1")
        self.assertEqual(s["as_of"], "2026-10-30T23:59:59+04:00")
        self.assertEqual(len(s["subjects"]), 40)
        json.dumps(s, allow_nan=False)

    def test_demo_contrast_comes_from_features(self):
        subjects = {r["subject_id"]: r for r in self.snapshot["subjects"]}
        normal, high = subjects["lab-001"], subjects["lab-002"]
        self.assertLess(normal["behavior_score"], 30)
        self.assertGreaterEqual(high["behavior_score"], 70)
        self.assertGreater(high["copy_count"], 4 * high["baseline"]["personal_copy_median"])
        self.assertGreater(high["features"]["after_hours_fraction"], .8)
        for row in (normal, high):
            expected = round(100 * (.6 * row["rule_score"] + .4 * row["ml_score"]))
            self.assertEqual(row["behavior_score"], expected)

    def test_busy_finance_and_night_shift_are_normal_context(self):
        subjects = {r["subject_id"]: r for r in self.snapshot["subjects"]}
        busy, night = subjects["lab-006"], subjects["lab-004"]
        self.assertGreater(busy["copy_count"], 2 * subjects["lab-001"]["copy_count"])
        self.assertEqual(busy["rule_details"][0]["severity"], 0)
        self.assertGreater(night["features"]["after_hours_fraction"], .5)
        self.assertEqual(night["rule_details"][1]["severity"], 0)

    def test_splits_calibration_and_budget(self):
        e = self.snapshot["evaluation"]
        self.assertEqual(e["split"]["train_user_days"], 1120)
        self.assertEqual(e["split"]["validation_user_days"], 840)
        self.assertEqual(e["split"]["test_user_days"], 840)
        self.assertLess(e["split"]["train_end"], e["split"]["validation_end"])
        self.assertLess(e["split"]["validation_end"], e["split"]["test_start"])
        self.assertFalse(e["model"]["labels_used_in_fit"])
        self.assertTrue(e["ml_calibration"]["valid"])
        for operating_point in e["operating_points"].values():
            self.assertLessEqual(operating_point["observed_validation_alerts"], operating_point["allowed_alerts"])
            self.assertFalse(operating_point["selection_uses_labels"])

    def test_seed_reproducible(self):
        other = build_demo_snapshot(42)
        self.assertEqual(self.snapshot, other)

    def test_labels_do_not_change_model_or_threshold(self):
        raw = generate_demo_daily_records(42)
        for row in raw:
            row["label"] = 1 - row["label"]
        altered = score_daily_records(raw, train_end="2026-09-18", validation_end="2026-10-09", seed=42)
        self.assertEqual(self.snapshot["evaluation"]["operating_points"], altered["evaluation"]["operating_points"])
        self.assertEqual(self.snapshot["evaluation"]["ml_calibration"], altered["evaluation"]["ml_calibration"])
        for a, b in zip(self.snapshot["subjects"], altered["subjects"]):
            for field in ("features", "raw_anomaly", "rule_score", "ml_score", "behavior_score"):
                self.assertEqual(a[field], b[field])


class LeakageAndMetricTests(unittest.TestCase):
    def test_future_and_same_day_peer_changes_do_not_affect_earlier_features(self):
        raw = generate_demo_daily_records(5)
        initial = extract_past_only_features(raw)
        altered = copy.deepcopy(raw)
        for row in altered:
            if row["date"] >= "2026-10-30" and row["subject_id"] != "lab-001":
                row["copy_count"] = 999999
                row["after_hours_copies"] = 999999
                row["workstations"] = ["future-host"]
        changed = extract_past_only_features(altered)
        for before, after in zip(initial, changed):
            if before["date"] < "2026-10-30" or before["subject_id"] == "lab-001":
                self.assertEqual(before["features"], after["features"])
                self.assertEqual(before["baseline"], after["baseline"])

    def test_thin_peer_group_falls_back_explicitly(self):
        raw = [r for r in generate_demo_daily_records(2) if r["subject_id"] in ("lab-001", "lab-002")]
        scored = extract_past_only_features(raw)
        self.assertTrue(scored)
        for row in scored:
            self.assertFalse(row["baseline"]["peer_adjustment_used"])
            self.assertIsNone(row["baseline"]["peer_copy_median"])
            self.assertLess(row["baseline"]["last_observation_date"], row["date"])

    def test_quantile_and_budget_ties_are_guarded(self):
        self.assertFalse(calibrate_ml_scores([.4] * 250)["valid"])
        self.assertFalse(calibrate_ml_scores([.1, .2])["valid"])
        selected = budget_threshold([1.] * 1000)
        self.assertEqual(selected["observed_validation_alerts"], 0)
        self.assertEqual(selected["allowed_alerts"], 10)

    def test_actor_only_flagged_on_benign_day_is_not_detected(self):
        rows = [
            {"subject_id": "a", "date": "2026-10-01", "label": 0},
            {"subject_id": "a", "date": "2026-10-02", "label": 1, "episode_id": "incident"},
            {"subject_id": "b", "date": "2026-10-02", "label": 0},
        ]
        result = evaluate_detector(rows, [1., 0., 0.], .5)
        self.assertEqual(result["actors_detected_in_malicious_windows"], 0)
        self.assertEqual(result["episodes_detected_in_labeled_windows"], 0)
        self.assertEqual(result["confusion_matrix"], {"tp": 0, "fp": 1, "fn": 1, "tn": 1})

    def test_unlabeled_source_is_not_assumed_benign(self):
        with self.assertRaisesRegex(ValueError, "explicit binary labels"):
            score_daily_records([{"label": None}], train_end="2010-06-30", validation_end="2010-09-30")


class CertImporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1] / "scripts" / "cert_ingest.py"
        spec = importlib.util.spec_from_file_location("cert_ingest", path)
        cls.importer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.importer)

    def test_streaming_import_preserves_semantics_and_missing_labels(self):
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / "file.csv", Path(folder) / "days.jsonl"
            source.write_text('id,date,user,pc,filename,content\n'
                              'e1,01/04/2010 10:00:00,U1,PC1,c:\\a.txt,not persisted\n'
                              'e2,01/04/2010 20:00:00,U1,PC2,c:\\b.txt,not persisted\n'
                              'e3,01/05/2010 11:00:00,U2,PC3,c:\\c.txt,not persisted\n')
            meta = self.importer.ingest(source, target)
            rows = [json.loads(x) for x in target.read_text().splitlines()]
            self.assertEqual(meta["source_event_rows"], 3)
            self.assertEqual(meta["output_user_days"], 2)
            self.assertEqual(rows[0]["copy_count"], 2)
            self.assertEqual(rows[0]["after_hours_copies"], 1)
            self.assertEqual(rows[0]["operation"], "removable_media_copy")
            self.assertEqual(rows[0]["role"], "Unknown")
            self.assertIsNone(rows[0]["label"])
            self.assertEqual(len(meta["source_sha256"]), 64)
            self.assertNotIn("not persisted", target.read_text())

    def test_missing_schema_fails_without_output(self):
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / "file.csv", Path(folder) / "days.jsonl"
            source.write_text("date,user\n01/01/2010,U1\n")
            with self.assertRaisesRegex(ValueError, "Missing required"):
                self.importer.ingest(source, target)
            self.assertFalse(target.exists())

    def test_truncated_source_and_wrong_member_length_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / "file.csv", Path(folder) / "days.jsonl"
            source.write_text('id,date,user,pc,filename,content\ne1,01/04/2010 10:00:00,U1,PC1,a.txt,partial')
            with self.assertRaisesRegex(ValueError, "line terminator"):
                self.importer.ingest(source, target)
            source.write_text(source.read_text() + "\n")
            with self.assertRaisesRegex(ValueError, "length mismatch"):
                self.importer.ingest(source, target, expected_size=999999)
            self.assertFalse(target.exists())

    def test_answer_join_excludes_other_actor_context_and_future_roles(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, target = root / "file.csv", root / "days.jsonl"
            source.write_text('id,date,user,pc,filename,content\n'
                              'e1,01/04/2010 10:00:00,U1,PC1,a.txt,x\n'
                              'e2,01/04/2010 11:00:00,U2,PC2,b.txt,x\n'
                              'e3,01/05/2010 10:00:00,U1,PC1,c.txt,x\n'
                              'e4,01/04/2010 15:00:00,U1,PC1,d.txt,x\n')
            archive = root / "answers.tar.bz2"
            members = {
                "answers/insiders.csv": "dataset,scenario,details,user,start,end\n4.2,1,r4.2-1-U1.csv,U1,01/04/2010 09:00:00,01/04/2010 20:00:00\n",
                "answers/r4.2-1/r4.2-1-U1.csv": "file,e1,01/04/2010 10:00:00,U1,PC1,a.txt,x\nfile,e2,01/04/2010 11:00:00,U2,PC2,b.txt,x\n",
            }
            with tarfile.open(archive, "w:bz2") as out:
                for name, text in members.items():
                    blob = text.encode()
                    info = tarfile.TarInfo(name)
                    info.size = len(blob)
                    out.addfile(info, io.BytesIO(blob))
            ldap = root / "LDAP"
            ldap.mkdir()
            (ldap / "2010-01.csv").write_text("user_id,role\nU1,Finance\nU2,Security\n")
            (ldap / "2010-02.csv").write_text("user_id,role\nU1,Engineering\nU2,Security\n")
            meta = self.importer.ingest(source, target, answers_archive=archive, ldap_dir=ldap)
            rows = [json.loads(x) for x in target.read_text().splitlines()]
            self.assertEqual([r["label"] for r in rows], [1, 0, 0])
            self.assertEqual(rows[0]["role"], "Finance")
            self.assertEqual(rows[0]["episode_id"], "r4.2-1-U1")
            self.assertEqual(rows[0]["incident_associated_copy_events"], 2)
            self.assertEqual(rows[0]["exact_observable_copy_events"], 1)
            self.assertEqual(meta["matched_answer_file_event_ids"], 1)
            self.assertEqual(meta["labels"]["other_actor_file_observables_excluded"], 1)
            previous_output = target.read_text()
            source.write_text('id,date,user,pc,filename,content\n'
                              'e1,01/04/2010 10:00:00,U1,PC1,a.txt,x\n'
                              'e1,01/04/2010 11:00:00,U1,PC1,b.txt,x\n')
            with self.assertRaisesRegex(ValueError, "Duplicate source event"):
                self.importer.ingest(source, target)
            self.assertEqual(target.read_text(), previous_output)

    def test_no_signal_incident_remains_in_recall_denominator(self):
        meta = {"labels": {"incident_intervals": [
            {"actor": "U1", "episode_id": "E1", "start": "2010-10-01T00:00:00", "end": "2010-10-03T23:59:59"},
            {"actor": "U2", "episode_id": "E2", "start": "2010-10-02T00:00:00", "end": "2010-10-04T23:59:59"},
        ]}}
        positive = {"subject_id": "cert-r4.2:U1", "date": "2010-10-02", "label": 1,
                    "episode_id": "E1", "combined_priority": 1.}
        s = {"history": [positive], "evaluation": {
            "split": {"test_start": "2010-10-01", "test_end": "2010-10-31"},
            "operating_points": {"combined": {"threshold": .5}},
            "comparisons": {"combined": {"episode_recall": 1., "actor_recall_in_labeled_malicious_windows": 1.}},
        }}
        self.importer.attach_incident_coverage(s, [positive], meta, {"cert-r4.2:U1", "cert-r4.2:U2"})
        c = s["evaluation"]["comparisons"]["combined"]
        self.assertEqual(c["episode_recall"], .5)
        self.assertEqual(c["actor_recall_in_labeled_malicious_windows"], .5)
        self.assertEqual(c["source_conditional_episode_recall"], 1.)
        self.assertEqual(s["evaluation"]["incident_coverage"]["incidents_without_observable_copy_events_in_test_interval"], 1)


if __name__ == "__main__":
    unittest.main()
