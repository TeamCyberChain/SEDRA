"""Reproducible, explicitly synthetic SEDRA behavior demonstration.

The classifier never consumes labels.  A completed user-day is the scoring
unit; this module must not be used to score a partially completed live day.
"""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import date, timedelta
import math
from typing import Any, Iterable

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score


PROFILE = "lab_daily_v1"
FEATURE_VERSION = "daily-copy-v1"
MODEL_VERSION = "iforest-lab-daily-v1"
PROVENANCE = "synthetic_lab"
LABEL_PROVENANCE = "explicit_synthetic_scenario_schedule_v1"
FEATURE_NAMES = (
    "log_copy_count", "personal_volume_deviation", "peer_volume_deviation",
    "after_hours_fraction", "after_hours_deviation",
    "novel_workstation_fraction", "workstation_count",
)
ROLES = ("Finance", "Engineering", "Operations", "Security", "Human Resources")


def _clip(value: float) -> float:
    return float(min(1.0, max(0.0, value)))


def _robust(values: Iterable[float], floor: float = 1.0) -> tuple[float, float]:
    a = np.asarray(list(values), dtype=float)
    med = float(np.median(a))
    scale = max(floor, 1.4826 * float(np.median(np.abs(a - med))))
    return med, scale


def generate_demo_daily_records(seed: int = 42) -> list[dict[str, Any]]:
    """Generate one coherent lab, with an explicit attack schedule, not CERT.

    84 completed days end on 2026-10-30. Normal activity, benign changes and
    attack interventions are generated before any scoring or evaluation.
    """
    rng = np.random.default_rng(seed)
    start = date(2026, 8, 8)
    subject_count = 40
    multipliers = rng.uniform(0.75, 1.25, subject_count)
    base_by_role = dict(zip(ROLES, (28, 36, 22, 26, 18)))
    attacks: dict[tuple[int, int], tuple[str, str]] = {}
    for begin, subject, kind, episode in (
        (45, 12, "burst", "validation-01"),
        (51, 17, "burst", "validation-02"),
        (58, 22, "burst", "validation-03"),
        (61, 27, "burst", "validation-04"),
        (66, 32, "burst", "test-01"),
        (70, 37, "slow", "test-02"),
        (77, 9, "burst", "test-03"),
        (82, 1, "burst", "test-04"),
    ):
        for day_index in (begin, begin + 1):
            attacks[(day_index, subject)] = (kind, episode)
    output = []
    for day_index in range(84):
        current_day = start + timedelta(days=day_index)
        for subject in range(subject_count):
            subject_id = f"lab-{subject + 1:03d}"
            role = ROLES[subject % len(ROLES)]
            # A permanently busy Finance user is a benign peer-control case.
            permanent_load = 3.0 if subject == 5 else 1.0
            weekend = .65 if current_day.weekday() >= 5 and role != "Security" else 1.0
            typical = base_by_role[role] * multipliers[subject] * permanent_load
            count = int(rng.poisson(typical * weekend))
            night_rate = .72 if role == "Security" else .035
            after_hours = int(rng.binomial(count, night_rate))
            workstations = [f"workstation-{subject_id}"]
            if rng.random() < .08:
                workstations.append(f"shared-{role.lower().replace(' ', '-')}")
            label, scenario, episode_id = 0, "normal", None
            if subject == 6 and day_index == 74:
                # New equipment is a benign change, not silently excluded.
                workstations = [f"replacement-{subject_id}"]
                scenario = "benign_workstation_replacement"
            if subject == 10 and day_index in (35, 56, 77):
                count *= 4
                scenario = "benign_periodic_bulk_copy"
            if (day_index, subject) in attacks:
                kind, episode_id = attacks[(day_index, subject)]
                label = 1
                scenario = "synthetic_slow_copy" if kind == "slow" else "synthetic_copy_burst"
                count = int(round(typical * (2.2 if kind == "slow" else 10.0)))
                after_hours = int(round(count * (.24 if kind == "slow" else .90)))
                workstations = [f"unfamiliar-{subject_id}-{episode_id}"]
            output.append({
                "subject_id": subject_id, "role": role, "date": current_day.isoformat(),
                "copy_count": count, "after_hours_copies": after_hours,
                "workstations": workstations, "label": label,
                "scenario": scenario, "episode_id": episode_id,
                "provenance": PROVENANCE, "label_provenance": LABEL_PROVENANCE,
                "operation": "removable_media_copy", "dataset_generated": True,
            })
    return output


def extract_past_only_features(
    records: list[dict[str, Any]], *, min_history_days: int = 14,
    baseline_days: int = 28, peer_min_users: int = 5,
) -> list[dict[str, Any]]:
    """Use only earlier days, including for peer statistics and seen hosts.

    Labels and scenario fields are carried only as evaluation metadata. Same-day
    rows are processed as a batch before any history is updated.
    """
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_keys = set()
    for row in records:
        key = (row["subject_id"], row["date"])
        if key in seen_keys:
            raise ValueError(f"Duplicate user-day: {key}")
        seen_keys.add(key)
        date.fromisoformat(row["date"])
        count, after = int(row["copy_count"]), int(row["after_hours_copies"])
        if count < 0 or not 0 <= after <= count:
            raise ValueError(f"Invalid copy counts: {key}")
        grouped[row["date"]].append(row)
    histories: dict[str, deque] = defaultdict(lambda: deque(maxlen=baseline_days))
    observed_hosts: dict[str, set[str]] = defaultdict(set)
    known_roles: dict[str, str] = {}
    output = []
    for day in sorted(grouped):
        todays = sorted(grouped[day], key=lambda r: r["subject_id"])
        role_users: dict[str, list[str]] = defaultdict(list)
        for user, history in histories.items():
            if len(history) >= min_history_days and known_roles.get(user):
                role_users[known_roles[user]].append(user)
        for row in todays:
            user, role = row["subject_id"], row.get("role", "Unknown")
            history = histories[user]
            if len(history) < min_history_days:
                continue
            count = int(row["copy_count"])
            fraction = float(row["after_hours_copies"] / max(1, count))
            counts = [x["copy_count"] for x in history]
            personal_median, personal_scale = _robust(counts)
            personal_scale = max(personal_scale, math.sqrt(max(1., personal_median)))
            peers = [x for x in role_users.get(role, []) if x != user]
            peer_valid = role != "Unknown" and len(peers) >= peer_min_users
            if peer_valid:
                peer_values = [r["copy_count"] for p in peers for r in histories[p]]
                peer_median, peer_scale = _robust(peer_values)
                peer_scale = max(peer_scale, math.sqrt(max(1., peer_median)))
            else:
                peer_median, peer_scale = personal_median, personal_scale
            personal_z = (count - personal_median) / personal_scale
            peer_z = (count - peer_median) / peer_scale
            # A personal OR well-established peer norm can explain busy work.
            volume_start = max(personal_median + 3 * personal_scale,
                               peer_median + 3 * peer_scale)
            volume_full = max(personal_median + 9 * personal_scale,
                              peer_median + 9 * peer_scale)
            volume_rule = _clip((count - volume_start) / max(1., volume_full - volume_start))
            past_fractions = [r["after_hours_copies"] / max(1, r["copy_count"]) for r in history]
            hours_median, hours_scale = _robust(past_fractions, floor=.05)
            hours_z = (fraction - hours_median) / hours_scale
            hours_rule = _clip((hours_z - 3) / 6) if row["after_hours_copies"] >= 3 else 0.
            current_hosts = set(row["workstations"])
            new_hosts = current_hosts - observed_hosts[user]
            novel_fraction = len(new_hosts) / max(1, len(current_hosts))
            peer_hosts = set().union(*(observed_hosts[p] for p in peers)) if peers else set()
            unfamiliar_to_peers = len(new_hosts - peer_hosts) / max(1, len(new_hosts))
            workstation_rule = (novel_fraction * (.45 + .35 * unfamiliar_to_peers +
                                  .20 * min(1., count / max(1., 2 * personal_median)))) if count >= 5 else 0.
            features = {
                "log_copy_count": math.log1p(count),
                "personal_volume_deviation": float(np.clip(personal_z, -20, 50)),
                "peer_volume_deviation": float(np.clip(peer_z, -20, 50)),
                "after_hours_fraction": fraction,
                "after_hours_deviation": float(np.clip(hours_z, -20, 50)),
                "novel_workstation_fraction": novel_fraction,
                "workstation_count": len(current_hosts),
            }
            details = [
                {"rule_id": "copy_volume", "name": "Unusual removable-media copy volume",
                 "severity": volume_rule, "observed": count,
                 "personal_median": personal_median, "peer_median": peer_median if peer_valid else None,
                 "activation_floor": volume_start},
                {"rule_id": "unusual_hour_copy", "name": "Copying at unusual hours",
                 "severity": hours_rule, "observed_fraction": fraction,
                 "personal_median_fraction": hours_median, "robust_deviation": hours_z},
                {"rule_id": "novel_workstation", "name": "Copying from an unfamiliar workstation",
                 "severity": workstation_rule, "unfamiliar_workstations": sorted(new_hosts),
                 "personal_history_days": len(history)},
            ]
            reasons = []
            if volume_rule > 0:
                reasons.append(f"{count} removable-media copies; personal daily median {personal_median:.0f}; context threshold {volume_start:.0f}.")
            if hours_rule > 0:
                reasons.append(f"{fraction:.0%} of copies occurred outside expected hours; personal median {hours_median:.0%}.")
            if workstation_rule > 0:
                reasons.append(f"Copying used {len(new_hosts)} workstation(s) not seen in this user's earlier history.")
            if not reasons:
                reasons.append("Recorded copying is within the established personal and available peer context.")
            output.append({
                **row, "features": features, "rule_score": max(volume_rule, hours_rule, workstation_rule),
                "rule_details": details, "reasons": reasons,
                "baseline": {"history_days": len(history), "last_observation_date": history[-1]["date"],
                    "personal_copy_median": personal_median, "peer_copy_median": peer_median if peer_valid else None,
                    "peer_users": len(peers), "peer_adjustment_used": peer_valid,
                    "peer_role": role if peer_valid else None, "sufficiency": "minimum_history_met"},
            })
        # Update after every subject was scored, so same-day peer leakage is impossible.
        for row in todays:
            user = row["subject_id"]
            histories[user].append(row)
            observed_hosts[user].update(row["workstations"])
            known_roles[user] = row.get("role", "Unknown")
    return output


def calibrate_ml_scores(validation_scores: Iterable[float]) -> dict[str, Any]:
    scores = np.asarray(list(validation_scores), dtype=float)
    if len(scores) < 200 or not np.isfinite(scores).all():
        return {"valid": False, "reason": "insufficient_finite_validation_samples",
                "sample_count": int(len(scores)), "q95": None, "q99": None}
    q95, q99 = [float(x) for x in np.quantile(scores, [.95, .99])]
    if q99 - q95 <= 1e-10:
        return {"valid": False, "reason": "tied_validation_quantiles", "sample_count": int(len(scores)),
                "q95": q95, "q99": q99}
    return {"valid": True, "reason": None, "sample_count": int(len(scores)), "q95": q95, "q99": q99}


def _ml_priority(raw: float, calibration: dict[str, Any]) -> float:
    if not calibration["valid"]:
        return 0.0
    return _clip((raw - calibration["q95"]) / (calibration["q99"] - calibration["q95"]))


def budget_threshold(scores: Iterable[float], budget_per_100_user_days: float = 1.) -> dict[str, Any]:
    """Select a threshold without labels; ties never exceed the alert budget."""
    values = np.asarray(list(scores), dtype=float)
    if len(values) == 0 or not np.isfinite(values).all():
        raise ValueError("Validation scores must be nonempty and finite")
    if budget_per_100_user_days < 0:
        raise ValueError("Alert budget must be nonnegative")
    allowed = min(len(values), int(math.floor(len(values) * budget_per_100_user_days / 100.)))
    if allowed == 0:
        threshold = float(np.nextafter(values.max(), math.inf))
    else:
        cutoff = float(np.sort(values)[::-1][allowed - 1])
        threshold = cutoff if int(np.sum(values >= cutoff)) <= allowed else float(np.nextafter(cutoff, math.inf))
    return {"threshold": threshold, "comparison": ">=", "allowed_alerts": allowed,
            "observed_validation_alerts": int(np.sum(values >= threshold)),
            "validation_user_days": len(values), "budget_per_100_user_days": budget_per_100_user_days,
            "selection_uses_labels": False, "ties": "conservative_threshold_no_top_k_tie_breaking"}


def evaluate_detector(rows: list[dict[str, Any]], scores: list[float], threshold: float) -> dict[str, Any]:
    """User-day metrics; an actor hit requires an alert on a labeled positive day."""
    y = np.asarray([int(r["label"]) for r in rows])
    values = np.asarray(scores, dtype=float)
    predicted = values >= threshold
    tp = int(np.sum(predicted & (y == 1)))
    fp = int(np.sum(predicted & (y == 0)))
    fn = int(np.sum(~predicted & (y == 1)))
    tn = int(np.sum(~predicted & (y == 0)))
    precision = tp / (tp + fp) if tp + fp else 0.
    recall = tp / (tp + fn) if tp + fn else 0.
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.
    positive_actors = {r["subject_id"] for r in rows if r["label"]}
    detected_actors = {r["subject_id"] for r, p in zip(rows, predicted) if r["label"] and p}
    all_actors = {r["subject_id"] for r in rows}
    normal_flagged = {r["subject_id"] for r, p in zip(rows, predicted)
                      if p and r["subject_id"] not in positive_actors}
    episodes: dict[str, list[tuple[dict, bool]]] = defaultdict(list)
    for row, p in zip(rows, predicted):
        if row["label"]:
            # Exact provided episode IDs; otherwise use each labeled user-day.
            key = row.get("episode_id") or f"{row['subject_id']}:{row['date']}"
            episodes[key].append((row, bool(p)))
    detected_episodes, delays = 0, []
    for episode in episodes.values():
        detected_dates = [r["date"] for r, p in episode if p]
        if detected_dates:
            detected_episodes += 1
            start = min(r["date"] for r, _ in episode)
            delays.append((date.fromisoformat(min(detected_dates)) - date.fromisoformat(start)).days)
    day_count = len({r["date"] for r in rows})
    return {
        "unit": "completed_user_day", "test_user_days": len(rows),
        "positive_user_days": int(y.sum()), "negative_user_days": int((y == 0).sum()),
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": precision, "recall": recall, "f1": f1,
        "average_precision": float(average_precision_score(y, values)) if y.sum() else None,
        "roc_auc": float(roc_auc_score(y, values)) if 0 < y.sum() < len(y) else None,
        "alert_count": tp + fp, "alerts_per_100_user_days": 100 * (tp + fp) / max(1, len(rows)),
        "false_alerts_per_calendar_day": fp / max(1, day_count),
        "false_alerts_per_100_normal_user_days": 100 * fp / max(1, tn + fp),
        "actor_recall_in_labeled_malicious_windows": len(detected_actors) / len(positive_actors) if positive_actors else None,
        "malicious_actors": len(positive_actors), "actors_detected_in_malicious_windows": len(detected_actors),
        "normal_actors": len(all_actors - positive_actors), "normal_actors_with_any_alert": len(normal_flagged),
        "labeled_episodes": len(episodes), "episodes_detected_in_labeled_windows": detected_episodes,
        "episode_recall": detected_episodes / len(episodes) if episodes else None,
        "mean_detection_delay_days_for_detected_episodes": float(np.mean(delays)) if delays else None,
        "actor_metric_definition": "An actor is detected only by an alert on that actor's labeled malicious day; alerts on benign days never count as hits.",
    }


def score_daily_records(
    records: list[dict[str, Any]], *, train_end: str, validation_end: str,
    seed: int = 42, budget_per_100_user_days: float = 1.,
    provenance: str = PROVENANCE, profile: str = PROFILE,
    dataset_generated: bool = True, label_provenance: str = LABEL_PROVENANCE,
    timestamp_suffix: str = "+04:00",
    model_output: str | None = None,
) -> dict[str, Any]:
    """Fit on earlier completed days, calibrate later, evaluate last. No label filtering."""
    if train_end >= validation_end:
        raise ValueError("Training cutoff must precede validation cutoff")
    if any(r.get("label") not in (0, 1) for r in records):
        raise ValueError("Evaluation requires explicit binary labels; null labels are not benign")
    model_version = MODEL_VERSION if profile == PROFILE else "iforest-cert-daily-v1"
    featured = extract_past_only_features(records)
    train = [r for r in featured if r["date"] <= train_end]
    validation = [r for r in featured if train_end < r["date"] <= validation_end]
    test = [r for r in featured if r["date"] > validation_end]
    if min(len(train), len(validation), len(test)) == 0:
        raise ValueError("Nonempty chronological train, validation and test sets are required after warm-up")
    x_train = np.asarray([[r["features"][name] for name in FEATURE_NAMES] for r in train], dtype=float)
    model = IsolationForest(n_estimators=160, max_samples=min(256, len(train)),
                            contamination="auto", random_state=seed, n_jobs=1)
    model.fit(x_train)
    for split in (train, validation, test):
        matrix = np.asarray([[r["features"][name] for name in FEATURE_NAMES] for r in split], dtype=float)
        for row, anomaly in zip(split, -model.score_samples(matrix)):
            row["raw_anomaly"] = float(anomaly)
    calibration = calibrate_ml_scores(r["raw_anomaly"] for r in validation)
    for row in featured:
        row["ml_score"] = _ml_priority(row["raw_anomaly"], calibration)
        row["combined_priority"] = .6 * row["rule_score"] + .4 * row["ml_score"]
        row["behavior_score"] = round(100 * row["combined_priority"])
        row["as_of"] = row["date"] + "T23:59:59" + timestamp_suffix
        row["profile"] = profile
        row["feature_version"] = FEATURE_VERSION
        row["model_version"] = model_version
        row["score_is_probability"] = False
        if row["ml_score"] >= .5:
            row["reasons"].append("The multivariate Isolation Forest score is elevated against the frozen validation distribution.")
    columns = {"rules": "rule_score", "isolation_forest": "raw_anomaly", "combined": "combined_priority"}
    comparisons, operating_points = {}, {}
    for name, column in columns.items():
        selected = budget_threshold([r[column] for r in validation], budget_per_100_user_days)
        operating_points[name] = selected
        comparisons[name] = evaluate_detector(test, [r[column] for r in test], selected["threshold"])
    model_artifact = None
    if model_output:
        import hashlib
        from pathlib import Path
        import joblib
        import sklearn
        destination = Path(model_output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": model, "feature_names": FEATURE_NAMES,
                     "feature_version": FEATURE_VERSION, "model_version": model_version,
                     "profile": profile, "provenance": provenance, "seed": seed,
                     "train_end": train_end, "validation_end": validation_end,
                     "calibration": calibration, "operating_points": operating_points,
                     "sklearn_version": sklearn.__version__}, destination, compress=3)
        model_artifact = {"name": destination.name, "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
                          "format": "joblib_pickle_trusted_local_artifact_only", "sklearn_version": sklearn.__version__}
    latest_date = max(r["date"] for r in featured)
    latest_by_subject = {r["subject_id"]: r for r in test}
    latest = sorted(latest_by_subject.values(), key=lambda r: r["subject_id"])
    claim_scope = ("Controlled synthetic lab only; no CERT benchmark or production-accuracy claim."
                   if dataset_generated else
                   "Published synthetic CERT subset, incident-associated copy user-days; no live or production-accuracy claim.")
    return {
        "provenance": provenance, "dataset_generated": dataset_generated, "dataset_is_synthetic": True,
        "dataset_generated_by_sedra": dataset_generated, "label_provenance": label_provenance,
        "profile": profile, "feature_version": FEATURE_VERSION, "model_version": model_version,
        "seed": seed, "as_of": latest_date + "T23:59:59" + timestamp_suffix,
        "subjects": latest, "records": latest,
        "history": [{"subject_id": r["subject_id"], "date": r["date"], "behavior_score": r["behavior_score"],
                     "rule_score": r["rule_score"], "ml_score": r["ml_score"], "copy_count": r["copy_count"],
                     "raw_anomaly": r["raw_anomaly"], "combined_priority": r["combined_priority"],
                     "label": r["label"], "episode_id": r.get("episode_id"), "scenario": r.get("scenario")}
                    for r in test],
        "evaluation": {
            "provenance": provenance, "dataset_generated": dataset_generated,
            "dataset_is_synthetic": True, "dataset_generated_by_sedra": dataset_generated,
            "claim_scope": claim_scope,
            "unit": "completed_user_day", "label_provenance": label_provenance,
            "split": {"strategy": "chronological_no_shuffle", "train_end": train_end,
                      "validation_end": validation_end, "test_start": min(r["date"] for r in test),
                      "test_end": latest_date, "train_user_days": len(train),
                      "validation_user_days": len(validation), "test_user_days": len(test),
                      "warmup_excluded_user_days": len(records) - len(featured)},
            "baseline": {"prior_only": True, "same_day_peers_excluded": True,
                         "history_days": 28, "minimum_history_days": 14, "peer_minimum_other_users": 5,
                         "updates": "Past observed days, including prior anomalies, enter history; labels never filter history."},
            "model": {"estimator": "IsolationForest", "n_estimators": 160, "contamination": "auto",
                      "feature_names": list(FEATURE_NAMES), "labels_used_in_fit": False,
                      "weights": {"rule_max": .6, "ml_tail": .4},
                      "weights_status": "Predeclared demo engineering parameters, not learned probabilities."},
            "ml_calibration": calibration, "operating_points": operating_points,
            "model_artifact": model_artifact,
            "comparisons": comparisons,
            "limits": ["No real employees or live enterprise data are represented.",
                       "A daily model does not score a partial current day.",
                       "A dataset label describes a scenario, not an inferred human intent.",
                       "Low support and distribution shift require a separate pilot.",
                       "An alert-budget threshold controls candidate triage, never hard DLP enforcement."],
        },
    }


def build_demo_snapshot(seed: int = 42) -> dict[str, Any]:
    """Stable entrypoint used once at application startup."""
    records = generate_demo_daily_records(seed)
    return score_daily_records(records, train_end="2026-09-18", validation_end="2026-10-09", seed=seed)
