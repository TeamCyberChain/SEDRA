#!/usr/bin/env python3
"""Stream a LOCAL CERT r4.2 file.csv into provenance-preserving user-days.

No downloads are performed. The r4.2 file stream describes copying to removable
media, not general file reads. Labels require observed copies inside declared
incident intervals; actor membership alone never labels an entire history.
"""
from __future__ import annotations

import argparse
import bisect
import csv
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path
import re
import sqlite3
import sys
import tarfile
import tempfile
from typing import Any


REQUIRED_HEADERS = {"id", "date", "user", "pc", "filename", "content"}


def load_answer_file_labels(archive: str | Path) -> tuple[dict[str, dict], dict]:
    """Join actor-matched *file* observable IDs, not all context rows.

    The publisher's detailed incident files also contain contextual activity by
    other actors. The master file supplies each incident's declared actor.
    """
    labels: dict[str, dict] = {}
    with tarfile.open(archive, "r:bz2") as source:
        members = {Path(m.name).name: m for m in source.getmembers() if m.isfile()}
        if "insiders.csv" not in members:
            raise ValueError("Answer archive has no insiders.csv master file")
        stream = io.TextIOWrapper(source.extractfile(members["insiders.csv"]), encoding="utf-8-sig")
        incidents = [r for r in csv.DictReader(stream) if r.get("dataset") == "4.2"]
        if not incidents:
            raise ValueError("Answer archive contains no r4.2 incidents")
        context_skipped = 0
        for incident in incidents:
            name = incident["details"]
            if name not in members:
                raise ValueError(f"Missing incident observables: {name}")
            data = io.TextIOWrapper(source.extractfile(members[name]), encoding="utf-8-sig")
            for row in csv.reader(data):
                if len(row) < 4 or row[0] != "file":
                    continue
                if row[3] != incident["user"]:
                    context_skipped += 1
                    continue
                labels[row[1]] = {
                    "actor": incident["user"], "scenario": incident["scenario"],
                    "episode_id": Path(name).stem,
                    "episode_start": datetime.strptime(incident["start"], "%m/%d/%Y %H:%M:%S").isoformat(),
                    "episode_end": datetime.strptime(incident["end"], "%m/%d/%Y %H:%M:%S").isoformat(),
                }
    return labels, {"source_name": Path(archive).name, "sha256": sha256_file(Path(archive)),
                    "r4_2_incidents": len(incidents), "actor_matched_file_event_ids": len(labels),
                    "other_actor_file_observables_excluded": context_skipped,
                    "incident_intervals": [{"actor": r["user"], "scenario": r["scenario"],
                        "episode_id": Path(r["details"]).stem,
                        "start": datetime.strptime(r["start"], "%m/%d/%Y %H:%M:%S").isoformat(),
                        "end": datetime.strptime(r["end"], "%m/%d/%Y %H:%M:%S").isoformat()} for r in incidents],
                    "label_rule": "A user-day is incident-associated iff an actual file copy by the declared actor occurs within the master incident's inclusive start/end interval. This is contextual ground truth, not proof every file copy is malicious. Exact file observable IDs are supplementary evidence."}


def load_ldap_snapshots(folder: str | Path) -> tuple[list[str], dict[str, dict], list[dict]]:
    snapshots, metadata = {}, []
    for path in sorted(Path(folder).rglob("*.csv")):
        match = re.fullmatch(r"(\d{4})-(\d{2})", path.stem)
        if not match:
            continue
        month = path.stem
        roles = {}
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            if not {"user_id", "role"} <= set(reader.fieldnames or []):
                raise ValueError(f"LDAP file lacks user_id/role columns: {path.name}")
            for row in reader:
                if row["user_id"]:
                    roles[row["user_id"]] = row["role"] or "Unknown"
        snapshots[month] = roles
        metadata.append({"name": path.name, "month": month, "sha256": sha256_file(path), "users": len(roles)})
    if not snapshots:
        raise ValueError("No dated YYYY-MM.csv LDAP snapshots were found")
    return sorted(snapshots), snapshots, metadata


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ingest(
    input_path: str | Path, output_path: str | Path, *,
    metadata_path: str | Path | None = None,
    workday_start: int = 9, workday_end: int = 18,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
    answers_archive: str | Path | None = None,
    ldap_dir: str | Path | None = None,
) -> dict[str, Any]:
    source, destination = Path(input_path).resolve(), Path(output_path).resolve()
    if source == destination:
        raise ValueError("Input and output must be different files")
    sidecar = Path(metadata_path) if metadata_path else destination.with_suffix(destination.suffix + ".metadata.json")
    if sidecar.resolve() in (source, destination):
        raise ValueError("Metadata path must differ from input and output")
    if not 0 <= workday_start < workday_end <= 24:
        raise ValueError("Reference work hours must satisfy 0 <= start < end <= 24")
    if not source.is_file():
        raise ValueError(f"Local source not found: {source}")
    source_stat = source.stat()
    if expected_size is not None and source_stat.st_size != expected_size:
        raise ValueError(f"Source length mismatch: expected {expected_size} bytes, found {source_stat.st_size}; extraction may be incomplete")
    with source.open("rb") as source_bytes:
        if source_stat.st_size == 0:
            raise ValueError("Source CSV is empty")
        source_bytes.seek(-1, 2)
        if source_bytes.read(1) not in (b"\n", b"\r"):
            raise ValueError("CERT CSV does not end in a line terminator; verify extraction completeness before importing")
    source_hash = sha256_file(source)
    after_hash_stat = source.stat()
    if (source_stat.st_size, source_stat.st_mtime_ns) != (after_hash_stat.st_size, after_hash_stat.st_mtime_ns):
        raise ValueError("Source changed during hashing; wait for extraction to complete")
    if expected_sha256 and source_hash.lower() != expected_sha256.lower():
        raise ValueError("Source SHA256 does not match the expected value")
    destination.parent.mkdir(parents=True, exist_ok=True)
    selected_rows, first_time, last_time = 0, None, None
    headers: list[str] = []
    answer_labels, answer_metadata = load_answer_file_labels(answers_archive) if answers_archive else ({}, None)
    actor_intervals: dict[str, list[dict]] = {}
    for incident in (answer_metadata or {}).get("incident_intervals", []):
        actor_intervals.setdefault(incident["actor"], []).append(incident)
    ldap_months, ldap, ldap_metadata = load_ldap_snapshots(ldap_dir) if ldap_dir else ([], {}, [])
    matched_answer_ids = set()
    with tempfile.TemporaryDirectory(prefix="sadd-cert-") as scratch:
        database = sqlite3.connect(str(Path(scratch) / "aggregate.sqlite"))
        try:
            database.executescript("""
                CREATE TABLE event_ids (id TEXT PRIMARY KEY);
                CREATE TABLE days (
                    subject TEXT, day TEXT, copies INTEGER, after_hours INTEGER,
                    malicious_copies INTEGER,
                    exact_observable_copies INTEGER,
                    PRIMARY KEY(subject, day)
                );
                CREATE TABLE hosts (subject TEXT, day TEXT, host TEXT,
                    PRIMARY KEY(subject, day, host));
                CREATE TABLE resources (subject TEXT, day TEXT, digest TEXT,
                    PRIMARY KEY(subject, day, digest));
                CREATE TABLE episodes (subject TEXT, day TEXT, episode TEXT, scenario TEXT, start TEXT, end TEXT,
                    PRIMARY KEY(subject, day, episode));
            """)
            # CSV parser limits are explicit; source content is discarded.
            csv.field_size_limit(16 * 1024 * 1024)
            with source.open("r", encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                headers = reader.fieldnames or []
                missing = sorted(REQUIRED_HEADERS - set(headers))
                if missing:
                    raise ValueError("Missing required CERT r4.2 columns: " + ", ".join(missing))
                if len(headers) != len(set(headers)):
                    raise ValueError("Duplicate CSV header names are not accepted")
                if "activity" in headers or "to_removable_media" in headers:
                    raise ValueError("A different release's activity schema was found; this importer is restricted to CERT r4.2 file.csv")
                for line_number, row in enumerate(reader, 2):
                    if None in row or any(row.get(name) is None for name in REQUIRED_HEADERS):
                        raise ValueError(f"Malformed CSV row at line {line_number}")
                    if not all(row[name].strip() for name in ("id", "date", "user", "pc", "filename")):
                        raise ValueError(f"Empty required value at line {line_number}")
                    try:
                        stamp = datetime.strptime(row["date"], "%m/%d/%Y %H:%M:%S")
                    except ValueError as exc:
                        raise ValueError(f"Invalid CERT timestamp at line {line_number}") from exc
                    try:
                        database.execute("INSERT INTO event_ids VALUES (?)", (row["id"],))
                    except sqlite3.IntegrityError as exc:
                        raise ValueError(f"Duplicate source event ID at line {line_number}") from exc
                    subject = "cert-r4.2:" + row["user"]
                    day = stamp.date().isoformat()
                    outside_hours = int(stamp.hour < workday_start or stamp.hour >= workday_end)
                    exact_evidence = answer_labels.get(row["id"])
                    exact_positive = int(bool(exact_evidence and exact_evidence["actor"] == row["user"]))
                    interval_matches = [i for i in actor_intervals.get(row["user"], [])
                                        if i["start"] <= stamp.isoformat() <= i["end"]]
                    label_evidence = interval_matches[0] if interval_matches else None
                    is_positive = int(bool(label_evidence))
                    database.execute("""
                        INSERT INTO days VALUES (?, ?, 1, ?, ?, ?)
                        ON CONFLICT(subject, day) DO UPDATE SET
                        copies=copies+1, after_hours=after_hours+excluded.after_hours,
                        malicious_copies=malicious_copies+excluded.malicious_copies,
                        exact_observable_copies=exact_observable_copies+excluded.exact_observable_copies
                    """, (subject, day, outside_hours, is_positive, exact_positive))
                    if exact_positive:
                        matched_answer_ids.add(row["id"])
                    if is_positive:
                        database.execute("INSERT OR IGNORE INTO episodes VALUES (?, ?, ?, ?, ?, ?)",
                            (subject, day, label_evidence["episode_id"], label_evidence["scenario"],
                             label_evidence["start"], label_evidence["end"]))
                    database.execute("INSERT OR IGNORE INTO hosts VALUES (?, ?, ?)",
                                     (subject, day, "cert-r4.2:" + row["pc"]))
                    resource_digest = hashlib.sha256(row["filename"].encode("utf-8")).hexdigest()
                    database.execute("INSERT OR IGNORE INTO resources VALUES (?, ?, ?)",
                                     (subject, day, resource_digest))
                    selected_rows += 1
                    first_time = stamp if first_time is None else min(first_time, stamp)
                    last_time = stamp if last_time is None else max(last_time, stamp)
                    if selected_rows % 10000 == 0:
                        database.commit()
            database.commit()
            if not selected_rows:
                raise ValueError("Source contains no activity records")
            after_parse_stat = source.stat()
            if (source_stat.st_size, source_stat.st_mtime_ns) != (after_parse_stat.st_size, after_parse_stat.st_mtime_ns):
                raise ValueError("Source changed during import; outputs will not be published")
            user_days = database.execute("SELECT COUNT(*) FROM days").fetchone()[0]
            users = database.execute("SELECT COUNT(DISTINCT subject) FROM days").fetchone()[0]
            source_subjects = {r[0] for r in database.execute("SELECT DISTINCT subject FROM days")}
            roster_subjects = {"cert-r4.2:" + user for snapshot in ldap.values() for user in snapshot}
            associated_events = database.execute("SELECT SUM(malicious_copies) FROM days").fetchone()[0]
            associated_days = database.execute("SELECT COUNT(*) FROM days WHERE malicious_copies>0").fetchone()[0]
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                             prefix=destination.name + ".", suffix=".tmp", delete=False) as target:
                temporary_output = Path(target.name)
                try:
                    for subject, day, copies, hours, malicious_copies, exact_copies in database.execute(
                        "SELECT subject,day,copies,after_hours,malicious_copies,exact_observable_copies FROM days ORDER BY day,subject"
                    ):
                        hosts = [r[0] for r in database.execute(
                            "SELECT host FROM hosts WHERE subject=? AND day=? ORDER BY host", (subject, day))]
                        resources = database.execute(
                            "SELECT COUNT(*) FROM resources WHERE subject=? AND day=?", (subject, day)).fetchone()[0]
                        month_index = bisect.bisect_right(ldap_months, day[:7]) - 1
                        role = ldap[ldap_months[month_index]].get(subject.split(":", 1)[1], "Unknown") if month_index >= 0 else "Unknown"
                        episode_rows = database.execute(
                            "SELECT episode,scenario,start,end FROM episodes WHERE subject=? AND day=? ORDER BY episode", (subject, day)).fetchall()
                        record = {
                            "subject_id": subject, "date": day, "role": role,
                            "copy_count": copies, "after_hours_copies": hours,
                            "workstations": hosts, "unique_filename_count": resources,
                            "operation": "removable_media_copy", "provenance": "cert_synthetic",
                            "dataset_release": "r4.2", "dataset_is_synthetic": True,
                            "dataset_generated_by_sadd": False, "source_sha256": source_hash,
                            "label": int(malicious_copies > 0) if answers_archive else None,
                            "incident_associated_copy_events": malicious_copies if answers_archive else None,
                            "exact_observable_copy_events": exact_copies if answers_archive else None,
                            "label_provenance": "cert_r4.2_master_actor_interval_copy_days" if answers_archive else "not_joined",
                            "label_evidence_level": "actor_interval_context_not_individual_copy_verdict" if answers_archive else "unlabeled",
                            "episode_id": episode_rows[0][0] if episode_rows else None,
                            "scenario": episode_rows[0][1] if episode_rows else None,
                            "episode_start": episode_rows[0][2] if episode_rows else None,
                            "episode_end": episode_rows[0][3] if episode_rows else None,
                            "role_provenance": "dated_ldap_month_snapshot" if month_index >= 0 else "not_provided",
                            "role_snapshot_month": ldap_months[month_index] if month_index >= 0 else None,
                        }
                        target.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                except BaseException:
                    temporary_output.unlink(missing_ok=True)
                    raise
            temporary_output.replace(destination)
        finally:
            database.close()
    metadata = {
        "dataset": "CERT Insider Threat Test Dataset", "release": "r4.2",
        "publisher": "CMU Software Engineering Institute",
        "publisher_url": "https://sei.cmu.edu/library/insider-threat-test-dataset/",
        "publisher_record": "https://doi.org/10.1184/R1/12841247.v1",
        "source_name": source.name, "source_sha256": source_hash,
        "source_size_bytes": source.stat().st_size,
        "expected_source_size_bytes": expected_size,
        "source_stability_checked": True, "source_final_line_terminator_checked": True,
        "checksum_assertion": "matched_caller_expected_hash" if expected_sha256 else "local_fingerprint_only_not_publisher_authenticated",
        "headers": headers, "source_event_rows": selected_rows, "output_user_days": user_days,
        "subjects": users, "first_event": first_time.isoformat(), "last_event": last_time.isoformat(),
        "cohort_subject_ids": sorted(source_subjects | roster_subjects),
        "cohort_population": "Union of source file-copy identities and dated LDAP roster identities; independent of answer labels.",
        "output_name": destination.name, "output_sha256": sha256_file(destination),
        "provenance": "cert_synthetic", "dataset_is_synthetic": True,
        "dataset_generated_by_sadd": False, "operation": "removable_media_copy",
        "aggregation": "source-local calendar day; active days only; no synthetic zero days inserted",
        "reference_hours": {"start_inclusive": workday_start, "end_exclusive": workday_end,
                            "timezone": "unspecified_dataset_local",
                            "meaning": "Analysis convention; not an employee's authorized work schedule"},
        "labels": answer_metadata or "Not joined. Null labels must never be treated as benign. Join answer-key event/interval evidence before evaluation.",
        "matched_answer_file_event_ids": len(matched_answer_ids),
        "incident_associated_file_events": associated_events if answers_archive else None,
        "incident_associated_user_days": associated_days if answers_archive else None,
        "answer_file_event_ids_absent_from_input": len(set(answer_labels) - matched_answer_ids),
        "roles": ldap_metadata or "Not joined. Use dated LDAP metadata as of the event before enabling peer groups.",
        "scope": "All input rows; no sampling, no activity reinterpretation, no downloads.",
        "privacy": "Content and filenames are not written to output. Resource hashes are used only for distinct counts.",
    }
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return metadata


def attach_incident_coverage(
    snapshot: dict, raw_records: list[dict], metadata: dict, selected: set[str],
) -> None:
    """Keep no-signal selected incidents in actor/episode recall denominators."""
    test_start = snapshot["evaluation"]["split"]["test_start"]
    test_end = snapshot["evaluation"]["split"]["test_end"]
    label_metadata = metadata.get("labels")
    if not isinstance(label_metadata, dict) or "incident_intervals" not in label_metadata:
        raise ValueError("Source metadata with all master incident intervals is required for coverage-aware recall")
    incidents = [i for i in label_metadata["incident_intervals"]
                 if "cert-r4.2:" + i["actor"] in selected
                 and i["start"][:10] <= test_end and i["end"][:10] >= test_start]
    by_episode = {i["episode_id"]: i for i in incidents}
    actors = {"cert-r4.2:" + i["actor"] for i in incidents}
    observed = {r.get("episode_id") for r in raw_records
                if r.get("label") == 1 and test_start <= r["date"] <= test_end} & set(by_episode)
    scored = {r.get("episode_id") for r in snapshot["history"] if r.get("label") == 1} & set(by_episode)
    snapshot["evaluation"]["incident_coverage"] = {
        "selected_master_incidents_overlapping_test": len(incidents),
        "selected_incident_actors": len(actors),
        "incidents_with_observed_copy_events_in_test_interval": len(observed),
        "incidents_without_observable_copy_events_in_test_interval": len(set(by_episode) - observed),
        "incidents_with_scored_positive_copy_days": len(scored),
        "observed_incidents_unscored_by_history_policy": len(observed - scored),
        "no_signal_episode_ids": sorted(set(by_episode) - observed),
        "unscored_episode_ids": sorted(observed - scored),
        "denominator_rule": "All selected master incidents overlapping the test interval, including no-copy/no-score incidents. Those are misses in coverage-adjusted actor/episode recall.",
    }
    columns = {"rules": "rule_score", "isolation_forest": "raw_anomaly", "combined": "combined_priority"}
    for name, comparison in snapshot["evaluation"]["comparisons"].items():
        threshold = snapshot["evaluation"]["operating_points"][name]["threshold"]
        flagged = [r for r in snapshot["history"] if r[columns[name]] >= threshold]
        detected_episodes = {r.get("episode_id") for r in flagged if r["label"] == 1} & set(by_episode)
        detected_actors = {"cert-r4.2:" + by_episode[e]["actor"] for e in detected_episodes}
        comparison["source_conditional_episode_recall"] = comparison["episode_recall"]
        comparison["source_conditional_actor_recall"] = comparison["actor_recall_in_labeled_malicious_windows"]
        comparison["episode_recall"] = len(detected_episodes) / len(incidents) if incidents else None
        comparison["actor_recall_in_labeled_malicious_windows"] = len(detected_actors) / len(actors) if actors else None
        comparison["labeled_episodes"] = len(incidents)
        comparison["episodes_detected_in_labeled_windows"] = len(detected_episodes)
        comparison["malicious_actors"] = len(actors)
        comparison["actors_detected_in_malicious_windows"] = len(detected_actors)
        comparison["normal_actors"] = len(selected - actors)
        comparison["normal_actors_with_any_alert"] = len({r["subject_id"] for r in flagged} - actors)
        comparison["actor_metric_definition"] = "Denominator includes all selected master actors with incidents overlapping test, even without observable or scoreable file-copy days. A hit requires an alert inside an incident-associated copy day."


def enrich_user_days_ldap(
    user_days_path: str | Path, ldap_dir: str | Path, *, metadata_path: str | Path | None = None,
) -> dict[str, Any]:
    """Add dated roles after source aggregation, without reparsing file.csv."""
    source = Path(user_days_path)
    sidecar = Path(metadata_path) if metadata_path else source.with_suffix(source.suffix + ".metadata.json")
    metadata = json.loads(sidecar.read_text())
    months, snapshots, role_metadata = load_ldap_snapshots(ldap_dir)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=source.parent,
                                     prefix=source.name + ".", suffix=".tmp", delete=False) as target:
        temporary_output = Path(target.name)
        try:
            with source.open(encoding="utf-8") as stream:
                for line in stream:
                    row = json.loads(line)
                    month_index = bisect.bisect_right(months, row["date"][:7]) - 1
                    actor = row["subject_id"].split(":", 1)[1]
                    row["role"] = snapshots[months[month_index]].get(actor, "Unknown") if month_index >= 0 else "Unknown"
                    row["role_provenance"] = "dated_ldap_month_snapshot" if month_index >= 0 else "not_provided"
                    row["role_snapshot_month"] = months[month_index] if month_index >= 0 else None
                    target.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        except BaseException:
            temporary_output.unlink(missing_ok=True)
            raise
    temporary_output.replace(source)
    roster = {"cert-r4.2:" + u for snapshot in snapshots.values() for u in snapshot}
    metadata["roles"] = role_metadata
    metadata["cohort_subject_ids"] = sorted(set(metadata.get("cohort_subject_ids", [])) | roster)
    metadata["output_sha256"] = sha256_file(source)
    sidecar.write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n")
    return metadata


def run_cert_benchmark(
    user_days_path: str | Path, output_path: str | Path, *, max_users: int = 200,
    train_end: str = "2010-06-30", validation_end: str = "2010-09-30", seed: int = 42,
    metadata_path: str | Path | None = None,
    model_output: str | Path | None = None,
) -> dict[str, Any]:
    """Deterministic label-blind user selection, then a distinct CERT profile."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from sadd.behavior import score_daily_records
    source = Path(user_days_path)
    if source.resolve() == Path(output_path).resolve():
        raise ValueError("Benchmark output must not overwrite user-day input")
    if max_users < 0:
        raise ValueError("max_users must be nonnegative (zero means all)")
    users = set()
    with source.open() as stream:
        for line in stream:
            users.add(json.loads(line)["subject_id"])
    sidecar = Path(metadata_path) if metadata_path else source.with_suffix(source.suffix + ".metadata.json")
    if not sidecar.is_file():
        raise ValueError("User-day metadata sidecar is required for source and label coverage")
    metadata = json.loads(sidecar.read_text())
    users.update(metadata.get("cohort_subject_ids", []))
    ordered = sorted(users, key=lambda u: hashlib.sha256(u.encode()).hexdigest())
    selected = set(ordered[:max_users] if max_users else ordered)
    records = []
    with source.open() as stream:
        for line in stream:
            row = json.loads(line)
            if row["subject_id"] in selected:
                if row.get("label") not in (0, 1):
                    raise ValueError("Answer-key labels are required before a benchmark can run")
                records.append(row)
    snapshot = score_daily_records(
        records, train_end=train_end, validation_end=validation_end, seed=seed,
        provenance="cert_synthetic", profile="cert_daily_v1", dataset_generated=False,
        label_provenance="cert_r4.2_master_actor_interval_copy_days", timestamp_suffix="",
        model_output=str(model_output or Path(output_path).with_suffix(".model.joblib")),
    )
    snapshot["evaluation"]["dataset_selection"] = {
        "source_sha256": sha256_file(source), "available_users": len(users), "selected_users": len(selected),
        "selection_rule": "Lowest SHA256(subject_id), independent of labels and scores; zero max_users means all.",
        "selected_subject_ids": sorted(selected), "max_users": max_users,
        "population": "Active removable-media-copy user-days only; no zero-filled calendar days.",
        "timezone": "unspecified_dataset_local", "comparable_to_full_CERT_benchmarks": False,
    }
    attach_incident_coverage(snapshot, records, metadata, selected)
    snapshot["evaluation"]["limits"].append("Positive days associate a declared actor's observed file copies with the master incident interval; this coarse contextual label does not prove each copy malicious. Exact file-observable IDs are supplementary. Other channels are outside this benchmark.")
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Local CERT r4.2 file.csv")
    parser.add_argument("--output", required=True, help="User-day JSONL destination")
    parser.add_argument("--metadata", help="Optional metadata JSON destination")
    parser.add_argument("--workday-start", type=int, default=9)
    parser.add_argument("--workday-end", type=int, default=18)
    parser.add_argument("--expected-sha256", help="Optional known SHA256 of the LOCAL CSV")
    parser.add_argument("--expected-size", type=int, help="Expected extracted member length in bytes; full official r4.2 file.csv is 193055265")
    parser.add_argument("--answers-archive", help="Official local answers.tar.bz2: master incident intervals and supplementary exact file IDs")
    parser.add_argument("--ldap-dir", help="Local extracted dated YYYY-MM.csv LDAP snapshots")
    parser.add_argument("--benchmark-output", help="Optional separately labeled CERT benchmark JSON")
    parser.add_argument("--max-users", type=int, default=200, help="Label-blind benchmark subset; 0 means all users")
    parser.add_argument("--train-end", default="2010-06-30")
    parser.add_argument("--validation-end", default="2010-09-30")
    args = parser.parse_args()
    try:
        result = ingest(args.input, args.output, metadata_path=args.metadata,
                        workday_start=args.workday_start, workday_end=args.workday_end,
                        expected_sha256=args.expected_sha256,
                        expected_size=args.expected_size,
                        answers_archive=args.answers_archive, ldap_dir=args.ldap_dir)
        if args.benchmark_output:
            benchmark = run_cert_benchmark(args.output, args.benchmark_output, max_users=args.max_users,
                                           train_end=args.train_end, validation_end=args.validation_end,
                                           metadata_path=args.metadata)
            result["benchmark_summary"] = benchmark["evaluation"]["comparisons"]
    except (ValueError, OSError, csv.Error) as exc:
        parser.error(str(exc))
    print(json.dumps({"source_event_rows": result["source_event_rows"],
                      "output_user_days": result["output_user_days"],
                      "source_sha256": result["source_sha256"],
                      "provenance": result["provenance"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
