# Final GitHub submission checklist

User-supplied times, Asia/Baku: **31 October 2026 17:00 checkpoint**, **1 November 13:00–13:30 GitHub submission**, **five-minute presentation plus five-minute Q&A**. Confirm later organizer instructions.

## Verify and freeze

- [ ] Start from Python 3.12; show one confirmed send, block and reconciled unknown delivery.
- [ ] Show the dated ML context and separate actual live rule changing the same-text decision.
- [ ] Run `scripts/verify.py`; inspect the actual count, failures and errors in test_summary.json.
- [ ] Run `scripts/live_smoke.py` against the authorized loopback lab; inspect original digests and receipts.
- [ ] Check frontend syntax and Python compilation; refresh all three screens and role switching.
- [ ] Preserve failed file-only v1 artifacts and audit_before/audit_after comparisons.
- [ ] Read v2 metrics, primary/secondary labels, prevalence, actor/episode denominator, workload and limitations. Pending results are not measured success.
- [ ] For the optional AI portal, privately configure the key, obtain a real public-text answer and verify restricted content has no provider contact. Inspect ai_portal_live_smoke.json; configured status alone is insufficient. Keep keys and response caches out of Git.
- [ ] Rehearse with another teammate operating the browser within five minutes.
- [ ] Confirm the team can explain the source, features, labels, thresholds, delivery states and limitations.

## Repository content

Include source, tests, pinned requirements, current docs, attributed Unicode data/license, AI usage disclosure, presentation and measured artifacts. Include provenance manifests/checksums and frozen protocol. Exclude raw CERT data, virtual environment, runtime SQLite databases, private tokens and scratch files.

PACKAGE_MANIFEST.json records package file hashes. Keep optional large Windows offline wheels separate from the small source ZIP. Never add the multi-gigabyte CERT archive to the competition repository.

## Publish to the designated destination

1. Inspect the final diff and file list.
2. Commit the frozen source and evidence.
3. Verify the actual organizer-designated repository/remote and permissions.
4. Push before the confirmed cutoff and verify the remote commit SHA.
5. Submit the exact URL, branch and commit requested by organizers.
6. Verify clean-checkout startup and README links on GitHub.
7. Keep the offline presentation, speaker script, screenshots and saved evidence ready.

This build does not assume a repository destination, invent a successful push or claim organizer acceptance.
