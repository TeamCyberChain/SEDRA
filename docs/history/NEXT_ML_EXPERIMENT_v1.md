# Next ML experiment and acceptance gate

## Decision

Keep the working gateway, evidence ledger and three-screen product. The next technical priority is a compact, source-aligned behavior experiment. The current file-only CERT baseline remains preserved as version 1, with its failed detection result.

## Input and observation unit

Start with `device.csv` and `logon.csv`, the existing copy aggregates and dated LDAP snapshots. Add email metadata after these joins are verified. Use `(release, channel, event_id)` as the identifier: the official README says event IDs are not globally unique across channels.

Create a user-calendar-day row only inside verified channel coverage and an eligible roster interval. A zero means no recorded events in a channel whose coverage is complete. Missing telemetry is a separate state. Preserve dataset-local timestamps; the release does not establish an Azerbaijan timezone.

Fourteen prior calendar days, including verified no-use days, can establish a reference. A person without enough personal history receives an explicitly limited peer/population assessment and remains in incident coverage. First observed USB use after a long no-use history must be scoreable. Workstation novelty is computed from earlier logons and activity; it is not called a new physical USB device.

## Compact features

| Source | Proposed evidence |
|---|---|
| Device | Connect count, unusual-hour connect count, first observed use, deviation from prior connection frequency |
| Logon | Time distribution, observed workstations, novelty against prior personal/peer history |
| File | Copy count, relative volume, resource breadth where the original fields support it |
| Email | Message count, external recipient count, recipient novelty and attachment count |

The release's email `size` excludes attachments; it is not total leaked bytes. A clock reference window is a modeling convention, not evidence that work was unauthorized.

## Labels and coverage

Predeclare the primary target as user-days containing an actor-matched official observable from one of the modeled channels. Validate channel, original ID, actor and timestamp against the actual source. Scenario files can contain another person's contextual rows; those must not turn that person into a malicious actor.

Retain the broader master-interval target as a secondary result. Include every selected incident overlapping the evaluation horizon in actor/episode coverage, even when no modeled channel observes it. Report no-signal, cold-start and scoreable incidents separately.

## Ranking and operating point

Keep the three rule explanations, but use a continuous underlying deviation for triage instead of relying only on clipped severity. Predeclare tie handling. An operating point above the score's maximum is explicitly inactive and cannot pass the product gate.

Compare rules, Isolation Forest and their frozen combination on the same observations. Compare personal-only and peer-context variants. The alert budget controls analyst workload; it does not disable hard content protection. Report TP/FP/FN, average precision relative to prevalence, alerts per 100 user-days, false-alerted actors, useful actor/episode recall and detection delay where meaningful.

## Honest holdout policy

The version-1 r4.2 test has now been observed. Any subsequent result on it is development evidence. Do not rename a newly selected subset an untouched test. Freeze the version-2 protocol before inspecting a genuinely new release or a prospective evaluation dataset, and keep its chronological train/validation/final-test split fixed.

The new source schema must be inspected before adapting features; fitted models and calibration remain source-specific. This is not a claim that a model trained on one CERT release transfers unchanged to another organization or to live lab users.

## Acceptance gate before an efficacy claim

1. Channel/actor/time joins and telemetry coverage are verified.
2. First-use and cold-start cases produce explicit assessments and remain in coverage.
3. The operating point produces a useful, nondegenerate triage queue.
4. A frozen evaluation shows useful recall at the declared alert burden and improves over the appropriate baseline; exact achieved values are reported.
5. Improvements on already inspected data are labeled development results.

Source expansion and feature/label alignment take priority over an autoencoder, SHAP, additional UI modules or a claim of 99% accuracy.
