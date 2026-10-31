# SEDRA implementation blueprint and historical design

> Current v2 implementation and executed evidence: [STATUS.md](STATUS.md), [matching contract](MATCHING_CONTRACT.md), [technical architecture](TECHNICAL_ARCHITECTURE.md). The original planning analysis below is retained as history. Its older test counts, matching limits and pending browser checks do not supersede the current reports.

SEDRA will deliver an explainable UEBA core with visible machine-learning evaluation, then connect that core to an authenticated AI gateway and cumulative document-fragment tracking. The competition build uses one product name and three main screens: Overview, Investigation, and AI Transfer Lab.

The delivery order is mandatory: a working log source, baseline, three anomaly rules, trained anomaly model and evidence-linked dashboard first; live prevention and cumulative matching second; investigation polish, compact validation experiments and packaging third. Performance figures will come from executed tests.

This plan is for Digital Challenge Azerbaijan on 31 October and 1 November 2026. All schedule times below use Asia/Baku.

# Current implementation and next ML gate

The first local executable build is available: three screens, separate lab and CERT behavior profiles, an actual local HTTP receiver, durable cumulative admission and a reproducible evaluation pipeline. The functional suite has executed 57 tests successfully. Browser visual QA remains pending because the managed preview environment lacks the declared NumPy dependency; local HTTP integration was verified independently.

The official r4.2 archive was downloaded and matched to its published SHA-256. The complete copy source contains 445,581 events and 45,907 active copy user-days from 264 copy-active identities; the LDAP roster contains 1,000 identities. A partial local extraction was rejected, independently re-extracted and reverified before the retained benchmark ran.

**The first file-only CERT detection configuration failed its quality gate.** At the frozen validation-selected operating points, rules, Isolation Forest and their combination each detect zero of 476 contextual positive test days. IF generates 120 false positives; the combination generates 100. Actor/episode recall is 0/40, retaining eight no-copy incidents and ten incidents excluded by insufficient personal copy history. This validates reproducible execution, not threat-detection efficacy.

The next ML version must first align sources and labels: device and logon activity alongside copies, with channel-qualified event IDs and actor/time validation against the official observables. It must construct calendar-day histories with explicit coverage and cold-start handling. A continuous triage ranking and declared tie policy replace the inactive saturated-rule operating point. The current r4.2 test is now development evidence; a revised model requires a genuinely untouched evaluation before an independent efficacy claim. Preserve the failed baseline and all measured artifacts.

The portable package contains docs/STATUS.md, docs/NEXT_ML_EXPERIMENT.md, the actual benchmark/model artifacts and source metadata. The product flow is fixed; behavior-model quality is the next acceptance gate.

# Decisions after the design review

| Review concern | Implementation decision |
|---|---|
| Mandatory UEBA result must be visible | Ingestion, baseline, three rules, trained Isolation Forest and risk panel are the first acceptance gate. |
| CERT semantics and provenance | Use CERT r4.2 as the primary external synthetic benchmark; file.csv means removable-media copy activity. Validate the actual README and headers. |
| Large archive | The team confirms AKM has no relevant download-size limit. Download the official approximately 4.8 GB archive in parallel with fixture development. |
| Daily and live feature mismatch | Evaluate CERT at user-day granularity. Fit a separate lab model; live requests use the last completed lab user-day snapshot with its timestamp visible. |
| Context-aware must affect a decision | High behavioral priority lowers the controlled-excerpt cumulative threshold; hard content prohibitions remain unconditional. |
| Matching limits | Index all normalized token 4-grams in the small corpus. Distinguish a candidate match from an enforcement decision. |
| Operational reliability | Durable SQLite admission, idempotency, unused-reservation TTL and unknown-delivery reconciliation are explicit contracts. |
| Delivery scope | One local Python application, three screens and an independent local HTTP receiver; no external API is needed for the core demo. |

# Data strategy and provenance

## Public benchmark

CMU describes CERT Insider Threat Test Dataset as synthetic background activity and synthetic malicious-actor data. Its answer archive supplies scenario and actor information; release-specific README files determine the available fields. It is an external research benchmark, not telemetry collected from a real company. [CMU dataset](https://www.sei.cmu.edu/library/insider-threat-test-dataset/)

The official distribution metadata lists r1 at 87,541,633 bytes, r4.2 at 4,824,287,500 bytes, r6.2 at 23,811,144,737 bytes, and the answer archive at 1,254,678 bytes. These are compressed download sizes. A full r4.2 download must not block the first functional checkpoint. [Official distribution metadata](https://api.figshare.com/v2/articles/12841247)

Data intake order:

1. Inspect organizer-supplied data if available and validate its provenance.

2. Download the official CERT r4.2 archive, answer archive, README and checksum manifest. Preserve the release and integrity evidence.

3. Extract only the required source and metadata first. Inspect file.csv, LDAP validity dates and answer-key structure before mapping fields.

4. Treat r1 only as a schema-verified fallback. It is no longer the default merely because it is smaller.

5. Keep a clearly labeled deterministic development fixture available for pipeline development while benchmark intake proceeds. Fixture results are functional results, not CERT benchmark results.

The intake manifest records source URL, release, checksum, license/readme, files used, selection rule, time range, row counts, missingness, duplicates and label granularity. In r4.2, file.csv records file copies to removable media; it does not observe every file read. A research source documents this distinction, and the acquired release must still be inspected. Missing byte counts, sensitivity labels or tenant identities remain missing. [r4.2 source semantics, Table 1](https://pure.port.ac.uk/ws/portalfiles/portal/21906414/applsci_10_05046.pdf)

LDAP/role metadata is used only after its headers and validity dates are checked. If roles are absent or groups are too small, use personal/global fallback and show limited context. Do not invent job roles.

LANL's 2017 dataset provides anonymized enterprise host and network events over approximately 90 days. It can support an additional telemetry evaluation, but does not supply the document contents and AI prompts needed for this DLP demo. It is optional for this deadline. [LANL dataset](https://csr.lanl.gov/data/2017/)

## Controlled live lab

The lab uses synthetic people, documents and historical activity. Current actions are actually executed:

1. An authenticated lab user opens a synthetic document through the application's document endpoint.

2. That endpoint emits an actual application audit event.

3. The same authenticated subject submits a prompt through the gateway.

4. Local content matching links the prompt to a registered synthetic source where a match exists.

5. The receiver records the payload actually delivered.

This demonstrates a real application-to-gateway path using test data. It does not claim operating-system-wide file monitoring.

The benchmark and lab have separate namespaces, fitted models, calibration values and baselines. The shared code implements the same methodological rules, but a CERT-trained model is never applied directly to generated lab activity. Lab behavior context comes from a completed synthetic user-day; actual document access and transfer events are separately timestamped. No artificial join connects a CERT actor to a live AI request.

# UEBA and machine learning

## Observation unit and features

Use user-day as the first CERT benchmark observation unit. The lab also uses its own completed user-day model, trained and evaluated on a separate synthetic history. The gateway reads the most recent completed snapshot and displays its age and provenance. Current partial-day counts are never passed to a full-day-trained model. Request-level content inspection remains immediate.

Candidate features, enabled only when the source supports them:

- Event count and distinct resource count.

- Previously unseen resource share, using only prior history.

- Distinct device count and new-device context.

- Activity-hour rarity learned from previous activity.

- Personal volume deviation and, where supported, peer deviation.

- Bytes or transfer-specific attributes only when present and semantically valid.

Do not use actor IDs, attack labels or future resource inventories as predictive features.

## Three explicit rules

| Rule | Meaning for r4.2 file.csv | Evidence |
|---|---|---|
| Unusual removable-media copy volume | Copy count exceeds a past personal reference with peer adjustment and a minimum-count condition | Observed copies, personal and peer baseline, user-day and source IDs |
| Atypical-time removable-media copying | Copy activity occurs at historically unusual times with sufficient volume | Prior hourly distribution, unusual-hour count and time boundary |
| New workstation context | Copy activity uses an observed workstation not present in allowed prior history | Workstation field, first-seen context, copy count and history sufficiency |

A workstation identifier is not a USB serial number. File resource breadth may be added only after the source field and semantics are verified.

Sensitive-resource variants require actual sensitivity evidence. Generic benchmark resources are not automatically labeled confidential.

## Model and operational score

Fit a pooled Isolation Forest using supported behavior features and per-user context. This avoids fitting a fragile separate model to every tiny group. Persist model version, training interval, feature list, preprocessing, random seed and baseline version.

Isolation Forest produces an anomaly score. Its contamination parameter affects the fitted decision threshold; it is not a discovered fraction of malicious employees. Use raw score ranking and select the operational threshold on validation data. [Isolation Forest documentation](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)

Show model score, rule reasons and history sufficiency separately. Feature deviations are observed evidence, not a causal explanation of the forest. SHAP remains optional after validation; it is not a checkpoint dependency. A risk score is a prioritization index, not a probability of malicious intent.

For the initial policy, R = max(r1, r2, r3), with each rule strength in [0,1]. Let s be the Isolation Forest anomaly score oriented so larger is more anomalous. Using validation quantiles, A = clip((s − q95)/(q99 − q95), 0, 1), with an explicit degenerate-calibration guard. B = 100 × (0.6R + 0.4A). These weights are declared engineering parameters and are frozen before final testing. Show R, A and B separately.

Hard prohibitions on secrets and restricted content remain effective at every behavior score. For documents explicitly classified controlled_excerpt, the initial unapproved-destination policy requires coverage below 20% distinct eligible fingerprint coverage when B < 70 and below 10% when B ≥ 70. A request is blocked when prospective coverage reaches or exceeds the applicable threshold. These are pilot policy settings, not universal safe disclosure percentages. Behavior context is obtained before evaluating the current request.

# Evaluation protocol

Use chronological train, validation and final-test intervals. Choose dates after inspecting label coverage. Fit reference statistics, resource inventories, peer profiles and preprocessing only from allowed past data. Freeze the final model and threshold before running the final test. [Data leakage guidance](https://scikit-learn.org/stable/common_pitfalls.html)

Use answer-key-supported user-day or episode labels; a malicious actor's entire history is not automatically malicious. Report user-day performance first. For actor recall, require an alert during a true malicious interval, or a separately declared early-warning interval. A false alert on an otherwise normal day does not become a successful malicious-episode detection. Report benign actors flagged and the horizon alongside actor metrics.

For the single-source r4.2 copy benchmark, the primary label is incident-associated copy user-day: an observed copy timestamp overlaps the official actor's incident interval. This is contextual ground truth, not a claim that every copy is malicious. Exact file-event IDs in detailed observables are supplementary evidence because not all scenarios list file IDs. Include all selected incidents overlapping the test horizon in coverage-adjusted actor/episode denominators; separately report no-copy and insufficient-history incidents. Freeze the active-copy-day population and chronological protocol before viewing final results.

Compare:

1. The three baseline rules.

2. Isolation Forest alone.

3. The combined approach.

4. With and without peer context, when valid metadata and sample sizes permit.

Compare rules, Isolation Forest and the weighted combination on the same test population. Select behavior-alert thresholds using validation data and a declared target such as one alert per 100 user-days. Freeze thresholds before the final test; achieved test alert load may differ. Report TP, FP, FN, precision, recall, F1, average precision with its exact definition, alert counts and alerts per 100 observed user-days. Give denominators, positive counts and dates. An alert budget governs the triage queue; it never disables mandatory DLP blocking. [Metric definitions](https://scikit-learn.org/stable/modules/model_evaluation.html)

A validation-only threshold preview is a later convenience. The first build reports fixed validation-selected thresholds and their held-out results. Changing a preview must not retrain the model, alter a published test result or silently update the live disclosure policy.

The gateway functional suite covers public text, restricted markers, cumulative fragments, repeated fragments, concurrent admission, idempotency, Unicode normalization, role filtering, reservation expiry and acknowledgment-loss reconciliation. Report fixture functional checks separately from any CERT benchmark performance.

If ML or peer context does not improve the measured result, report that finding. Its contribution may be ranking rather than enforcement.

# Gateway and cumulative content protection

## Enforcement boundary

The prototype is an explicit application gateway. The client submits plaintext content to its own authenticated API; the server inspects it before forwarding. It does not intercept arbitrary TLS sessions.

The route resolves to a server-configured local receiver. Subject identity comes from the server-side session, never from a request-body subject or risk score. The local competition app has explicitly simulated employee and analyst identities for testing. Production identity assurance requires integration with organizational authentication.

The first build supports ALLOW and BLOCK, with delivery state recorded separately. Redaction and hold are deferred until their complete lifecycle is implemented and tested.

## Content detection

For the bounded registered corpus, index every normalized token 4-gram, retaining candidate positions and source versions. If four consecutive normalized tokens match the same profile in an indexed source, the matcher finds that candidate. This does not guarantee an alert or block: public/boilerplate evidence and content policy remain separate. Count distinct eligible 4-gram fingerprints, not the union of every possible source position. Repeated wording in a source must not multiply the exposure estimate.

The first build recognizes an explicitly nonfunctional SEDRA_SECRET test-marker format in addition to registered document excerpts. Additional real secret formats, validated structured PII and trusted sensitivity labels require separate implementation and tests. Unregistered confidential prose without a supported pattern can remain undetected.

Matching uses versioned NFKC normalization, a pinned Default_Ignorable_Code_Point table, and source-language-aware English or Azerbaijani casing. Azerbaijani I↔ı and İ↔i remain distinct pairs, including decomposed dotted I. Matching normalization does not rewrite the actual outgoing payload. Sub-four-token fragments, paraphrase, translation, arbitrary confusables, Base64/ROT13 and images/OCR are outside this build's guarantee. Do not concatenate unrelated requests to claim a shorter-fragment guarantee. [Unicode normalization](https://www.unicode.org/reports/tr15/) · [Unicode special casing](https://www.unicode.org/Public/15.0.0/ucd/SpecialCasing.txt)

## Cumulative state

State is keyed by server-derived subject, protected document ID and version, destination trust class and a declared 24-hour window. Keep the exact destination as evidence. A new browser session does not reset state. Cross-user collusion is outside the prevention guarantee; a shared-document investigation view would not itself implement collusion prevention.

Prospective coverage is the union of confirmed forwarded, pending/reserved, uncertain-delivery and proposed outgoing eligible fingerprints, divided by the source's distinct eligible fingerprint count. Repeated excerpts do not increase coverage. The percentage measures this fingerprint set, not document bytes or guaranteed semantic reconstruction.

Admission is atomic in SQLite. An idempotency key binds subject, destination and original payload digest. RESERVED expires after 30 seconds only if no send was claimed; the worker durably enters SENDING before network I/O. A stale send or timeout becomes DELIVERY_UNKNOWN and retains possible-exposure budget until trusted reconciliation. TTL does not turn uncertain delivery into proof of non-delivery.

The receiver acknowledges request identity and the digest of the exact payload received. Fault injection can discard an acknowledgment after acceptance, creating DELIVERY_UNKNOWN. Reconciliation queries the receiver and confirms actual delivery. A missing receipt at one instant is not sufficient proof that an in-flight send will never arrive.

Track attempted, confirmed forwarded, reserved, possible unknown and blocked fingerprint sets separately. Keep historical delivery records after the rolling detection window expires. Blocked content can overlap already released content; do not present all blocked bytes or fingerprints as newly prevented leakage.

The UI must acknowledge earlier released fragments when cumulative detection stops a later request.

# Architecture and interface

Build a modular local Python application with scikit-learn, SQLite and buildless HTML/CSS/JavaScript. The first executable scaffold uses Python's development HTTP server to avoid frontend and web-framework installation dependencies; production ingress is a separate deployment task. An independent localhost HTTP receiver provides actual delivery evidence. Package local assets and pin model dependencies.

Shared records:

| Record | Required information |
|---|---|
| Event | Source IDs, timestamps, subject, action, object and provenance |
| Feature snapshot | Completed user-day, reference/model versions, observed features and history sufficiency |
| Decision | Request ID, policy version, behavior context, findings, threshold and reasons |
| Delivery | Original outbound payload digest, actual receiver acknowledgment and confirmed/unknown state |
| Coverage | Subject, document/version, trust class, distinct eligible fingerprints, reservation and window |
| Investigation | Linked behavior snapshot, real application-access timeline, decision and receiver evidence |

Three main screens:

- Overview: risk queue, baseline comparison, model indicator and a compact evaluation area.

- Investigation: completed-day baseline evidence, rule/model findings, actual application timeline, content match, decision and delivery outcome.

- AI Transfer Lab: document browser, prompt submission, cumulative coverage and actual receiver view.

A small evidence graph and analyst case notes are optional additions after the core investigation works. Any graph must distinguish content-confirmed connections from temporal associations and expose supporting evidence.

Employee sessions may submit and inspect only their own requests; analyst sessions see cross-user evidence with content previews masked. Enforce these distinctions in backend responses. The visible identity switch is explicitly a local demo mechanism, not production authentication. Ordinary audit records retain digests, reasons and counts rather than prompt bodies. The isolated synthetic receiver retains the full received synthetic payload until explicit demo reset, for delivery proof.

# Coverage and deployment answers

| Channel | Competition scope | Enforcement |
|---|---|---|
| CERT r4.2 removable-media copy log | Historical ingestion, personal/peer baseline, rules and ML after verified schema intake | Detection only |
| Lab document access | Actual audit events from the app's document endpoint | Application-scoped observation |
| AI gateway | Live text inspection and cumulative analysis using completed behavior context | Actual allow/block on this route |
| Email and web/cloud events | Optional next adapters after the first source works | Historical detection if implemented |
| VPN and privileged activity | Explicit future adapters unless provided and implemented | No current claim |

Production deployment can connect existing SIEM, endpoint or identity telemetry to the event interface. For broad AI-transfer enforcement, organizations must route relevant activity through an approved gateway or integrate supported endpoint/browser/proxy controls. A direct external site visit outside that route remains uncovered. Domain names alone do not prove personal versus corporate account use.

An unmanaged phone on mobile data is outside this prototype's control. Corporate resource access controls and device/egress policy would be separate deployment measures. Do not claim control over personal devices or offline photography.

The gateway's local inspection, decisions, explanations and receiver demo do not require an external LLM.

# Commercial comparison and product claim

| Product | Capability verified in official documentation | Implication |
|---|---|---|
| Forcepoint | Cumulative rules aggregate matches over time as drip DLP; classifiers include fingerprinting | Cumulative detection is not a new category invented by SEDRA |
| Microsoft Purview | Cumulative exfiltration detection and peer groups based on organizational/access context | Cumulative tracking plus peer comparison is not enough to claim uniqueness |
| Netskope | Exact/similar fingerprint matching and GenAI inline controls with behavioral context | Fingerprinting and AI DLP alone are not sufficient differentiation |

Sources: [Forcepoint policy documentation](https://help.forcepoint.com/dlp/10.3.0/dlphelp/FF9308AE-980A-48CD-AC96-3894D08B2859.html), [Purview cumulative detection and peers](https://learn.microsoft.com/en-us/purview/insider-risk-management-policies), [Netskope fingerprinting](https://docs.netskope.com/en/create-fingerprint-rules), [Netskope DLP](https://www.netskope.com/products/data-loss-prevention).

The defensible contribution is the demonstrated integration: reproducible UEBA evaluation, explicit fingerprint accounting across AI requests, a behavior-dependent disclosure policy, actual receiver evidence and one investigation flow. Commercial superiority or unique invention is not established without comparative testing.

Suggested product sentence: SEDRA connects behavioral anomalies to verifiable data-protection decisions and shows exactly what was attempted, released and stopped.

# Acceptance gates and schedule

## First checkpoint

By the 31 October 17:00 checkpoint, require:

- One actual ingested source with provenance and reproducible normalization.

- Baseline with history sufficiency and three working anomaly rules.

- Trained Isolation Forest, persisted metadata and visible scores.

- Chronological initial evaluation, with its actual data type clearly labeled.

- Dashboard links from a finding to supporting records.

- Reproducible results on the same input.

Public-benchmark readiness is a separate explicit status. A development-fixture result cannot be marked as a completed CERT evaluation. Target a basic gateway/receiver path before the checkpoint if the mandatory core is already stable.

## Build sequence

1. Establish the event/API contracts and begin the deterministic fixture pipeline immediately. Download CERT r4.2 and its documentation in parallel.

2. First working integration: trained lab model, three rules, risk panel and a local gateway-to-receiver path. Treat completion as a tested milestone, not an unverified 13:00 promise.

3. Before the 17:00 checkpoint: verify source ingestion/provenance, display actual evaluation status, rehearse the mandatory MVP and keep a deterministic recovery path.

4. After the checkpoint: complete public-benchmark evaluation and reinforce cumulative tracking, context comparison and source traceability.

5. During the evening build: investigation polish, meaningful concurrency/TTL/role tests and five-minute demo rehearsal. Avoid adding new infrastructure.

6. On 1 November before 10:30: fix defects and freeze final evaluation. Add optional features only if all core acceptance checks pass.

7. 10:30 feature freeze; 10:30–12:00 package, rehearse and prepare final artifacts.

8. 12:30 technical verification; submit during 13:00–13:30.

The supplied agenda provides a five-minute presentation/demo and five-minute Q&A. The portable source package uses the local source [hackathon-agenda.pdf](sources/hackathon-agenda.pdf).

## Essential end-to-end checks

1. Public content reaches the receiver.

2. A hard-prohibited test secret is blocked even at low behavioral risk.

3. Normal bulk work and unusual bulk work receive justified, distinct behavioral findings.

4. Judge-selected fragments satisfy the declared four-token candidate contract; the interface shows the supported minimum and exact coverage unit.

5. Repeated fingerprints and idempotent retries do not inflate unique exposure.

6. Concurrent requests do not bypass prospective cumulative limits.

7. A lost acknowledgment retains possible disclosure and can be reconciled with the receiver; an unused expired reservation cannot be sent.

8. Missing role/history fields produce limited-context output.

9. Employee cannot access another employee's request; analyst receives masked evidence.

10. Identical content and destination are tested under two completed behavior contexts; high behavior priority lowers the cumulative limit while hard rules remain unchanged.

11. Startup and reset are repeatable with local assets.

12. Benchmark and live-lab sources remain visibly distinct.

Parallel work streams: data/model/evaluation; gateway/content/state; frontend/investigation/packaging. Agree the event and API contracts before splitting the work.

# Presentation and jury answers

## Five-minute sequence

| Time | Demonstration |
|---|---|
| 0:00–0:30 | Problem and SEDRA's value |
| 0:30–1:15 | User-day baseline, three rules and visible ML evidence |
| 1:15–2:15 | Repeated fragments accumulate; a later request is blocked; receiver proves the outcome |
| 2:15–3:00 | Identical excerpt, different behavior context, different declared threshold |
| 3:00–3:40 | Investigation connects behavior snapshot, document access, match and delivery |
| 3:40–4:30 | Actual benchmark or explicitly labeled fixture metrics, denominators and alert load |
| 4:30–5:00 | Deployment path and value; detailed limits remain in Q&A/backup material |

The signature interaction lets a judge choose excerpt boundaries in a registered synthetic document, with the four-token candidate limit stated. Repeated excerpts demonstrate deduplication. A reset and a labeled recorded fallback support recovery. The core demonstration runs locally without an external LLM.

## Prepared answers

**Where is ML?** Separate fitted Isolation Forest models belong to the CERT and lab data lanes. The lab displays a completed user-day model snapshot; chronological evaluation compares rules, ML and the declared weighted combination.

**Is CERT real company telemetry?** No. It is a public synthetic research benchmark. The live lab uses synthetic content with actually executed application and gateway actions. These are reported separately.

**How is traffic captured?** Clients explicitly use the authenticated gateway. The prototype controls that route; arbitrary encrypted browser traffic is not intercepted.

**Can a phone or direct AI website bypass it?** Yes, when that route is outside the deployment. Broad coverage requires organization-specific endpoint, browser or egress enforcement.

**What about unknown confidential documents?** The initial executable recognizes the synthetic test-secret format and registered text. General confidential prose, new secret formats and semantic transformations require additional detectors and validation.

**Is cumulative detection unique?** No. Commercial products document cumulative detection. Our contribution is the demonstrated, inspectable implementation and measured integration, not an unsupported world-first claim.

**Did earlier fragments leave?** The receiver and unique-forwarded coverage show exactly that. Later blocking does not undo previous release.

**Does a high score prove malicious intent?** No. It is an evidence-based prioritization score. In the declared controlled-excerpt policy it also lowers the allowed cumulative fingerprint coverage. Hard content prohibitions apply at every score.

**How do you know peers reduce false positives?** We compare results with and without peer context. The benefit is a hypothesis until measured.

**What about 99% accuracy elsewhere?** Compare label units, class balance, chronological splits, thresholds and alert workload before comparing percentages. This project reports its own executed metrics. The review's exact 2026 IF metric bundle is not used without a matching primary source.

## Handoff artifacts

Deliver source code, pinned dependencies, local startup/reset commands, source and model metadata, evaluation scripts/reports, synthetic fixtures, matching/state contract, coverage description, demo guide and AI_ASSISTANCE.md. Every teammate must be able to explain the contribution they present. The supplied rules permit AI and require understanding/responsibility; external assistance is disclosed when requested and recorded proactively in the handoff.

# Primary references and task sources

- Hackathon topic: [topic-6.pdf](sources/topic-6.pdf)

- Invitation and rules: [hackathon-rules.txt](sources/hackathon-rules.txt)

- Agenda: [hackathon-agenda.pdf](sources/hackathon-agenda.pdf)

- [CMU CERT dataset](https://www.sei.cmu.edu/library/insider-threat-test-dataset/)

- [CMU distribution metadata](https://api.figshare.com/v2/articles/12841247)

- [LANL Unified Host and Network Dataset](https://csr.lanl.gov/data/2017/)

- [Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)

- [Model evaluation](https://scikit-learn.org/stable/modules/model_evaluation.html)

- [Avoiding data leakage](https://scikit-learn.org/stable/common_pitfalls.html)

- [Forcepoint policy semantics](https://help.forcepoint.com/dlp/10.3.0/dlphelp/FF9308AE-980A-48CD-AC96-3894D08B2859.html)

- [Microsoft Purview policies](https://learn.microsoft.com/en-us/purview/insider-risk-management-policies)

- [Netskope fingerprint rules](https://docs.netskope.com/en/create-fingerprint-rules)

- [Netskope DLP](https://www.netskope.com/products/data-loss-prevention)

## Additional source checks

A 2021 study reports 966 malicious and 329,486 normal daily instances for its r4.2 representation. Those counts are preprocessing-dependent and are not assumed to equal this project's selected population. The review's precise 2026 Isolation Forest metric bundle remains unverified and is not used as a project result. [Study, Table 3](https://onlinelibrary.wiley.com/doi/10.1155/2021/1777536)

The original winnowing paper explains the sampling tradeoff and guaranteed threshold. The prototype avoids that additional threshold by indexing all four-token grams in its bounded corpus. [Original paper](https://sschleimer.warwick.ac.uk/Maths/winnowing.pdf)

