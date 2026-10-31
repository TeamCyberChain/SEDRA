# V2 matching, policy and delivery contract

This replaces the retained v1 contract under `docs/history/`. All live demonstration data is fictional.

## Representations and evidence

Python 3.12 / Unicode 15.0 is required. The base profile `sedra-nfkc-dicp15-az-en-v1` applies NFKC, the pinned 4,174 default-ignorable set and explicit EN/AZ case folding. AZ I/ı and İ/i remain distinct. Original bytes are never replaced by normalized text in outbound delivery.

Matcher profile: `4grams-plus-anchored-distinctive-tokens-tr39-v2`. A secondary [Unicode TR39 skeleton](https://www.unicode.org/reports/tr39/) uses the attributed official `confusables-15.0.0.txt`. It supplies content evidence, never identity equivalence. Mixed Latin/Cyrillic/Greek tokens are flagged, not independently blocked. AZ dotless-I is retained.

Inputs are at most 65,536 UTF-8 bytes and the corpus at most 100,000 tokens. Invalid Unicode scalars fail. Sources bind ID, version, classification, language and SHA-256. Existing source/4-gram manifests cannot change without a version change. Start a fresh v2 ledger when migrating: historic v1 sends do not retroactively acquire token evidence.

**4-gram coverage:** distinct eligible normalized consecutive source four-token tuples / distinct eligible source 4-grams. Exact tuple equality verifies lookup. TR39 matches resolve to original source tuple identities, preventing double counting. Registered public-source tuples are excluded.

**Anchored-token coverage:** distinct eligible source-token fingerprints / eligible distinct source-token vocabulary. Vocabulary tokens have length ≥4, exclude the fixed English stop list and public-reference tokens, and occur in one protected source (up to two for restricted vocabulary). A consecutive source pair needs at least one eligible token for controlled content or two for restricted content. Alternatively, three distinct eligible source tokens co-occur in a bounded 40-token span. These bounded heuristics support insertion/reordering evidence.

Requests are never blindly concatenated into invented source sentences. Supported evidence aggregates by subject, source/version and destination trust class. Repeated evidence does not increase unique exposure. Independent subjects remain separate.

Neither ratio measures source bytes reconstructed, semantic similarity or malicious intent. Public-reference exclusion is an explicit small corpus, not universal public-language knowledge. Source-specific heuristics still need pilot false-positive validation.

## Structured findings and encoding

Hard-block findings cover the known synthetic marker, including supported spacing/width/invisible changes; 20-character AKIA/ASIA AWS access IDs; supported matching private PEM envelopes with ≥64 body characters; contextual 13–19-digit nontrivial Luhn-valid cards; 28-character AZ IBANs with MOD97; explicit labeled FIN values; and conservative long credential assignments with alphabetic/numeric diversity. A structure/checksum is not proof that a value is active or authentic. Public-key envelopes and unlabelled numeric identifiers do not automatically block.

Findings expose type, representation, confidence label and value SHA-256, never the matched value. Base64 processing accepts at most eight canonical candidates and 8 KiB total decoded text, strict UTF-8, ≥95% printable/whitespace, and one decoding level. An encoding alone never blocks: independent protected evidence must match. Binary, nested encoding and encryption remain outside scope.

## Policy

Profile: `sedra-dual-window-anchored-token-restricted-v2`.

Any confirmed restricted-source evidence or structured finding is an unconditional BLOCK, including zero behavior and the core's approved route. The HTTP lab exposes only its fixed public_ai receiver.

Controlled excerpts on unapproved routes block when **either** evidence unit reaches its corresponding limit:

| Effective context | 24h 4-grams | 24h tokens | 30d 4-grams | 30d tokens |
| --- | ---: | ---: | ---: | ---: |
| Behavior <70 | 20% | 25% | 35% | 40% |
| Behavior ≥70 | 10% | 12% | 20% | 25% |

Prospective exposure unions confirmed, reserved/in-flight, uncertain and incoming evidence. Blocked attempts are visible but do not reserve delivered exposure. Confirmed evidence ages out of each finite window; unknown delivery stays conservatively counted beyond both windows until reconciliation.

`prospective_coverage` stays the 4-gram ratio. `token_prospective_coverage` is separate. Long-window metrics are recorded individually. The UI's long-window maximum is the larger ratio, not a third normalized unit. Per-unit limits are displayed.

## Server-derived behavior

Completed-day ML stays dated. A separate live rule derives 80 after six actual protected-document reads in 120 seconds, or 85 after three blocked attempts. Effective context is the maximum of the daily and live scores. These are small demonstration thresholds, not production estimates of intent.

Clients cannot provide a subject, score or arbitrary destination URL. First evaluation freezes context and thresholds. Later behavior never rewrites old evidence or silently changes a retry decision.

## Durable admission and transport

SQLite BEGIN IMMEDIATE serializes evaluation and exposure reservation. ALLOW enters RESERVED before I/O. Exactly one worker claims SENDING. The app sends original text and validates the receipt's subject, request ID, original SHA-256 and UTF-8 byte count.

| State | Meaning |
| --- | --- |
| RESERVED | Unused allowed lease, 30-second TTL |
| SENDING | Durable send claim exists |
| EXPIRED_UNUSED | Unclaimed lease expired; late claim forbidden |
| FORWARDED_CONFIRMED | Validated receiver acknowledgment |
| DELIVERY_UNKNOWN | Possible exposure, conservatively counted |
| NOT_SENT_CONFIRMED | Trusted non-delivery released uncertain exposure |
| BLOCKED | Send claim forbidden |

Stale SENDING becomes DELIVERY_UNKNOWN after 30 seconds. Missing receipt alone never proves non-delivery. HTTP reconciliation validates an existing receipt and never retransmits. The core's trusted negative-reconciliation API is not an untrusted HTTP boolean. Confirmed delivery cannot become confirmed non-delivery.

Idempotency binds subject, request ID, original hash and destination. Identical replay returns existing state; changed body/destination fails. The UI retains its pending key after transport failure for unchanged input. The receiver independently enforces payload identity.

## Authorization, privacy and reset

Loopback binding, Host/Origin checks, HttpOnly/SameSite=Strict port-scoped cookies, CSRF and server-side employee scopes remain enforced. Analyst alone resets; selectable local roles are simulated authentication, not enterprise SSO. The separate receiver listener/database requires a private token and runs on another thread in the same process. Receipts prove local delivery, not an external provider call.

Gateway SQLite stores hashes/evidence, not raw prompts. Fingerprints are not anonymous. The receiver retains full synthetic payloads until reset and masks analyst previews. Reset guards active transfers/reconciliation and preserves source registration. SQLite contexts explicitly close on Windows.

No semantic/OCR/image, arbitrary encoding chain, bypass-traffic, cross-identity or lifetime protection guarantee. Local benign controls are regression evidence only. Enterprise deployment needs independent review and measured population behavior.
