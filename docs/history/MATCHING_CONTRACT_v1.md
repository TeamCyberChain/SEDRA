# SEDRA matching and gateway contract

This document describes implemented prototype behavior, not a claim of complete
enterprise DLP coverage. All demonstration documents must be synthetic or public.

## Inputs, versions and exact candidate guarantee

The Python 3.12 implementation uses Unicode 15.0.0. It refuses to initialize the
matcher under a different Unicode database version. Its normalization profile is
`sedra-nfkc-dicp15-az-en-v1`; its matcher profile is
`all-token-4grams-distinct-public-exclusion-v1`.

Every consecutive **four-token** tuple in every registered source is indexed.
Index lookup compares the complete token tuple, not only a hash. If a request
contains four consecutive normalized tokens occurring consecutively in a source
under that source's profile, the matcher returns a candidate. Three-token matches
are below this contract. A candidate is not a universal alert or block guarantee.

No winnowing or sampling is used. At this small corpus size, retaining all tuples
gives a simpler minimum-fragment guarantee. Winnowing's original guarantee has a
separate window parameter and minimum detected length, described by Schleimer,
Wilkerson and Aiken: https://sschleimer.warwick.ac.uk/Maths/winnowing.pdf .

Input is bounded to 65,536 UTF-8 bytes per text and 100,000 corpus tokens. Invalid
Unicode scalar values are rejected. Corpus sources have `id`, `title`, `text`,
`language` (`en` or `az`), `classification` (`public`, `controlled_excerpt` or
`restricted`) and `version`. A changed registered source or matching denominator
requires a new version. The raw source hash identifies the registered document.

## Normalization and tokenization

1. Apply Unicode NFKC.
2. Remove the explicitly pinned Unicode 15.0 `Default_Ignorable_Code_Point` set
   from the matching representation; record their presence as a reason flag.
3. Normalize again.
4. Apply English/default full case folding or the Azerbaijani I rules, followed
   by full case folding for other characters.
5. Normalize again. Tokenize maximal runs of Unicode letters/numbers and their
   combining marks; punctuation and whitespace delimit tokens.

The Azerbaijani pairs remain `I`/`ı` and `İ`/`i`. They are not all collapsed into
one character. The implementation handles canonically decomposed dotted I and
intervening combining marks using the relevant Unicode casing contexts.

The 4,174 default-ignorable code points are taken from Unicode 15.0
DerivedCoreProperties. The set is **not** equivalent to general category `Cf`.
Matching removes these characters only in its internal representation. **The
gateway caller must forward the original, unchanged request body.** The ledger
records its original UTF-8 SHA256 and byte length, not a normalized replacement.

This profile is not general semantic matching. It does not claim to equate all
visual confusables, transliterations, paraphrases, screenshots, OCR output,
encrypted archives or arbitrary encodings. Unicode normalization and confusable
detection are distinct mechanisms.

Primary references:

- Unicode normalization: https://www.unicode.org/reports/tr15/
- Unicode 15.0 properties:
  https://www.unicode.org/Public/15.0.0/ucd/DerivedCoreProperties.txt
- Unicode casing:
  https://www.unicode.org/Public/15.0.0/ucd/SpecialCasing.txt
- Unicode case folding:
  https://www.unicode.org/Public/15.0.0/ucd/CaseFolding.txt
- Unicode security mechanisms: https://www.unicode.org/reports/tr39/
- Python Unicode API: https://docs.python.org/3/library/unicodedata.html

Unicode data copyright Unicode, Inc. Data terms and license:
https://www.unicode.org/license.txt . The ranges in `mosaic.py` are attributed to
the Unicode 15.0 data, with adjacent ranges merged without adding code points.

## Candidates, public phrases and confirmed evidence

All candidates remain visible as counts. A tuple also found in a registered
public source under the same language profile is excluded from protected evidence
and the protected-source denominator. Public sources are a small explicit
reference corpus, **not proof that all common language has been identified**.

In this prototype, a confirmed match is an exact tuple match that remains eligible
after public-reference exclusion. This means confirmed textual matching, not a
confirmed malicious user or universal proof of secrecy. The minimum confirming
unit can be one eligible four-token tuple; the sensitivity/false-positive tradeoff
must be measured and is not concealed behind a stronger claim.

Repeated source text does not inflate coverage: tuples are distinct by content.
Source positions are candidate evidence, and several positions can correspond to
one tuple. They are not all added as separate disclosed spans.

## Exactly what coverage means

Coverage is a ratio from 0 to 1:

`distinct eligible normalized source 4-grams in the set / distinct eligible
normalized 4-grams in that source version`.

It is **not** source-byte reconstruction percentage or a probability of
malicious intent. Sets track attempted, confirmed forwarded, reserved/in-flight,
unknown-delivery and blocked matches. Repeating an excerpt cannot increase the
unique count. A blocked payload can overlap information already forwarded;
blocked coverage must not be advertised as entirely newly prevented leakage.

`prospective_coverage` is the frozen admission-time union of confirmed forwarded,
reserved/in-flight, unknown-delivery and current-request evidence. Other coverage
fields on returned records are the current active-window metrics. The nested
`evaluation_coverage` preserves admission-time evidence.

## Policy

Profile: `sedra-controlled20-high10-restricted-v1`.

- For `controlled_excerpt` data on unapproved routes, deny when prospective
  coverage is **greater than or equal to 0.20**.
- If the supplied server-derived behavior score is at least 70/100, the threshold
  tightens to **0.10**. Behavior is frozen on the first evaluation of a request ID.
- Any eligible confirmed `restricted` source match is denied, even at a low
  behavior score and even on the demonstration approved route.
- A `SEDRA_SECRET_[A-Z0-9]{16,}` demo secret is independently denied. Its check uses
  the normalized representation so supported invisible/width changes do not
  remove that rule. Never use real credentials in the demo.
- The exact destination name `approved_ai` is the prototype's configured approved
  trust class. Other destination names share `unapproved_ai`. This is a local
  policy label, not evidence of a real service's enterprise account/tenant.
- Controlled excerpts on the approved route do not use the unapproved cumulative
  limit. No production external service is provisioned by this module.

The cumulative state is scoped to authenticated subject, source ID/version and
destination trust class, across sessions and devices attributed to that subject.
It uses a 24-hour rolling window. Cross-user collusion is not aggregated.
Unknown delivery remains conservatively budgeted beyond that window until
reconciled. Confirmed historical deliveries remain in the ledger even when they
age out of active-window coverage.

Different short prompts are **never blindly concatenated**. Splitting data into
sub-four-token fragments, inserting changes within every possible four-token
sequence or routing outside this gateway remains outside the matching guarantee.

## Durable admission and network boundary

`Gateway.evaluate(...)` uses `BEGIN IMMEDIATE` in SQLite so admission and the
reservation occur atomically. Two concurrent requests cannot both evaluate the
same old exposure budget. Allowed requests enter `RESERVED`; blocked requests
enter `BLOCKED`.

The caller must then:

1. Call `claim_send(subject_id=..., request_id=...)`. It durably records `SENDING`
   before network I/O. Only one caller can claim a reservation.
2. Send the unchanged body to the independent receiver and validate the receiver's
   acknowledgment against the recorded request/body identity.
3. Call `confirm_forwarded(...)` for an acknowledged transfer, or `mark_unknown(...)`
   when the network outcome is uncertain.

The matcher/gateway core performs **no** network I/O. Authentication, endpoint
permissions, receiver validation and transport behavior belong to the HTTP app.

### States and expiry

- `RESERVED`: admitted but no durable send claim; its unused lease expires after
  30 seconds to `EXPIRED_UNUSED`.
- `SENDING`: a send was claimed. After 30 seconds without a result it recovers to
  `DELIVERY_UNKNOWN`, never to unused budget.
- `FORWARDED_CONFIRMED`: the caller reports a validated receiver acknowledgment.
- `DELIVERY_UNKNOWN`: possible exposure remains reserved conservatively.
- `NOT_SENT_CONFIRMED`: trusted reconciliation established non-delivery.
- `BLOCKED`: no send claim is permitted.

`reconcile(..., delivered=True/False)` requires a trusted receiver result. A
missing or timed-out acknowledgment alone is **not** evidence of non-delivery.
Confirmed delivery cannot later be changed to non-delivery by this API. Expiry
does not erase sent history or unknown exposure.

Idempotency binds the subject, request ID, original UTF-8 body hash and destination.
Same-key/same-body retry returns the existing decision/state; changed body or
destination is rejected. The server-derived behavior context is not part of the
key and does not silently change an existing request's decision. Retrying a
`SENDING` or unknown request must not trigger another uncontrolled send.

## Privacy and reset

The core stores body hashes, counts, source positions, opaque tuple fingerprints,
policy results and state transitions. It does not store raw prompts or source text
in SQLite. Fingerprints are not claimed to be anonymous or irreversible. The
registered source text resides in process memory for matching and must remain a
protected input in any real deployment.

`reset_demo()` explicitly clears only gateway request/transition rows and preserves
the corpus manifest. The HTTP app must authorize this demo operation and prevent
it while transfers are active. This is a deliberate synthetic-demo reset, not a
normal expiry/reconciliation operation or a production evidence-deletion policy.

## Verification

Run `python -m unittest discover -s tests -p 'test_gateway.py' -v` from the project
root. Tests cover the candidate minimum, public-reference suppression, duplicate
source/request handling, Unicode/profile limits, concurrency, idempotency, unused
expiry, unknown outcomes, reconciliation, persistence, unchanged body hashing,
subminimum fragmentation and the explicit cross-user limitation.
