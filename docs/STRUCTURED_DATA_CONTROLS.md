# SEDRA 0.4 — structured sensitive-data controls

These controls inspect outgoing text independently of the four registered demonstration documents. They are deterministic rules, not an LLM verdict. Recognized protected identifiers and credentials hard-block before either the independent receiver or an AI provider is contacted. A low behavior score does not override the block.

## Supported controls

| Type | Required evidence | Handling |
| --- | --- | --- |
| Azerbaijan FİN | Explicit AZ/EN label, JSON key or delimited column; supported seven-character alphabet/format | Block |
| Azerbaijan IBAN | AZ country structure, 28 characters, four-letter bank field, twenty alphanumeric account characters and MOD97 | Block |
| International IBAN | One of 89 pinned country formats, its exact length/structure and MOD97 | Block |
| Payment card | Explicit payment context/field, 13–19 digits and Luhn | Block |
| Labeled credential | Explicit supported credential key/assignment and bounded 8–256-character value shape | Block |
| AWS access key ID | AKIA/ASIA access-ID format, including supported separators | Block |
| Private key envelope | Supported private PEM header/footer and bounded body | Block |
| Authorization bearer | Explicit Authorization: Bearer field and bounded token shape | Block |
| Synthetic secret | SADD_SECRET / SEDRA_SECRET laboratory marker | Block |

FİN without context is deliberately not treated as proof of personal data: a seven-character order code or ordinary word can have the same shape. The supported FİN profile retains the conservative existing alphabet excluding I/O. It does not verify that a code was issued. General names, addresses, phone numbers, emails and arbitrary unlabeled passwords are not claimed as covered by these rules.

## Representations

Inspection supports NFKC/fullwidth forms, the pinned Unicode 15 default-ignorable set, decimal digits mapped to ASCII, selected single-character Greek/Cyrillic TR39 look-alikes, supported spaces/dashes/dots, JSON fields and escaped JSON strings, and consistent CSV/semicolon/TSV/pipe tables. Raw assignment rules cover the declared field labels. Structured field context does not cross CSV columns; neighboring cells and separate requests are never concatenated into a FİN.

ASCII O/0 and I/1 are not guessed or corrected. Arbitrary spelling changes, reordered identifier characters, arbitrary separator insertion, OCR, images, encrypted content and arbitrary encoding chains remain outside the guarantee. The existing registered-fragment mechanism continues separately for supported reordered source tokens.

Base64 remains canonical UTF-8, one decode, at most eight candidates and 8 KiB decoded in total. JSON depth is explicitly limited to 64; an overflow returns STRUCTURED_INSPECTION_LIMIT and blocks because inspection could not complete. Quoted brackets inside a JSON string do not count as nesting. Input is bounded to 65,536 UTF-8 bytes; the AI portal has its tighter existing 4,096-byte limit. Evidence is capped at 64 distinct type/value findings; omitted additional evidence is marked, and a hard block already applies.

Normalization is for inspection only. The original message hash/byte count and original outbound payload are preserved. A finding exposes its type, category, validation checks, representations, Unicode normalization steps and canonical value SHA-256. It never includes the detected value. SHA-256 masking is not a claim of anonymization or encryption for low-entropy identifiers.

## Use it

Open http://127.0.0.1:8765/#inventory and expand **Sensitive data controls**. Select a synthetic example and click **Load in Transfer Control**. Select lab-001 if needed and click **Evaluate & send**. Loading an example alone does not submit anything.

The AI Workspace at /portal also includes **FİN · JSON** and **IBAN · grouped** buttons. Submit an example to observe a real BLOCK and no provider contact. The public workshop question can still reach the installed local model. All examples are for isolated demonstration; there is no bank or identity-registry query.

## Sources and provenance

- [SWIFT IBAN Registry, release 103, September 2026](https://www.swift.com/swift-resource/9606/download): the 89 country structures, lengths and public registry examples are pinned in sadd/iban_formats.json. This is a local snapshot, not an automatic registry update service. Bank assignment, account existence, ownership and national account-specific checks beyond the declared structure/MOD97 are not verified.
- [Azerbaijan FİN definition, Cabinet of Ministers decision 49](https://frameworks.e-qanun.az/21/c_f_21469.html): the official definition describes a seven-character letter/digit identifier. The implementation's supported alphabet/context constraints are stated above; it does not connect to the population register.
- [Unicode 15 TR39 confusables](https://www.unicode.org/Public/security/15.0.0/confusables.txt): the previously bundled table is reused for the limited script-look-alike view, with its existing notices.

## Reproduce the checks

Run `.venv\Scripts\python.exe scripts/verify.py`. The executed suite contains 118 tests, including parser boundaries, positive/negative controls, all 89 registry examples, corrupted checksums, wrong country structures, resource limits, original hashes and existing authorization/concurrency/delivery regressions.

Run `scripts/audit_structured.py` with the same Python to execute the frozen previous detector and current detector on identical synthetic inputs. The saved regression records expected-type detections of 7/43 before and 43/43 after; one negative-control flag before and zero among 20 controls after. These are finite regression results, not population precision/recall estimates. The earlier before-fix probe artifact is preserved separately.

Run `scripts/smoke_structured.py` for actual loopback HTTP delivery/block controls and local model inference, and `scripts/smoke_sedra.py` for label revisions, idempotence and reconciliation. Both use temporary ledgers instead of resetting the main app. Current outcomes are in their saved artifacts; no functional pass establishes CERT efficacy. Historical v1 remains a failed 0-TP configuration and v2 remains unmeasured.
