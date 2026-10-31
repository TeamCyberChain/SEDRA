# SEDRA 0.8 review snapshot

Download [SEDRA-0.8-Review-Source.zip](SEDRA-0.8-Review-Source.zip) and extract it to an empty folder. It contains the complete 201-file reviewed source tree, tests, current technical report, requirements mapping, attribution and executed evidence. No private runtime databases, API keys, model binary, raw CERT archive or Windows case packet is included.

The archive is the exact local Git snapshot `782fb7b` (31 October 2026). The full local suite passed 184 tests. GitHub Actions is configured in the archive but remote CI is not claimed to have run for an archive-only upload.

Inside the extracted folder start with `README.md` and `docs/REVIEWER_GUIDE.md`. Use Python 3.12, install `requirements.txt`, run `scripts/verify.py`, then `python -m sadd.app --port 8765 --data-dir data/runtime-v2`. The local receiver demo needs no AI key. Optional local model setup is documented separately.

This is a private development review checkpoint. Existing presentation/Q&A material is retained from an earlier build; its update is deferred. CERT file-only v1 remains 0 TP / 476 positive user-days; multichannel v2 remains unmeasured.
