# Data and dependency attribution

## CERT Insider Threat Test Dataset

Brian Lindauer, **Insider Threat Test Dataset**, Carnegie Mellon University KiltHub, published 30 September 2020. DOI: [10.1184/R1/12841247.v1](https://doi.org/10.1184/R1/12841247.v1).

The retrieved official distribution metadata declares **CC BY 4.0**: <https://creativecommons.org/licenses/by/4.0/>. The unmodified metadata and release README are preserved in `artifacts/data_provenance/` when acquisition completes. This project derives user-day counts, context features and evaluation reports from r4.2; those derived records are not original raw telemetry. CERT itself is a published synthetic research dataset. The full raw archive is downloaded separately and is not bundled with this source package.

Archive integrity: `r4.2.tar.bz2`, 4,824,287,500 bytes, SHA-256 `586446b00e83ce5cdabf9dc889b0b6e7a9f44556cee3c03d39445d790122556c`.

## Unicode

The matching profile uses Unicode 15.0 normalization through Python 3.12 and a documented table of `Default_Ignorable_Code_Point` ranges from the Unicode Character Database. Copyright Unicode, Inc. Unicode data license and attribution terms: <https://www.unicode.org/license.txt>. Source definitions: <https://www.unicode.org/Public/15.0.0/ucd/DerivedCoreProperties.txt> and <https://www.unicode.org/Public/15.0.0/ucd/SpecialCasing.txt>.

## Software dependencies

V2 also bundles the official Unicode TR39 15.0 confusables table under `sedra/unicode/`, with Unicode's LICENSE.txt. Source: <https://www.unicode.org/Public/security/15.0.0/confusables.txt>. It is used as a secondary content-matching skeleton, not a claim of complete TR39 conformance or an identity canonicalizer.

The small source package installs pinned dependencies. An optional separate offline package includes unmodified Windows CPython 3.12 wheels with their bundled licenses. Their projects and license files remain authoritative:

- NumPy: <https://numpy.org/>
- scikit-learn: <https://scikit-learn.org/>
- Python: <https://www.python.org/>
- SciPy: <https://scipy.org/>
- joblib: <https://joblib.readthedocs.io/>
- threadpoolctl: <https://github.com/joblib/threadpoolctl>

## Competition documents

The topic and agenda are copies of documents supplied by the team. The invitation/rules are a portable text transcription with the recipient address omitted. They document the competition requirements; their inclusion does not imply organizer endorsement of this project.

## Project assistance

See `AI_ASSISTANCE.md` for the AI contribution and the team's verification responsibilities.
# Local inference supplement

The optional local AI supplement contains official llama.cpp CPU runtime build b12020 (MIT license) and official Qwen2.5-1.5B-Instruct Q4_K_M GGUF weights (Apache License 2.0). Their license texts accompany the supplement as data/local_ai/llama-LICENSE.txt and Qwen-LICENSE.txt. Sources and pinned source/per-file hashes are recorded in artifacts/local_ai_source_manifest.json; setup and scope are described in docs/LOCAL_AI.md. Neither the runtime nor model is claimed as original team work. No OpenAI API key or generated local service token is included in the supplement.

