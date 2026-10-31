"""Bounded exact-fragment matching for the SEDRA prototype.

No content leaves this module and normalized text is never an outbound payload.
See docs/MATCHING_CONTRACT.md for the deliberately limited guarantee.
"""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
import json
import re
import unicodedata
from .content_security import skeleton, mixed_script_tokens, text_views, structured_findings


UNICODE_VERSION = "15.0.0"
NORMALIZATION_PROFILE = "sedra-nfkc-dicp15-az-en-v1"
MATCHING_PROFILE = "4grams-plus-anchored-distinctive-tokens-tr39-v2"
K = 4
MAX_TEXT_BYTES = 65_536
MAX_CORPUS_TOKENS = 100_000

# Unicode 15.0 DerivedCoreProperties.txt, Default_Ignorable_Code_Point.
# Adjacent ranges are merged without adding code points (4,174 in total).
# Source: https://www.unicode.org/Public/15.0.0/ucd/DerivedCoreProperties.txt
# Copyright Unicode, Inc.; Unicode data terms: https://www.unicode.org/license.txt
from .unicode_profile import DEFAULT_IGNORABLE_RANGES, IGNORABLES as _IGNORABLES
_DEMO_SECRET = re.compile(r"SEDRA_SECRET_[A-Z0-9]{16,}")


def validate_text(text: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    try:
        raw = text.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError("text must contain valid Unicode scalar values") from exc
    if len(raw) > MAX_TEXT_BYTES:
        raise ValueError(f"text exceeds the {MAX_TEXT_BYTES}-byte prototype limit")
    return raw


def _az_casefold(text: str) -> str:
    """Handle Azeri I/İ and canonical dotted-I equivalents, then full folding.

    Work in NFD so the Unicode Before_Dot / After_I contexts remain visible.
    Other characters use Python's full, locale-independent case folding.
    """
    chars = list(unicodedata.normalize("NFD", text))
    out = []
    for i, ch in enumerate(chars):
        if ch == "I":
            before_dot = False
            j = i + 1
            while j < len(chars):
                following = chars[j]
                if following == "\u0307":
                    before_dot = True
                    break
                if unicodedata.combining(following) in (0, 230):
                    break
                j += 1
            out.append("i" if before_dot else "ı")
        elif ch == "\u0307":
            after_i = False
            j = i - 1
            while j >= 0:
                preceding = chars[j]
                if preceding == "I":
                    after_i = True
                    break
                if unicodedata.combining(preceding) in (0, 230):
                    break
                j -= 1
            if not after_i:
                out.append(ch.casefold())
        else:
            out.append(ch.casefold())
    return "".join(out)


def normalize_text(text: str, language: str = "en") -> str:
    """Return a matching representation; do not use it as the sent message."""
    if language not in ("en", "az"):
        raise ValueError("supported matching languages are en and az")
    validate_text(text)
    value = unicodedata.normalize("NFKC", text)
    value = "".join(ch for ch in value if ord(ch) not in _IGNORABLES)
    value = unicodedata.normalize("NFKC", value)
    value = _az_casefold(value) if language == "az" else value.casefold()
    return unicodedata.normalize("NFKC", value)


def tokenize(text: str, language: str = "en") -> tuple[str, ...]:
    """Maximal runs of Unicode letters/numbers and their combining marks."""
    value = normalize_text(text, language)
    tokens, current = [], []
    for ch in value:
        kind = unicodedata.category(ch)[0]
        if kind in ("L", "N") or (kind == "M" and current):
            current.append(ch)
        else:
            if current:
                tokens.append("".join(current))
                current = []
    if current:
        tokens.append("".join(current))
    return tuple(tokens)


def grams(tokens: tuple[str, ...]) -> list[tuple[str, ...]]:
    return [tokens[i:i + K] for i in range(max(0, len(tokens) - K + 1))]


def fingerprint(value: tuple[str, ...], language: str) -> str:
    # Lookup uses the full tuple, not this digest. The digest is a stable opaque
    # ledger identifier; it is not described as anonymous or irreversible.
    data = json.dumps([NORMALIZATION_PROFILE, language, value], ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
    return sha256(data).hexdigest()


class FragmentMatcher:
    def __init__(self, documents: list[dict]):
        if unicodedata.unidata_version != UNICODE_VERSION:
            raise RuntimeError(
                f"This profile requires Unicode {UNICODE_VERSION}; runtime uses "
                f"{unicodedata.unidata_version}. Use the pinned Python 3.12 runtime."
            )
        self.documents: dict[str, dict] = {}
        self._index: dict[str, dict[tuple[str, ...], list[tuple[str, int]]]] = {
            "en": defaultdict(list), "az": defaultdict(list)
        }
        self._eligible: dict[str, set[tuple[str, ...]]] = {}
        source_tokens: dict[str, tuple[str, ...]] = {}
        total_tokens = 0
        for supplied in documents:
            doc = dict(supplied)
            for field in ("id", "title", "text", "language", "classification", "version"):
                if field not in doc:
                    raise ValueError(f"document missing {field}")
            if not isinstance(doc["id"], str) or not doc["id"] or "\x00" in doc["id"]:
                raise ValueError("document id must be nonempty text without NUL")
            doc["version"] = str(doc["version"])
            if not doc["version"] or "\x00" in doc["version"]:
                raise ValueError("document version must be nonempty text without NUL")
            if doc["classification"] not in ("public", "controlled_excerpt", "restricted"):
                raise ValueError("unsupported document classification")
            if doc["id"] in self.documents:
                raise ValueError("duplicate document id")
            tok = tokenize(doc["text"], doc["language"])
            total_tokens += len(tok)
            if total_tokens > MAX_CORPUS_TOKENS:
                raise ValueError("corpus exceeds prototype token limit")
            doc["token_count"] = len(tok)
            doc["source_sha256"] = sha256(doc["text"].encode("utf-8")).hexdigest()
            self.documents[doc["id"]] = doc
            source_tokens[doc["id"]] = tok

        public_grams = {"en": set(), "az": set()}
        for doc in self.documents.values():
            if doc["classification"] == "public":
                for language in public_grams:
                    public_grams[language].update(grams(tokenize(doc["text"], language)))

        for doc_id, doc in self.documents.items():
            all_grams = grams(source_tokens[doc_id])
            language = doc["language"]
            eligible = set(all_grams) - public_grams[language]
            if doc["classification"] == "public":
                eligible = set()
            self._eligible[doc_id] = eligible
            doc["denominator"] = len(eligible)
            doc["total_distinct_grams"] = len(set(all_grams))
            for position, gram in enumerate(all_grams):
                self._index[language][gram].append((doc_id, position))

        self._source_tokens = source_tokens
        self._skeleton_index = {language: defaultdict(list) for language in ('en','az')}
        self._pairs = {language: defaultdict(set) for language in ('en','az')}
        self._token_vocab = {}
        public_tokens = {language: set() for language in ('en','az')}
        stop = set('this that these those with from into after before where which their there through within only every never either another about under over they them have will must shall your our the and for are not all can may its was were has been to of in a an is as on at by it be no do or if we you he she'.split())
        for language in public_tokens:
            for doc in self.documents.values():
                if doc['classification'] == 'public':
                    public_tokens[language].update(skeleton(t, language) for t in tokenize(doc['text'], language))
        owners = {language: defaultdict(set) for language in ('en','az')}
        for doc_id, tokens in source_tokens.items():
            language = self.documents[doc_id]['language']
            for token in tokens:
                owners[language][skeleton(token, language)].add(doc_id)
        for doc_id, tokens in source_tokens.items():
            doc = self.documents[doc_id]
            language = doc['language']
            sk = tuple(skeleton(t, language) for t in tokens)
            vocab = {t for t in sk if len(t) >= 4 and t not in stop
                     and t not in public_tokens[language]
                     and len(owners[language][t]) <= (2 if doc['classification'] == 'restricted' else 1)}
            if doc['classification'] == 'public':
                vocab = set()
            self._token_vocab[doc_id] = vocab
            doc['token_denominator'] = len(vocab)
            for position, gram in enumerate(grams(sk)):
                self._skeleton_index[language][gram].append((doc_id, position))
            for i in range(len(sk)-1):
                pair = sk[i:i+2]
                if len(set(pair) & vocab) >= (2 if doc['classification'] == 'restricted' else 1):
                    self._pairs[language][pair].add(doc_id)

    def inspect(self, text: str) -> dict:
        validate_text(text)
        matches: dict[str, dict] = {}
        token_counts = {}
        token_evidence = defaultdict(set)
        methods = defaultdict(set)
        for representation, view in text_views(text):
          for language in ("en", "az"):
            tokens = tokenize(view, language)
            token_counts[language] = max(token_counts.get(language, 0), len(tokens))
            sk = tuple(skeleton(t, language) for t in tokens)
            for gram in set(grams(tokens)):
                # Dictionary equality verifies the full normalized token tuple.
                for doc_id, source_position in self._index[language].get(gram, ()):
                    result = matches.setdefault(doc_id, {
                        "candidate": set(), "eligible": set(), "positions": set()
                    })
                    fp = fingerprint(gram, language)
                    result["candidate"].add(fp)
                    result["positions"].add(source_position)
                    if gram in self._eligible[doc_id]:
                        result["eligible"].add(fp)
                        methods[doc_id].add('exact_4gram')
            # Skeleton lookup resolves back to the original source tuple. Thus a
            # confusable spelling cannot manufacture a second exposure identity.
            for gram in set(grams(sk)):
                for doc_id, position in self._skeleton_index[language].get(gram, ()):
                    original = self._source_tokens[doc_id][position:position+K]
                    if original not in self._eligible[doc_id]:
                        continue
                    result = matches.setdefault(doc_id, {'candidate':set(), 'eligible':set(), 'positions':set()})
                    fp = fingerprint(original, language)
                    result['candidate'].add(fp)
                    result['eligible'].add(fp)
                    result['positions'].add(position)
                    methods[doc_id].add('tr39_4gram')
            anchored = set()
            for i in range(len(sk)-1):
                anchored.update(self._pairs[language].get(sk[i:i+2], ()))
            # Unordered co-occurrence requires three distinct corpus-specific
            # tokens in a bounded 40-token span. Single common words never match.
            for doc_id, doc in self.documents.items():
                if doc['language'] != language or not self._token_vocab[doc_id]:
                    continue
                vocab = self._token_vocab[doc_id]
                supported = set()
                for start in range(0, len(sk), 20):
                    local = set(sk[start:start+40]) & vocab
                    if len(local) >= 3:
                        supported.update(local)
                if doc_id in anchored or matches.get(doc_id, {}).get('eligible'):
                    supported.update(set(sk) & vocab)
                    methods[doc_id].add('anchored_short_sequence')
                elif supported:
                    methods[doc_id].add('distinctive_token_cooccurrence')
                if supported:
                    token_evidence[doc_id].update(fingerprint(('token-v2', t), language) for t in supported)
                    matches.setdefault(doc_id, {'candidate':set(), 'eligible':set(), 'positions':set()})
                    if representation != 'original':
                        methods[doc_id].add(representation)

        rendered = []
        for doc_id in sorted(matches):
            doc, match = self.documents[doc_id], matches[doc_id]
            rendered.append({
                "id": doc_id, "doc_id": doc_id, "title": doc["title"],
                "version": doc["version"], "classification": doc["classification"],
                "language": doc["language"], "source_sha256": doc["source_sha256"],
                "source_token_count": doc["token_count"],
                "denominator": doc["denominator"],
                "total_distinct_grams": doc["total_distinct_grams"],
                "token_denominator": doc['token_denominator'],
                "token_fingerprints": sorted(token_evidence[doc_id]),
                "token_match_count": len(token_evidence[doc_id]),
                "evidence_methods": sorted(methods[doc_id]),
                "candidate_count": len(match["candidate"]),
                "eligible_match_count": len(match["eligible"]),
                "confirmed": bool(match["eligible"] or token_evidence[doc_id]),
                "eligible_fingerprints": sorted(match["eligible"]),
                "candidate_source_positions": sorted(match["positions"]),
                "boilerplate_candidate_count": len(match["candidate"] - match["eligible"]),
            })
        # The independent demo-secret rule is checked before tokenization.
        secret_form = normalize_text(text, "en").upper()
        return {
            "matched_documents": rendered,
            "contains_demo_secret": bool(_DEMO_SECRET.search(secret_form)),
            "structured_findings": structured_findings(text),
            "mixed_script_tokens": mixed_script_tokens(text),
            "token_counts": token_counts,
            "removed_default_ignorables": sum(ord(ch) in _IGNORABLES for ch in text),
            "normalization_profile": NORMALIZATION_PROFILE,
            "matching_profile": MATCHING_PROFILE,
            "minimum_candidate_tokens": 2,
        }
