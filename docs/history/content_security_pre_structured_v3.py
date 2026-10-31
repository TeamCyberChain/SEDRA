"""Bounded structured detectors. Evidence never contains the detected value.

TR39 is a secondary matching representation, not an identity canonicalizer.
Base64 is decoded once, with canonical/UTF-8/size checks, and is never forwarded
in place of the original payload. No regex or encoding alone implies a secret.
"""
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
import base64
import binascii
import re
import unicodedata

CONFUSABLES_PATH = Path(__file__).parent / 'unicode' / 'confusables-15.0.0.txt'

@lru_cache(maxsize=1)
def confusables():
    table = {}
    for line in CONFUSABLES_PATH.read_text(encoding='utf-8-sig').splitlines():
        fields = line.split('#', 1)[0].split(';')
        if len(fields) >= 2:
            src = ''.join(chr(int(c, 16)) for c in fields[0].split())
            dst = ''.join(chr(int(c, 16)) for c in fields[1].split())
            if len(src) == 1:
                table[src] = dst
    return table

def skeleton(value, language='en'):
    table = confusables()
    return unicodedata.normalize('NFD', ''.join(
        c if language == 'az' and c in 'ıİ' else table.get(c, c)
        for c in unicodedata.normalize('NFD', value)
    )).casefold()

def mixed_script_tokens(text):
    count = 0
    for word in re.findall(r'[^\W\d_]+', text, re.UNICODE):
        scripts = {script for c in word for script in ('LATIN','CYRILLIC','GREEK')
                   if script in unicodedata.name(c, '')}
        count += len(scripts) > 1
    return count

def text_views(text):
    """At most eight canonical Base64 candidates, 8 KiB decoded in total."""
    views = [('original', text)]
    total = 0
    for candidate in re.findall(r'(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{20,10924}={0,2}(?![A-Za-z0-9+/_=-])', text)[:8]:
        if len(candidate) % 4 == 1:
            continue
        padded = candidate + '=' * (-len(candidate) % 4)
        try:
            raw = base64.b64decode(padded, altchars=b'-_', validate=True)
            if len(raw) + total > 8192:
                continue
            canonical = base64.urlsafe_b64encode(raw).decode().rstrip('=')
            if canonical != candidate.replace('+','-').replace('/','_').rstrip('='):
                continue
            decoded = raw.decode('utf-8', errors='strict')
            if not decoded or sum(c.isprintable() or c in '\r\n\t' for c in decoded)/len(decoded) < .95:
                continue
            total += len(raw)
            views.append(('base64_once', decoded))
        except (ValueError, UnicodeError, binascii.Error):
            continue
    return views

def luhn(value):
    digits = [int(c) for c in value]
    return len(set(digits)) > 1 and sum(
        (d*2-9 if d*2>9 else d*2) if i%2 == len(digits)%2 else d
        for i,d in enumerate(digits)) % 10 == 0

def iban_valid(value):
    value = re.sub(r'\s+', '', value).upper()
    if not re.fullmatch(r'AZ\d{2}[A-Z]{4}\d{20}', value):
        return False
    digits = ''.join(str(ord(c)-55) if c.isalpha() else c for c in value[4:]+value[:4])
    return int(digits) % 97 == 1

def structured_findings(text):
    findings = []
    def add(kind, value, representation, confidence='high'):
        entry = {'type':kind, 'representation':representation, 'confidence':confidence,
                 'value_sha256':sha256(value.encode()).hexdigest(), 'action':'BLOCK'}
        if entry not in findings:
            findings.append(entry)
    for representation, raw in text_views(text):
        value = unicodedata.normalize('NFKC', raw)
        value = ''.join(c for c in value if unicodedata.category(c) != 'Cf' and c != '\u034f')
        compact = re.sub(r'\s+', '', value)
        for match in re.finditer(r'SEDRA_SECRET_[A-Z0-9]{16,}', compact, re.I):
            add('SYNTHETIC_SECRET', match[0], representation)
        for match in re.finditer(r'(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])', value):
            add('AWS_ACCESS_KEY_ID', match[0], representation)
        for match in re.finditer(r'-----BEGIN ((?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----\s*([A-Za-z0-9+/=\s]{64,})-----END \1-----', value):
            add('PEM_PRIVATE_KEY', match[0], representation)
        for match in re.finditer(r'(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)', value):
            digits = re.sub(r'\D','',match[0])
            context = value[max(0,match.start()-48):match.end()+20]
            if 13 <= len(digits) <= 19 and luhn(digits) and re.search(r'card|visa|mastercard|\bpan\b|kart', context, re.I):
                add('PAYMENT_CARD_LUHN', digits, representation)
        for match in re.finditer(r'\bAZ\d{2}(?:\s?[A-Z0-9]){24}\b', value, re.I):
            if iban_valid(match[0]):
                add('AZ_IBAN_MOD97', re.sub(r'\s+','', match[0]), representation)
        for match in re.finditer(r'\b(?:FIN|FİN|personal identification number)\s*[:=]\s*([A-HJ-NP-Z0-9]{7})\b', value, re.I):
            add('AZ_FIN_CONTEXTUAL', match[1], representation)
        for match in re.finditer(r'\b(?:password|passwd|api[_ -]?key|client[_ -]?secret|access[_ -]?token)\s*[:=]\s*[\"\']?([A-Za-z0-9_+./=-]{16,})', value, re.I):
            secret = match[1]
            if len(set(secret)) >= 8 and any(c.isdigit() for c in secret) and any(c.isalpha() for c in secret):
                add('LABELED_CREDENTIAL', secret, representation)
    return findings
