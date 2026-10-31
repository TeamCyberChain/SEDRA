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
import csv
import io
import json
from .unicode_profile import IGNORABLES
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


STRUCTURED_PROFILE = 'sedra-structured-context-checksum-tr39-v3'
MAX_FINDINGS = 64
SEP = r'[ \t\r\n.\-]{0,3}'
FIN_ALPHABET = r'[A-HJ-NP-Z0-9]'
FIN_LABEL = r'(?:f[iİı]n(?:[ _-]*(?:kod(?:u)?|code|number))?|fərdi[ _-]+identifikasiya[ _-]+(?:nömrəsi|nomresi)|personal[ _-]+identification[ _-]+number)'
SECRET_LABEL = r'(?:password|passwd|pwd|şifrə|sifre|parol|api[ _-]?(?:key|açarı|acari)|client[ _-]?secret|access[ _-]?token|secret[ _-]?key)'
ASSIGNMENT = r'''["']?[ \t]*(?:[:=][ \t\r\n]*|[ \t]+(?:is[ \t]+)?)["']?'''
FIN_KEYS = {'fin', 'finkod', 'finkodu', 'fincode', 'finnumber', 'ferdiidentifikasiyanomresi', 'personalidentificationnumber'}
SECRET_KEYS = {'password','passwd','pwd','sifre','parol','apiacari','apikey','clientsecret','accesstoken','secretkey'}
CARD_KEYS = {'card','cardnumber','paymentcard','pan','kart','kartnomresi','kartnumarasi'}
# Exact documentation placeholders, never substring exclusions.
PLACEHOLDERS = {'example_documentation','your_api_key_here','your_password_here','redacted','<redacted>','<api_key>','<password>'}


@lru_cache(maxsize=1)
def iban_registry():
    return json.loads((Path(__file__).parent/'iban_formats.json').read_text(encoding='utf-8'))


@lru_cache(maxsize=128)
def iban_pattern(country):
    spec = iban_registry()['countries'][country]
    parts = re.findall(r'(\d+)!([nac])', spec['structure'][2:])
    symbols = {'n': '[0-9]', 'a': '[A-Z]', 'c': '[A-Z0-9]'}
    return re.compile(country + ''.join(symbols[k]+'{'+n+'}' for n,k in parts))


def iban_valid(value):
    """Pinned country structure and MOD97; not an account/bank existence check."""
    value = re.sub(r'[\s.\-]', '', value).upper()
    if not re.fullmatch(r'[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}', value):
        return False
    spec = iban_registry()['countries'].get(value[:2])
    if not spec or len(value) != spec['length'] or not iban_pattern(value[:2]).fullmatch(value):
        return False
    if not 2 <= int(value[2:4]) <= 98:
        return False
    # Stream the remainder, bounded by the maximum ISO IBAN length.
    remainder = 0
    for char in value[4:] + value[:4]:
        for digit in str(ord(char)-55) if char.isalpha() else char:
            remainder = (remainder*10 + int(digit)) % 97
    return remainder == 1


def _normalize_structured(raw):
    value = unicodedata.normalize('NFKC', raw)
    steps = ['NFKC'] if value != raw else []
    output = []
    for char in value:
        if ord(char) in IGNORABLES:
            steps.append('default_ignorables_removed')
            continue
        if unicodedata.category(char) == 'Nd' and char not in '0123456789':
            char = str(unicodedata.decimal(char))
            steps.append('decimal_digits_ascii')
        elif any(script in unicodedata.name(char, '') for script in ('CYRILLIC', 'GREEK')):
            mapped = confusables().get(char, char)
            if len(mapped) == 1 and mapped.isascii() and mapped.isalnum():
                char = mapped
                steps.append('TR39_script_lookalike')
        if unicodedata.category(char) == 'Pd' and char != '-':
            char = '-'
            steps.append('dash_normalized')
        output.append(char)
    return ''.join(output), list(dict.fromkeys(steps))


def _label_key(value):
    value, _ = _normalize_structured(value)
    value = value.casefold().translate(str.maketrans({'ə':'e','ı':'i'}))
    return re.sub(r'[^a-z0-9]', '', ''.join(c for c in unicodedata.normalize('NFD',value) if unicodedata.category(c) != 'Mn'))


def _fin_valid(value):
    value = re.sub(r'[ \t.\-]', '', value).upper()
    return value if re.fullmatch(FIN_ALPHABET+'{7}', value) else None


def _secret_valid(value):
    if value.casefold() in PLACEHOLDERS or not 8 <= len(value) <= 256 or len(set(value)) < 5:
        return False
    classes = [any(c.isalpha() for c in value), any(c.isdigit() for c in value), any(not c.isalnum() for c in value)]
    return sum(classes) >= 2 or (len(value) >= 20 and len(set(value)) >= 10)


def _json_depth_exceeded(text, limit=64):
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped: escaped=False
            elif char=='\\': escaped=True
            elif char=='"': quoted=False
        elif char=='"': quoted=True
        elif char in '[{':
            depth += 1
            if depth > limit:return True
        elif char in ']}':depth -= 1
    return False


def structured_findings(text):
    """Bounded supported representations; no raw values, offsets or validity claims."""
    if not isinstance(text,str) or len(text.encode('utf-8')) > 65536:
        raise ValueError('Structured inspection accepts at most 65536 UTF-8 bytes')
    findings, seen = [], {}

    def add(kind, value, representation, steps, checks, category='credentials'):
        digest = sha256(value.encode('utf-8')).hexdigest()
        key = kind, digest
        if key in seen:
            prior = seen[key]
            if representation not in prior['representations']:
                prior['representations'].append(representation)
            prior['normalization_steps'] = list(dict.fromkeys(prior['normalization_steps'] + steps))
            return
        if len(findings) >= MAX_FINDINGS:
            findings[-1]['additional_findings_omitted'] = True
            return  # Existing hard-block evidence already establishes the verdict.
        entry = {'type':kind,'category':category,'sensitivity':'restricted','representation':representation,
                 'representations':[representation], 'confidence':'high','confidence_basis':'rule_evidence_not_probability',
                 'validation_checks':checks,'normalization_steps':steps,'detector_profile':STRUCTURED_PROFILE,
                 'value_sha256':digest,'action':'BLOCK'}
        seen[key] = entry
        findings.append(entry)

    def field(key, raw_value, representation):
        value, steps = _normalize_structured(raw_value)
        label = _label_key(key)
        if label in FIN_KEYS:
            canonical = _fin_valid(value)
            if canonical:
                add('AZ_FIN_CONTEXTUAL',canonical,representation,steps,['explicit_field_context','7_character_format','restricted_alphabet'],'personal_identifiers')
        elif label in SECRET_KEYS and _secret_valid(value):
            add('LABELED_CREDENTIAL',value,representation,steps,['explicit_credential_field','bounded_value_shape'])
        elif label in CARD_KEYS:
            digits = re.sub(r'[\s.\-]', '', value)
            if re.fullmatch(r'[0-9]{13,19}', digits) and luhn(digits):
                add('PAYMENT_CARD_LUHN',digits,representation,steps,['explicit_payment_context','13_to_19_digits','luhn'],'financial')
        elif label in ('iban','bankaccount','bankaccountnumber','hesabnomresi') and iban_valid(value):
            canonical = re.sub(r'[\s.\-]', '', value).upper()
            add('AZ_IBAN_MOD97' if canonical.startswith('AZ') else 'IBAN_MOD97',canonical,representation,steps,
                ['country_format','country_length','mod97','swift_registry_103'],'financial')

    views = list(text_views(text))
    for representation, raw in views:
        value, steps = _normalize_structured(raw)
        # Parse genuine JSON, including escaped field names/values. No eval or recursive decoding.
        if 'json_leaf' not in representation and raw.lstrip().startswith(('{','[')):
            try:
                if _json_depth_exceeded(raw):
                    raise RecursionError('Declared JSON depth limit')
                root = json.loads(raw)
                stack = [root]
                while stack:
                    node = stack.pop()
                    if isinstance(node,dict):
                        for key, child in node.items():
                            if isinstance(child,str):
                                field(key,child,representation+' / json_field')
                                views.append((representation+' / json_leaf',child))
                            elif type(child) is int:
                                field(key,str(child),representation+' / json_field')
                            elif isinstance(child,(dict,list)):
                                stack.append(child)
                    elif isinstance(node,list):
                        for child in node:
                            if isinstance(child,str):
                                views.append((representation+' / json_leaf',child))
                            elif isinstance(child,(dict,list)):
                                stack.append(child)
            except json.JSONDecodeError:
                pass  # Plain-text rules still apply to malformed/incomplete JSON.
            except RecursionError:
                add('STRUCTURED_INSPECTION_LIMIT',raw,representation,[],['json_depth_limit_64_fail_closed'],'inspection_limits')

        # Independent fields only; never concatenate neighboring cells or requests.
        parsed_table = False
        for delimiter in (',',';','\t','|'):
            if delimiter not in raw and not (delimiter==',' and '\n' in raw):
                continue
            try:
                rows = list(csv.reader(io.StringIO(raw),delimiter=delimiter))
                if len(rows)<2:
                    continue
                header, rows = rows[0], rows[1:]
                keys = [_label_key(k) for k in header]
                if not any(k in FIN_KEYS|SECRET_KEYS|CARD_KEYS|{'iban'} for k in keys):
                    continue
                if any(len(row)!=len(keys) for row in rows if row):
                    continue
                parsed_table = True
                for row in rows:
                    for index, key in enumerate(keys):
                        if index < len(row):
                            field(key,row[index],representation+' / delimited_field')
                            if 'delimited_leaf' not in representation:
                                views.append((representation+' / delimited_leaf',row[index]))
                break
            except csv.Error:
                pass

        compact = re.sub(r'\s+', '', value)
        for match in re.finditer(r'(?:SADD|SEDRA)_SECRET_[A-Z0-9]{16,}',compact,re.I):
            add('SYNTHETIC_SECRET',match[0].upper(),representation,steps,['synthetic_marker_format'])
        aws = r'(?<![A-Z0-9_])(?:A'+SEP+r'K'+SEP+r'I'+SEP+r'A|A'+SEP+r'S'+SEP+r'I'+SEP+r'A)(?:'+SEP+r'[A-Z0-9]){16}(?![A-Z0-9_])'
        for match in re.finditer(aws,value,re.I):
            add('AWS_ACCESS_KEY_ID',re.sub(r'[\s.\-]','',match[0]).upper(),representation,steps,['aws_access_id_format'])
        for match in re.finditer(r'-----BEGIN ((?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----\s*([A-Za-z0-9+/=\s]{64,})-----END \1-----',value):
            add('PEM_PRIVATE_KEY',match[0],representation,steps,['private_key_envelope','bounded_base64_body'])

        # Country-specific length prevents accepting arbitrary checksum-valid strings.
        upper = value.upper()
        for prefix in re.finditer(r'(?<![A-Z0-9_])([A-Z])'+SEP+r'([A-Z])(?='+SEP+r'[0-9])',upper):
            country = prefix[1]+prefix[2]
            spec = iban_registry()['countries'].get(country)
            if not spec:
                continue
            pattern = r'[A-Z0-9](?:'+SEP+r'[A-Z0-9]){'+str(spec['length']-1)+r'}(?![A-Z0-9_]|[.\-][A-Z0-9])'
            match = re.match(pattern,upper[prefix.start():])
            if match:
                candidate = re.sub(r'[\s.\-]','',match[0])
                if iban_valid(candidate):
                    add('AZ_IBAN_MOD97' if country=='AZ' else 'IBAN_MOD97',candidate,representation,steps,
                        ['country_format','country_length','mod97','swift_registry_103'],'financial')

        fin_value = r'('+FIN_ALPHABET+r'(?:[ \t.\-]{0,3}'+FIN_ALPHABET+r'){6})(?![A-Z0-9_]|[.\-][A-Z0-9]|[ \t]+[A-Z0-9](?![A-Z0-9]))'
        for match in re.finditer(r'\b'+FIN_LABEL+r'\b'+ASSIGNMENT+fin_value,'' if parsed_table else value,re.I):
            canonical = _fin_valid(match[1])
            if canonical:
                add('AZ_FIN_CONTEXTUAL',canonical,representation,steps,['explicit_fin_context','7_character_format','restricted_alphabet'],'personal_identifiers')

        for match in re.finditer(r'(?<![0-9])(?:[0-9][ \t.\-]{0,3}){12,18}[0-9](?![0-9])','' if parsed_table else value):
            digits = re.sub(r'\D','',match[0])
            context = value[max(0,match.start()-64):match.end()+24]
            if 13 <= len(digits) <= 19 and luhn(digits) and re.search(r'\b(?:card|visa|mastercard|pan|kart)(?:[ _-]*(?:number|nömrəsi|nomresi|numarasi))?\b',context,re.I):
                add('PAYMENT_CARD_LUHN',digits,representation,steps,['payment_context','13_to_19_digits','luhn'],'financial')

        credential_assignment = r'''["']?[ \t]*(?:[:=]|\bis\b)[ \t\r\n]*["']?'''
        credential = r'''\b'''+SECRET_LABEL+r'''\b'''+credential_assignment+r'''([^\s"'\x00-\x1f,;{}\[\]<>]{8,256})'''
        for match in re.finditer(credential,'' if parsed_table else value,re.I):
            if _secret_valid(match[1]):
                add('LABELED_CREDENTIAL',match[1],representation,steps,['explicit_credential_context','bounded_value_shape'])
        for match in re.finditer(r'\bauthorization["\']?[ \t]*[:=][ \t]*["\']?bearer[ \t]+([A-Za-z0-9_.~+/-]{16,512}={0,2})',value,re.I):
            if len(set(match[1])) >= 8:
                add('BEARER_TOKEN',match[1],representation,steps,['authorization_bearer_context','bounded_token_shape'])
    return findings

