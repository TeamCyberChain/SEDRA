"""Server-owned descriptions and synthetic examples for the actual detectors."""
from .content_security import STRUCTURED_PROFILE, iban_registry


def _demo_iban(country, bban):
    digits = ''.join(str(ord(c)-55) if c.isalpha() else c for c in bban+country+'00')
    return country+f'{98-int(digits)%97:02d}'+bban


def detector_catalog():
    registry = iban_registry()
    rules = [
        ('AZ_FIN_CONTEXTUAL','Azerbaijan FİN','Personal identifiers','Explicit FİN field + 7-character format',
         'AZ/EN labels, JSON, CSV/TSV, supported separators and Unicode views. No identity assignment lookup.'),
        ('AZ_IBAN_MOD97','Azerbaijan IBAN','Financial','AZ structure + 28 characters + MOD97',
         'Account portion is alphanumeric. Spaces, supported separators and script look-alikes are inspected.'),
        ('IBAN_MOD97','International IBAN','Financial','Country format + length + MOD97',
         f"{len(registry['countries'])} pinned country formats; no bank assignment, ownership or account-existence lookup."),
        ('PAYMENT_CARD_LUHN','Payment card','Financial','Payment field/context + 13–19 digits + Luhn',
         'Context is required to reduce order-number false positives; no issuer or card validity lookup.'),
        ('LABELED_CREDENTIAL','Labeled credential','Credentials','Credential field + bounded value shape',
         'AZ/EN labels, JSON and delimited fields; 8–256 characters. Not a complete password detector.'),
        ('AWS_ACCESS_KEY_ID','AWS access key ID','Credentials','AKIA / ASIA + 16 alphanumeric characters',
         'Supported spacing and script look-alikes. Format evidence does not prove a working key.'),
        ('PEM_PRIVATE_KEY','Private key envelope','Credentials','Private PEM envelope + bounded body',
         'Private, RSA, EC, OpenSSH and encrypted envelopes; public-key envelopes do not trigger this rule.'),
        ('BEARER_TOKEN','Authorization bearer token','Credentials','Explicit Authorization: Bearer context',
         'Bounded token shape. No signature, token validity or provider lookup.'),
        ('SYNTHETIC_SECRET','Synthetic test secret','Demonstration','SEDRA_SECRET marker',
         'Fictional laboratory marker. Grants no access to a real service.'),
    ]
    az = _demo_iban('AZ','TEST'+'SYNTHETIC'+'0'*11)
    examples = {
        'fin_json': {'label':'FİN · JSON field','text':'{"employee":{"fin_code":"A1B2C3D"}}','expected':'BLOCK'},
        'fin_spaced': {'label':'FİN · spaced characters','text':'FİN kodu: A 1 B 2 C 3 D','expected':'BLOCK'},
        'fin_csv': {'label':'FİN · CSV column','text':'name,fin_code\nSynthetic,A1B2C3D','expected':'BLOCK'},
        'iban_alphanumeric': {'label':'AZ IBAN · alphanumeric','text':'IBAN: '+az,'expected':'BLOCK'},
        'iban_grouped': {'label':'AZ IBAN · separated groups','text':'IBAN: '+'-'.join(az[i:i+4] for i in range(0,len(az),4)),'expected':'BLOCK'},
        'iban_international': {'label':'UK IBAN · country validation','text':_demo_iban('GB','TEST'+'123456'+'12345678'),'expected':'BLOCK'},
        'credential_json': {'label':'Credential · JSON field','text':'{"password":"SynTh3t!c9"}','expected':'BLOCK'},
        'invalid_iban': {'label':'IBAN · invalid checksum control','text':az[:3]+str((int(az[3])+1)%10)+az[4:],'expected':'ALLOW (structured rules only)'},
    }
    return {'profile':STRUCTURED_PROFILE,'default_action':'BLOCK','rules':[dict(zip(
        ('id','name','category','checks','scope'),row)) | {'action':'BLOCK'} for row in rules],
        'iban_registry':{'release':registry['source_release'],'date':registry['source_date'],
                         'source':registry['source_url'],'country_count':len(registry['countries']),
                         'country_codes':list(registry['countries'])},
        'limits':{'max_input_utf8_bytes':65536,'max_distinct_findings':64,'base64_depth':1,
                  'max_json_depth':64,
                  'max_base64_candidates':8,'max_base64_decoded_bytes':8192,
                  'json_recursion_overflow_action':'BLOCK'},
        'examples':examples,
        'limitation':'Format/context evidence only. No assignment, account ownership, token validity, OCR or arbitrary encoding coverage.'}
