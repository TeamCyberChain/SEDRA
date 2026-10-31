"""Repeat the external review with synthetic content only, on isolated ledgers."""
import base64
import json
from pathlib import Path
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sedra.corpus import DOCUMENTS
from sedra.gateway import Gateway

def cases():
    runbook = DOCUMENTS[2]['text'].split()
    return {
        'restricted_three_words': 'fictional restricted runbook',
        'restricted_two_words': 'restricted runbook',
        'inserted_words': 'fictional filler restricted filler runbook filler laboratory filler credential',
        'cyrillic_homoglyph': 'This fictionаl restricted runbооk contаins а lаborаtоry credentiаl mаrker.',
        'reversed_order': 'credential laboratory runbook restricted fictional',
        'aws_access_id': 'AWS access key: AKIAIOSFODNN7EXAMPLE',
        'pem_private': '-----BEGIN RSA PRIVATE KEY-----\n' + 'A'*80 + '\n-----END RSA PRIVATE KEY-----',
        'card_luhn': 'Card number: 4111 1111 1111 1111',
        'az_iban': 'Bank account: AZ21NABZ00000000137010001944',
        'spaced_secret': ' '.join('SEDRA_SECRET_A1B2C3D4E5F6G7H8'),
        'base64_secret': base64.b64encode(b'SEDRA_SECRET_A1B2C3D4E5F6G7H8').decode(),
        'benign_public': 'Please explain how a public cybersecurity workshop can help our team.',
    }

def run(output):
    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        for index, (name, text) in enumerate(cases().items()):
            gateway = Gateway(Path(tmp)/f'{index}.sqlite', DOCUMENTS)
            result = gateway.evaluate('audit-user', f'audit-{index}', text, 0)
            results[name] = {k: result[k] for k in ('decision','reason_codes')}
    Path(output).write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results, indent=2))

if __name__ == '__main__':
    run(sys.argv[1] if len(sys.argv)>1 else 'artifacts/audit_current.json')
