"""Build a CRX3 for a specifically authorized managed-browser deployment.

The existing signing key is mandatory and must stay outside version control.
Only the seven extension sources are packaged, never runtime data or keys.
"""
import argparse
import base64
import hashlib
from io import BytesIO
import json
from pathlib import Path
import struct
import zipfile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ROOT = Path(__file__).resolve().parents[1]
FILES = {'manifest.json','core.js','worker.js','guard.js','options.html','options.css','options.js'}


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result) + bytes([value])


def field(number, value):
    return varint((number << 3) | 2) + varint(len(value)) + value


def build(private_key, output):
    source = ROOT / 'browser-extension'
    if {p.name for p in source.iterdir() if p.is_file()} != FILES:
        raise ValueError('Unexpected source boundary')
    manifest = json.loads((source / 'manifest.json').read_text())
    key = serialization.load_pem_private_key(private_key.read_bytes(), password=None)
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if public != base64.b64decode(manifest['key'], validate=True):
        raise ValueError('Signing key does not match the reviewed manifest identity')
    digest = hashlib.sha256(public).digest()[:16]
    identifier = ''.join(chr(97 + int(c,16)) for c in digest.hex())
    archive = BytesIO()
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
        for name in sorted(FILES):
            entry = zipfile.ZipInfo(name, (2026,10,31,0,0,0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(entry, (source / name).read_bytes())
    payload = archive.getvalue()
    signed_header = field(1, digest)
    signed = b'CRX3 SignedData\x00' + struct.pack('<I', len(signed_header)) + signed_header + payload
    signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    key.public_key().verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    header = field(2, field(1,public) + field(2,signature)) + field(10000,signed_header)
    output.mkdir(parents=True, exist_ok=True)
    crx = b'Cr24' + struct.pack('<II',3,len(header)) + header + payload
    (output / 'sedra-browser-guard.crx').write_bytes(crx)
    update = ('<?xml version="1.0" encoding="UTF-8"?>\n'
              '<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">'
              f'<app appid="{identifier}"><updatecheck '
              'codebase="http://127.0.0.1:8765/browser-deployment/sedra-browser-guard.crx" '
              f'version="{manifest["version"]}" /></app></gupdate>\n')
    (output / 'updates.xml').write_text(update, encoding='utf-8')
    return {'extension_id':identifier, 'version':manifest['version'], 'crx_sha256':hashlib.sha256(crx).hexdigest(), 'files':len(FILES)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-key', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.private_key, args.output)))
