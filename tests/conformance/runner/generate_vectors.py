#!/usr/bin/env python3
"""
Generates test vectors (keys + signed artifacts) for local conformance testing.
"""
import json
import os
from datetime import datetime, timedelta
from base64 import urlsafe_b64encode

from nacl.signing import SigningKey
from nacl.encoding import RawEncoder

OUTDIR = os.path.join(os.path.dirname(__file__), '..', 'vectors')
os.makedirs(OUTDIR, exist_ok=True)

# Helper
def b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode('ascii')

# Create server signing key
server_sk = SigningKey.generate()
server_pk = server_sk.verify_key.encode(RawEncoder)
server_id = 'test-server-1'

# Create device key
device_sk = SigningKey.generate()
device_pk = device_sk.verify_key.encode(RawEncoder)
device_id = 'dev-test-1'
account_id = 'acct-test-1'

issued_at = datetime.utcnow()
expires_at = issued_at + timedelta(days=365*2)

# Canonicalize function (simple stable JSON: keys sorted, separators compact). For real use, prefer JCS.
import functools
import json

def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

# Device cert to sign
device_cert = {
    "device_id": device_id,
    "account_id": account_id,
    "pubkey_ed25519": b64url(device_pk),
    "issued_at": issued_at.replace(microsecond=0).isoformat() + 'Z',
    "expires_at": expires_at.replace(microsecond=0).isoformat() + 'Z'
}

# Sign with server key
sig = server_sk.sign(canonical_json(device_cert)).signature
device_cert_signed = dict(device_cert)
device_cert_signed['sig'] = b64url(sig)

with open(os.path.join(OUTDIR, 'device_cert.json'), 'w') as f:
    json.dump(device_cert_signed, f, indent=2)

# CRL
crl = {
    "revoked_device_ids": ["dev-revoked-1"],
    "issued_at": issued_at.replace(microsecond=0).isoformat() + 'Z',
    "issuer_id": server_id,
    "version": 1
}
crl_sig = server_sk.sign(canonical_json(crl)).signature
crl['sig'] = b64url(crl_sig)
with open(os.path.join(OUTDIR, 'crl.json'), 'w') as f:
    json.dump(crl, f, indent=2)

# Manifest + sample chunk hash
manifest = {
    "manifest_id": "manifest-test-1",
    "filename": "example.txt",
    "size": 1024,
    "chunk_hashes": ["sha256:abcdef0123456789"],
    "chunk_size": 262144,
    "dedup": True,
    "timestamp": issued_at.replace(microsecond=0).isoformat() + 'Z'
}
# Sign manifest with device key (sender_sig)
manifest_sig = device_sk.sign(canonical_json(manifest)).signature
manifest['sender_sig'] = b64url(manifest_sig)
with open(os.path.join(OUTDIR, 'manifest.json'), 'w') as f:
    json.dump(manifest, f, indent=2)

# Write public keys and server public key for verification reference
with open(os.path.join(OUTDIR, 'meta.json'), 'w') as f:
    json.dump({
        'server_public_key_b64url': b64url(server_pk),
        'device_public_key_b64url': b64url(device_pk),
        'server_id': server_id,
        'device_id': device_id
    }, f, indent=2)

print('Generated test vectors in', OUTDIR)
