#!/usr/bin/env python3
"""
runner.py

Usage: runner.py <vectors_dir>

Validates JSON examples in the vectors directory against the JSON Schemas and verifies signatures.
"""
import json
import os
import sys
from base64 import urlsafe_b64decode
from jsonschema import Draft202012Validator, RefResolver
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError


def b64url_to_bytes(s: str) -> bytes:
    # Add padding
    s2 = s + '=' * ((4 - len(s) % 4) % 4)
    return urlsafe_b64decode(s2.encode('ascii'))


def load_schema(path: str):
    with open(path, 'r') as f:
        return json.load(f)


def validate_schema(schema_path: str, instance_path: str):
    schema = load_schema(schema_path)
    with open(instance_path, 'r') as f:
        instance = json.load(f)
    base_uri = 'file://' + os.path.abspath(os.path.dirname(schema_path)) + '/'
    resolver = RefResolver(base_uri=base_uri, referrer=schema)
    Draft202012Validator(schema, resolver=resolver).validate(instance)
    return instance


def verify_signature(signer_pub_b64: str, obj: dict, sig_b64: str) -> bool:
    vk_bytes = b64url_to_bytes(signer_pub_b64)
    sig = b64url_to_bytes(sig_b64)
    vk = VerifyKey(vk_bytes)
    # canonicalize the obj exactly as generate_vectors.py did (sort keys, compact separators)
    import json
    data = json.dumps({k: obj[k] for k in obj if k != 'sig' and k != 'sender_sig'}, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    try:
        vk.verify(data, sig)
        return True
    except BadSignatureError:
        return False


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: runner.py <vectors_dir>')
        sys.exit(2)
    vectors_dir = sys.argv[1]
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
    schema_dir = os.path.join(repo_root, 'openapi', 'components', 'schemas')

    print('Schema dir:', schema_dir)

    # Validate device_cert
    try:
        device_instance = validate_schema(os.path.join(schema_dir, 'device-cert.schema.json'), os.path.join(vectors_dir, 'device_cert.json'))
        print('device_cert.json: schema OK')
    except Exception as e:
        print('device_cert.json: schema validation FAILED:', e)
        raise

    # Validate CRL
    try:
        crl_instance = validate_schema(os.path.join(schema_dir, 'crl.schema.json'), os.path.join(vectors_dir, 'crl.json'))
        print('crl.json: schema OK')
    except Exception as e:
        print('crl.json: schema validation FAILED:', e)
        raise

    # Validate manifest
    try:
        manifest_instance = validate_schema(os.path.join(schema_dir, 'file-manifest.schema.json'), os.path.join(vectors_dir, 'manifest.json'))
        print('manifest.json: schema OK')
    except Exception as e:
        print('manifest.json: schema validation FAILED:', e)
        raise

    # Load meta for pubkeys
    meta = json.load(open(os.path.join(vectors_dir, 'meta.json')))
    server_pub = meta['server_public_key_b64url']
    device_pub = meta['device_public_key_b64url']

    # Verify device_cert signed by server
    ok = verify_signature(server_pub, {k: device_instance[k] for k in device_instance if k != 'sig'}, device_instance['sig'])
    print('device_cert signature verification:', 'OK' if ok else 'FAILED')
    if not ok:
        raise SystemExit('device_cert signature invalid')

    # Verify CRL signed by server
    ok = verify_signature(server_pub, {k: crl_instance[k] for k in crl_instance if k != 'sig'}, crl_instance['sig'])
    print('crl signature verification:', 'OK' if ok else 'FAILED')
    if not ok:
        raise SystemExit('crl signature invalid')

    # Verify manifest signed by device
    ok = verify_signature(device_pub, {k: manifest_instance[k] for k in manifest_instance if k != 'sender_sig'}, manifest_instance['sender_sig'])
    print('manifest signature verification:', 'OK' if ok else 'FAILED')
    if not ok:
        raise SystemExit('manifest signature invalid')

    print('\nAll conformance checks passed.')
