#!/usr/bin/env python3
"""
linux-bench Python engine — VCフォーマット別 署名/検証ベンチマーク

計測方式:
  - time.perf_counter_ns()（ナノ秒精度）で各イテレーションを個別記録
  - ウォームアップ後に本計測
  - 統計計算は行わず生タイミング(ns)を出力（統計は ../aggregate.mjs が一元計算）

使い方:
  python3 bench.py --format sdjwt|jsonld|jsonld-jcs|mdoc|all \
                   [--n 2000] [--warmup 50] [--out results.json]

依存: pip install -r requirements.txt  (cryptography, PyLD, cbor2)
"""
import argparse
import base64
import hashlib
import json
import os
import platform
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument('--format', default='all',
                    choices=['sdjwt', 'jsonld', 'jsonld-jcs', 'mdoc', 'all'])
parser.add_argument('--n', type=int, default=2000)
parser.add_argument('--warmup', type=int, default=50)
parser.add_argument('--out', default=None)
args = parser.parse_args()

N, WARMUP = args.n, args.warmup
benches = {}


def bench(key, n, fn):
    for _ in range(WARMUP):
        fn()
    timings = [0] * n
    for i in range(n):
        s = time.perf_counter_ns()
        fn()
        timings[i] = time.perf_counter_ns() - s
    benches[key] = {'n': n, 'warmup': WARMUP, 'timings_ns': timings}
    print(f'  {key}: done (n={n})', file=sys.stderr)


def b64url(data) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


CRED_NS = 'https://www.w3.org/2018/credentials#'
RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'
SUBJECT = {'id': 'did:example:1', 'name': 'Taro Yamada'}
VC_DOC = {
    '@context': [{
        '@version': 1.1, 'type': '@type', 'id': '@id',
        'VerifiableCredential': CRED_NS + 'VerifiableCredential',
        'issuer': {'@id': CRED_NS + 'issuer', '@type': '@id'},
        'issuanceDate': {'@id': CRED_NS + 'issuanceDate',
                         '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'},
        'credentialSubject': CRED_NS + 'credentialSubject',
        'name': 'http://schema.org/name',
    }],
    'type': 'VerifiableCredential',
    'issuer': 'https://example.com',
    'issuanceDate': '2024-01-01T00:00:00Z',
    'credentialSubject': SUBJECT,
}


def jcs_canonical(v) -> str:
    """RFC 8785 相当の字句的正規化（本ベンチのデータは ASCII/単純型のみ）"""
    return json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


# ── SD-JWT VC (Ed25519, cryptography) ────────────────────────────
def run_sdjwt():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    header = b64url(json.dumps({'alg': 'EdDSA', 'crv': 'Ed25519'}))
    payload = b64url(json.dumps({'iss': 'https://issuer.example.com',
                                 'vct': 'identity', 'sub': 'did:example:holder'}))
    sig_input = f'{header}.{payload}'.encode()

    def sign():
        s = priv.sign(sig_input)
        _ = f'{header}.{payload}.{b64url(s)}'
    bench('sdjwt/cryptography/sign', N, sign)

    token = f'{header}.{payload}.{b64url(priv.sign(sig_input))}'

    def verify():
        h, p, s = token.split('.')
        sig = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
        pub.verify(sig, f'{h}.{p}'.encode())
    bench('sdjwt/cryptography/verify', N, verify)


# ── JSON-LD VC (URDNA2015) ───────────────────────────────────────
def run_jsonld():
    from pyld import jsonld
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    opts = {'algorithm': 'URDNA2015', 'format': 'application/n-quads'}

    def normalize():
        return jsonld.normalize(VC_DOC, opts)

    def sign():
        norm = normalize()
        priv.sign(hashlib.sha256(norm.encode()).digest())
    bench('jsonld/pyld/sign', N, sign)

    sig0 = priv.sign(hashlib.sha256(normalize().encode()).digest())

    def verify():
        norm = normalize()
        pub.verify(sig0, hashlib.sha256(norm.encode()).digest())
    bench('jsonld/pyld/verify', N, verify)

    bench('jsonld/pyld/normalize-only', N, lambda: normalize())

    # noLib: インラインN-Quads
    vc = {'issuer': 'https://example.com',
          'issuanceDate': '2024-01-01T00:00:00Z', 'credentialSubject': SUBJECT}

    def inline_norm() -> bytes:
        s, sub = '_:c14n0', f"<{vc['credentialSubject']['id']}>"
        quads = [
            f"{sub} <http://schema.org/name> \"{vc['credentialSubject']['name']}\" .",
            f"{s} <{RDF_TYPE}> <{CRED_NS}VerifiableCredential> .",
            f"{s} <{CRED_NS}credentialSubject> {sub} .",
            f"{s} <{CRED_NS}issuanceDate> \"{vc['issuanceDate']}\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .",
            f"{s} <{CRED_NS}issuer> <{vc['issuer']}> .",
        ]
        quads.sort()
        return ('\n'.join(quads) + '\n').encode()

    priv2 = ed25519.Ed25519PrivateKey.generate()
    pub2 = priv2.public_key()
    bench('jsonld/nolib/sign', N,
          lambda: priv2.sign(hashlib.sha256(inline_norm()).digest()))
    sig1 = priv2.sign(hashlib.sha256(inline_norm()).digest())
    bench('jsonld/nolib/verify', N,
          lambda: pub2.verify(sig1, hashlib.sha256(inline_norm()).digest()))


# ── JSON-LD VC (JCS / RFC 8785) ──────────────────────────────────
def run_jcs():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    doc = {
        '@context': {'@version': 1.1, 'id': '@id', 'type': '@type'},
        'type': 'VerifiableCredential', 'issuer': 'https://example.com',
        'issuanceDate': '2024-01-01T00:00:00Z', 'credentialSubject': SUBJECT,
    }
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    bench('jsonld-jcs/nolib/sign', N,
          lambda: priv.sign(hashlib.sha256(jcs_canonical(doc).encode()).digest()))
    sig0 = priv.sign(hashlib.sha256(jcs_canonical(doc).encode()).digest())
    bench('jsonld-jcs/nolib/verify', N,
          lambda: pub.verify(sig0, hashlib.sha256(jcs_canonical(doc).encode()).digest()))


# ── mdoc (CBOR/COSE + ECDSA P-256) ───────────────────────────────
MDOC_FIELDS = [
    ('family_name', 'Yamada'), ('given_name', 'Taro'), ('birth_date', '1990-01-01'),
    ('issue_date', '2024-01-01'), ('expiry_date', '2029-01-01'),
    ('issuing_country', 'JP'), ('document_number', 'JP-12345678'),
]


def run_mdoc():
    import cbor2
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature, encode_dss_signature)
    from cryptography.hazmat.primitives import hashes
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()

    def build_sig_struct() -> bytes:
        digest_map = {}
        for i, (k, v) in enumerate(MDOC_FIELDS):
            item = cbor2.dumps({'digestID': i, 'elementIdentifier': k, 'elementValue': v})
            digest_map[i] = hashlib.sha256(item).digest()
        prot_hdr = cbor2.dumps({1: -7})
        mso = cbor2.dumps({'docType': 'org.iso.18013.5.1.mDL', 'valueDigests': digest_map})
        return cbor2.dumps(['Signature1', prot_hdr, b'', mso])

    def sign():
        der = priv.sign(build_sig_struct(), ec.ECDSA(hashes.SHA256()))
        # COSE は raw r||s（ieee-p1363 相当）を用いる
        r, s = decode_dss_signature(der)
        _ = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    bench('mdoc/cbor2/sign', N, sign)

    ss0 = build_sig_struct()
    der0 = priv.sign(ss0, ec.ECDSA(hashes.SHA256()))
    r0, s0 = decode_dss_signature(der0)
    raw0 = r0.to_bytes(32, 'big') + s0.to_bytes(32, 'big')

    def verify():
        r = int.from_bytes(raw0[:32], 'big')
        s = int.from_bytes(raw0[32:], 'big')
        pub.verify(encode_dss_signature(r, s), ss0, ec.ECDSA(hashes.SHA256()))
    bench('mdoc/cbor2/verify', N, verify)


RUNNERS = {
    'sdjwt': run_sdjwt,
    'jsonld': run_jsonld,
    'jsonld-jcs': run_jcs,
    'mdoc': run_mdoc,
}


def lib_versions():
    from importlib.metadata import version, PackageNotFoundError
    out = {}
    for pkg in ['cryptography', 'PyLD', 'cbor2']:
        try:
            out[pkg] = version(pkg)
        except PackageNotFoundError:
            out[pkg] = 'n/a'
    return out


def main():
    targets = list(RUNNERS) if args.format == 'all' else [args.format]
    for f in targets:
        print(f'[python] format={f}', file=sys.stderr)
        RUNNERS[f]()
    result = {
        'lang': 'python',
        'format': args.format,
        'n': N, 'warmup': WARMUP,
        'env': {
            'python': platform.python_version(),
            'implementation': platform.python_implementation(),
            'platform': f'{sys.platform} {platform.machine()}',
            'osRelease': platform.release(),
            'cpu': platform.processor() or 'unknown',
            'cores': os.cpu_count(),
            'libraries': lib_versions(),
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        },
        'benches': benches,
    }
    data = json.dumps(result)
    if args.out:
        with open(args.out, 'w') as fh:
            fh.write(data)
        print(f'wrote {args.out}', file=sys.stderr)
    else:
        print(data)


if __name__ == '__main__':
    main()
