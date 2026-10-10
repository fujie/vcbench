#!/usr/bin/env python3
"""
linux-bench Python engine — signing/verification benchmarks per VC format

Measurement method:
  - every iteration is timed individually with time.perf_counter_ns() (ns precision)
  - warmup iterations precede the measured run
  - no statistics are computed here; raw timings (ns) are emitted (../aggregate.mjs aggregates them)

Usage:
  python3 bench.py --format sdjwt|jsonld|jsonld-jcs|mdoc|all \
                   [--n 2000] [--warmup 50] [--out results.json]

Dependencies: pip install -r requirements.txt  (cryptography, PyLD, cbor2)
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
                    choices=['sdjwt', 'jsonld', 'jsonld-jcs', 'mdoc', 'primitives', 'all'])
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
    """Lexical canonicalization equivalent to RFC 8785 (this benchmark uses ASCII/simple types only)."""
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

    # noLib: inline N-Quads
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
        # COSE uses raw r||s (equivalent to ieee-p1363)
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


def run_primitives():
    """Cryptographic primitive baseline.

    The per-format benchmarks mix a signature algorithm with a serialization
    pipeline. Measuring the primitives alone lets a cross-language difference
    be attributed to one or the other instead of being left as a conjecture.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519, ec
    from cryptography.hazmat.primitives import hashes

    msg = b'a' * 256

    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()
    ed_sig = ed_priv.sign(msg)
    bench('prim/ed25519/sign', args.n, lambda: ed_priv.sign(msg))
    bench('prim/ed25519/verify', args.n, lambda: ed_pub.verify(ed_sig, msg))

    ec_priv = ec.generate_private_key(ec.SECP256R1())
    ec_pub = ec_priv.public_key()
    ec_sig = ec_priv.sign(msg, ec.ECDSA(hashes.SHA256()))
    bench('prim/p256/sign', args.n, lambda: ec_priv.sign(msg, ec.ECDSA(hashes.SHA256())))
    bench('prim/p256/verify', args.n, lambda: ec_pub.verify(ec_sig, msg, ec.ECDSA(hashes.SHA256())))

    bench('prim/sha256', args.n, lambda: hashlib.sha256(msg).digest())


RUNNERS = {
    'sdjwt': run_sdjwt,
    'jsonld': run_jsonld,
    'jsonld-jcs': run_jcs,
    'mdoc': run_mdoc,
    'primitives': run_primitives,
}


def lib_versions():
    """Package versions, plus the OpenSSL that `cryptography` bundles.

    The bundled OpenSSL matters: between cryptography 49.0.0 and 50.0.2 the
    Ed25519 signature primitive changed by a factor of three on macOS/arm64
    while the Python version made under 1% difference, so a result file that
    records only the Python version cannot be compared against another.
    """
    from importlib.metadata import version, PackageNotFoundError
    out = {}
    for pkg in ['cryptography', 'PyLD', 'cbor2']:
        try:
            out[pkg] = version(pkg)
        except PackageNotFoundError:
            out[pkg] = 'n/a'
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        out['openssl'] = backend.openssl_version_text()
    except Exception:
        try:
            import ssl
            out['openssl'] = ssl.OPENSSL_VERSION
        except Exception:
            out['openssl'] = 'n/a'
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
