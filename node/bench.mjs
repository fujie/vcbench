#!/usr/bin/env node
/**
 * linux-bench Node.js engine — signing/verification benchmarks per VC format
 *
 * Measurement method (identical to the methodology of the paper):
 *   - every iteration is timed individually with process.hrtime.bigint() (ns precision)
 *   - warmup iterations precede the measured run
 *   - no statistics are computed here; raw timings (ns) are emitted (../aggregate.mjs aggregates them)
 *
 * Usage:
 *   node bench.mjs --format <FORMAT> [--n 2000] [--warmup 50] [--out results.json]
 *
 * FORMAT:
 *   sdjwt | jsonld | jsonld-jcs | mdoc   basic signing/verification (suite shared by all languages)
 *   jsonld-complex                       canonicalization of OB3 / DCC / synthetic blank-node credentials
 *   breakdown                            breakdown of the JSON-LD signing pipeline
 *   serial                               serialization speed, no cryptography
 *   scaling                              attribute-count scaling
 *   seldisc                              selective disclosure
 *   unified                              Ed25519-unified benchmark
 *   e2e                                  end-to-end issue -> present (5 of 20 disclosed) -> verify
 *   all                                  all of the above
 */
import crypto from 'node:crypto'
import os from 'node:os'
import fs from 'node:fs'
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)

// jose v6 assumes a global crypto object (WebCrypto).
// Node versions older than 19 do not define it globally, so polyfill with node:crypto.webcrypto.
if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = crypto.webcrypto
}
const NODE_MAJOR = Number(process.versions.node.split('.')[0])
if (NODE_MAJOR < 20) {
  process.stderr.write(
    `WARN: detected Node ${process.version}. The paper measurements used Node v22.x. ` +
    `Node 22 or later is recommended so that results remain comparable (nvm install 22).\n`)
}

// ── CLI ──────────────────────────────────────────────────────────
const args = {}
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, '')] = process.argv[i + 1]
const FORMAT = args.format ?? 'all'
const N = Number(args.n ?? 2000)
const WARMUP = Number(args.warmup ?? 50)
const OUT = args.out ?? null

const benches = {}
const meta = {}   // side information such as payload sizes (aggregate copies it into the summary)

function bench(key, n, fn) {
  for (let i = 0; i < WARMUP; i++) fn()
  const t = new Array(n)
  for (let i = 0; i < n; i++) {
    const s = process.hrtime.bigint()
    fn()
    t[i] = Number(process.hrtime.bigint() - s)
  }
  benches[key] = { n, warmup: WARMUP, timings_ns: t }
  process.stderr.write(`  ${key}: done (n=${n})\n`)
}

async function benchAsync(key, n, fn) {
  for (let i = 0; i < WARMUP; i++) await fn()
  const t = new Array(n)
  for (let i = 0; i < n; i++) {
    const s = process.hrtime.bigint()
    await fn()
    t[i] = Number(process.hrtime.bigint() - s)
  }
  benches[key] = { n, warmup: WARMUP, timings_ns: t }
  process.stderr.write(`  ${key}: done (n=${n})\n`)
}

const b64url = (buf) => Buffer.from(buf).toString('base64url')
const CRED_NS = 'https://www.w3.org/2018/credentials#'
const RDF_TYPE = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'

function jcsCanonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(jcsCanonical).join(',') + ']'
  return '{' + Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${jcsCanonical(v[k])}`).join(',') + '}'
}

// shared credential (same payload as in the paper's methodology)
const SUBJECT = { id: 'did:example:1', name: 'Taro Yamada' }
const VC_CONTEXT = [{
  '@version': 1.1, type: '@type', id: '@id',
  VerifiableCredential: `${CRED_NS}VerifiableCredential`,
  issuer: { '@id': `${CRED_NS}issuer`, '@type': '@id' },
  issuanceDate: { '@id': `${CRED_NS}issuanceDate`, '@type': 'http://www.w3.org/2001/XMLSchema#dateTime' },
  credentialSubject: `${CRED_NS}credentialSubject`,
  name: 'http://schema.org/name',
}]
const VC_DOC = {
  '@context': VC_CONTEXT,
  type: 'VerifiableCredential',
  issuer: 'https://example.com',
  issuanceDate: '2024-01-01T00:00:00Z',
  credentialSubject: SUBJECT,
}

// ── shared helpers for Data Integrity (eddsa-rdfc-2022 / ecdsa-rdfc-2019) ──
// The cryptosuite does NOT sign the canonicalized document directly. It
// canonicalizes the document and the proof options separately and signs
// sha256(proofOptionsNQuads) || sha256(documentNQuads) — 64 bytes. Measuring
// only one canonicalization understates the cost of the suite, so both are
// included here and in the end-to-end suite.
const RDFC_OPTS = { algorithm: 'URDNA2015', format: 'application/n-quads', safe: false }
const sha256b = (b) => crypto.createHash('sha256').update(b).digest()
const SEC_NS = 'https://w3id.org/security#'
// The proof-options context is embedded locally, like every other context in
// this kit, so that no network retrieval occurs during measurement.
const DI_PROOF_CTX = [{
  '@version': 1.1, type: '@type', id: '@id',
  DataIntegrityProof: `${SEC_NS}DataIntegrityProof`,
  cryptosuite: `${SEC_NS}cryptosuite`,
  created: { '@id': 'http://purl.org/dc/terms/created', '@type': 'http://www.w3.org/2001/XMLSchema#dateTime' },
  verificationMethod: { '@id': `${SEC_NS}verificationMethod`, '@type': '@id' },
  proofPurpose: { '@id': `${SEC_NS}proofPurpose`, '@type': '@vocab' },
  assertionMethod: `${SEC_NS}assertionMethod`,
}]
const diProofOptions = (cryptosuite) => ({
  '@context': DI_PROOF_CTX,
  type: 'DataIntegrityProof',
  cryptosuite,
  created: '2024-01-01T00:00:00Z',
  verificationMethod: 'did:example:issuer#key-1',
  proofPurpose: 'assertionMethod',
})
// hashData = sha256(canonical proof options) || sha256(canonical document)
async function diHashData(jsonld, doc, proofOptions) {
  const [proofNQ, docNQ] = await Promise.all([
    jsonld.normalize(proofOptions, RDFC_OPTS),
    jsonld.normalize(doc, RDFC_OPTS),
  ])
  return Buffer.concat([sha256b(Buffer.from(proofNQ)), sha256b(Buffer.from(docNQ))])
}

// ── SD-JWT VC ────────────────────────────────────────────────────
async function runSdJwt() {
  // stdcrypto: node:crypto directly (the "common to with/without library" implementation of the paper)
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519')
  const header = b64url(Buffer.from(JSON.stringify({ alg: 'EdDSA', crv: 'Ed25519' })))
  const payload = b64url(Buffer.from(JSON.stringify({ iss: 'https://issuer.example.com', vct: 'identity', sub: 'did:example:holder' })))
  const sigInput = `${header}.${payload}`
  bench('sdjwt/stdcrypto/sign', N, () => {
    const s = crypto.sign(null, Buffer.from(sigInput), privateKey)
    void `${sigInput}.${b64url(s)}`
  })
  const token = `${sigInput}.${b64url(crypto.sign(null, Buffer.from(sigInput), privateKey))}`
  bench('sdjwt/stdcrypto/verify', N, () => {
    const p = token.split('.')
    crypto.verify(null, Buffer.from(`${p[0]}.${p[1]}`), publicKey, Buffer.from(p[2], 'base64url'))
  })

  // jose: full JWT pipeline (reference value)
  const { SignJWT, jwtVerify } = await import('jose')
  const kp = crypto.generateKeyPairSync('ed25519')
  const claims = { iss: 'https://issuer.example.com', vct: 'identity', sub: 'did:example:holder' }
  let joseToken = ''
  await benchAsync('sdjwt/jose/sign', N, async () => {
    joseToken = await new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA' }).sign(kp.privateKey)
  })
  await benchAsync('sdjwt/jose/verify', N, async () => {
    await jwtVerify(joseToken, kp.publicKey)
  })
}

// ── W3C VCDM 2.0 + Data Integrity (eddsa-rdfc-2022, RDFC-1.0) ───
async function runJsonLd() {
  const jsonld = (await import('jsonld')).default
  const { privateKey } = crypto.generateKeyPairSync('ed25519')
  const publicKey = crypto.createPublicKey(privateKey)
  const proofOptions = diProofOptions('eddsa-rdfc-2022')
  const hashData = () => diHashData(jsonld, VC_DOC, proofOptions)

  await benchAsync('jsonld/jsonld-lib/sign', N, async () => {
    crypto.sign(null, await hashData(), privateKey)
  })
  const sig0 = crypto.sign(null, await hashData(), privateKey)
  await benchAsync('jsonld/jsonld-lib/verify', N, async () => {
    if (!crypto.verify(null, await hashData(), publicKey, sig0)) throw new Error('verify failed')
  })
  // the canonicalization of the document alone, for the breakdown in the paper
  await benchAsync('jsonld/jsonld-lib/normalize-only', N, async () => {
    await jsonld.normalize(VC_DOC, RDFC_OPTS)
  })
  // both canonicalizations, i.e. everything the suite does before hashing
  await benchAsync('jsonld/jsonld-lib/normalize-both', N, async () => {
    await jsonld.normalize(proofOptions, RDFC_OPTS)
    await jsonld.normalize(VC_DOC, RDFC_OPTS)
  })

  // noLib: statically expanded N-Quads. This is NOT a faster canonicalizer; it
  // is the same pipeline with canonicalization removed, and is reported only as
  // a lower bound on what the rest of the pipeline costs.
  const vc = { issuer: 'https://example.com', issuanceDate: '2024-01-01T00:00:00Z', credentialSubject: SUBJECT }
  const inlineNorm = () => {
    const s = '_:c14n0', sub = `<${vc.credentialSubject.id}>`
    const quads = [
      `${sub} <http://schema.org/name> "${vc.credentialSubject.name}" .`,
      `${s} <${RDF_TYPE}> <${CRED_NS}VerifiableCredential> .`,
      `${s} <${CRED_NS}credentialSubject> ${sub} .`,
      `${s} <${CRED_NS}issuanceDate> "${vc.issuanceDate}"^^<http://www.w3.org/2001/XMLSchema#dateTime> .`,
      `${s} <${CRED_NS}issuer> <${vc.issuer}> .`,
    ]
    quads.sort()
    return Buffer.from(quads.join('\n') + '\n', 'utf8')
  }
  const kp2 = crypto.generateKeyPairSync('ed25519')
  const pub2 = crypto.createPublicKey(kp2.privateKey)
  bench('jsonld/nolib/sign', N, () => {
    crypto.sign(null, sha256b(inlineNorm()), kp2.privateKey)
  })
  const sig1 = crypto.sign(null, sha256b(inlineNorm()), kp2.privateKey)
  bench('jsonld/nolib/verify', N, () => {
    if (!crypto.verify(null, sha256b(inlineNorm()), pub2, sig1)) throw new Error('verify failed')
  })
}

// ── JSON-LD VC (JCS / RFC 8785) ──────────────────────────────────
async function runJcs() {
  const canonicalize = (await import('canonicalize')).default
  const doc = {
    '@context': { '@version': 1.1, id: '@id', type: '@type' },
    type: 'VerifiableCredential', issuer: 'https://example.com',
    issuanceDate: '2024-01-01T00:00:00Z', credentialSubject: SUBJECT,
  }
  const { privateKey } = crypto.generateKeyPairSync('ed25519')
  const publicKey = crypto.createPublicKey(privateKey)
  bench('jsonld-jcs/canonicalize-lib/sign', N, () => {
    crypto.sign(null, crypto.createHash('sha256').update(canonicalize(doc)).digest(), privateKey)
  })
  const sig0 = crypto.sign(null, crypto.createHash('sha256').update(canonicalize(doc)).digest(), privateKey)
  bench('jsonld-jcs/canonicalize-lib/verify', N, () => {
    crypto.verify(null, crypto.createHash('sha256').update(canonicalize(doc)).digest(), publicKey, sig0)
  })
  bench('jsonld-jcs/nolib/sign', N, () => {
    crypto.sign(null, crypto.createHash('sha256').update(jcsCanonical(doc)).digest(), privateKey)
  })
  const sig1 = crypto.sign(null, crypto.createHash('sha256').update(jcsCanonical(doc)).digest(), privateKey)
  bench('jsonld-jcs/nolib/verify', N, () => {
    crypto.verify(null, crypto.createHash('sha256').update(jcsCanonical(doc)).digest(), publicKey, sig1)
  })
}

// ── mdoc (ISO/IEC 18013-5, CBOR/COSE + ECDSA P-256) ─────────────
const MDOC_FIELDS = [
  ['family_name', 'Yamada'], ['given_name', 'Taro'], ['birth_date', '1990-01-01'],
  ['issue_date', '2024-01-01'], ['expiry_date', '2029-01-01'],
  ['issuing_country', 'JP'], ['document_number', 'JP-12345678'],
]
const MDOC_NS = 'org.iso.18013.5.1'

async function runMdoc() {
  const { encode: cborEncode, decode: cborDecode } = await import('cbor-x')
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })

  // IssuerSignedItem carries a random salt of at least 16 bytes (ISO/IEC
  // 18013-5 9.1.2.5) so that an undisclosed element cannot be recovered from
  // its digest; the MSO carries version, digestAlgorithm and validityInfo.
  const buildIssued = () => {
    const items = MDOC_FIELDS.map(([k, v], i) => ({
      digestID: i, random: crypto.randomBytes(16), elementIdentifier: k, elementValue: v,
    }))
    const encoded = items.map((it) => cborEncode(it))
    const digests = Object.fromEntries(items.map((it, i) => [it.digestID, sha256b(encoded[i])]))
    const mso = cborEncode({
      version: '1.0', digestAlgorithm: 'SHA-256', docType: `${MDOC_NS}.mDL`,
      valueDigests: { [MDOC_NS]: digests },
      validityInfo: { signed: '2024-01-01T00:00:00Z', validFrom: '2024-01-01T00:00:00Z', validUntil: '2029-01-01T00:00:00Z' },
    })
    const protectedHdr = cborEncode({ 1: -7 })
    const sigStruct = cborEncode(['Signature1', protectedHdr, Buffer.alloc(0), mso])
    const sig = crypto.sign('sha256', sigStruct, { key: privateKey, dsaEncoding: 'ieee-p1363' })
    return cborEncode({
      docType: `${MDOC_NS}.mDL`,
      issuerSigned: { nameSpaces: { [MDOC_NS]: encoded }, issuerAuth: [protectedHdr, {}, mso, sig] },
    })
  }

  // Verification follows ISO/IEC 18013-5 9.3.1: decode, verify COSE_Sign1 over
  // the reconstructed Sig_structure, then match each element's digest against
  // the MSO by digestID. Matching by position would break on a disclosed subset.
  const verifyMdoc = (bytes) => {
    const doc = cborDecode(bytes)
    const [protectedHdr, , mso, sig] = doc.issuerSigned.issuerAuth
    const sigStruct = cborEncode(['Signature1', protectedHdr, Buffer.alloc(0), mso])
    if (!crypto.verify('sha256', sigStruct, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sig)) {
      throw new Error('COSE_Sign1 signature verification failed')
    }
    const digests = cborDecode(mso).valueDigests[MDOC_NS]
    for (const enc of doc.issuerSigned.nameSpaces[MDOC_NS]) {
      const it = cborDecode(enc)
      if (!Buffer.from(digests[it.digestID]).equals(sha256b(Buffer.from(enc)))) {
        throw new Error('digest mismatch')
      }
    }
    return true
  }

  bench('mdoc/cbor-x/sign', N, () => { buildIssued() })
  const issued = buildIssued()
  bench('mdoc/cbor-x/verify', N, () => { verifyMdoc(issued) })
  meta['mdoc/cbor-x/bytes'] = issued.length

  // noLib: hand-written CBOR encoder for the signing side. The verification
  // side is not reimplemented by hand; cbor-x is used for decoding in both.
  const cborUint = (n) => n <= 23 ? Buffer.from([n]) : n <= 0xff ? Buffer.from([0x18, n]) : Buffer.from([0x19, (n >> 8) & 0xff, n & 0xff])
  const cborNeg = (n) => { const x = -1 - n; return x <= 23 ? Buffer.from([0x20 | x]) : Buffer.from([0x38, x]) }
  const cborText = (s) => { const b = Buffer.from(s, 'utf8'); const h = b.length <= 23 ? Buffer.from([0x60 | b.length]) : Buffer.from([0x78, b.length]); return Buffer.concat([h, b]) }
  const cborBytes = (b) => { const buf = Buffer.from(b); const h = buf.length <= 23 ? Buffer.from([0x40 | buf.length]) : Buffer.from([0x58, buf.length]); return Buffer.concat([h, buf]) }
  const cborMap = (...pairs) => Buffer.concat([pairs.length / 2 <= 23 ? Buffer.from([0xa0 | (pairs.length / 2)]) : Buffer.from([0xb8, pairs.length / 2]), ...pairs])
  const cborArray = (...items) => Buffer.concat([items.length <= 23 ? Buffer.from([0x80 | items.length]) : Buffer.from([0x98, items.length]), ...items])
  const protHdr = cborMap(cborUint(1), cborNeg(-7))
  const buildSigStructManual = () => {
    const digestMap = []
    for (let i = 0; i < MDOC_FIELDS.length; i++) {
      const [k, v] = MDOC_FIELDS[i]
      const item = cborMap(
        cborText('digestID'), cborUint(i),
        cborText('random'), cborBytes(crypto.randomBytes(16)),
        cborText('elementIdentifier'), cborText(k),
        cborText('elementValue'), cborText(v))
      digestMap.push(cborUint(i), cborBytes(sha256b(item)))
    }
    const msoPayload = cborMap(
      cborText('version'), cborText('1.0'),
      cborText('digestAlgorithm'), cborText('SHA-256'),
      cborText('docType'), cborText(`${MDOC_NS}.mDL`),
      cborText('valueDigests'), cborMap(...digestMap))
    return cborArray(cborText('Signature1'), cborBytes(protHdr), cborBytes(Buffer.alloc(0)), cborBytes(msoPayload))
  }
  bench('mdoc/nolib/sign', N, () => {
    crypto.sign('sha256', buildSigStructManual(), { key: privateKey, dsaEncoding: 'ieee-p1363' })
  })
  const ss1 = buildSigStructManual()
  const sig1 = crypto.sign('sha256', ss1, { key: privateKey, dsaEncoding: 'ieee-p1363' })
  bench('mdoc/nolib/verify', N, () => {
    if (!crypto.verify('sha256', ss1, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sig1)) {
      throw new Error('verify failed')
    }
  })
}

// ── JSON-LD complex credentials (OB3 / DCC / synthetic) — Node only ──────
async function runJsonLdComplex() {
  const jsonld = (await import('jsonld')).default
  const obCtx = await import('@digitalcredentials/open-badges-context')
  const ob = obCtx.default ?? obCtx
  const ccCtx = await import('@digitalbazaar/credentials-context')
  const cc = ccCtx.default ?? ccCtx
  const map = new Map()
  for (const [url, doc] of ob.contexts) map.set(url, doc)
  for (const [url, doc] of cc.contexts) map.set(url, doc)
  const loader = (url) => {
    const doc = map.get(url)
    if (!doc) throw new Error(`Context not embedded: ${url}`)
    return { contextUrl: null, document: doc, documentUrl: url }
  }
  const OB_URL = ob.CONTEXT_URL_V3_0_3

  const ob3 = {
    '@context': ['https://www.w3.org/ns/credentials/v2', OB_URL],
    id: 'urn:uuid:a63a60be-f4af-491c-87fc-2c8fd3007a58',
    type: ['VerifiableCredential', 'OpenBadgeCredential'],
    issuer: { id: 'https://university.example/issuers/565049', type: ['Profile'], name: 'Example University', url: 'https://university.example', email: 'registrar@university.example' },
    validFrom: '2026-01-01T00:00:00Z',
    name: 'Digital Credentials Achievement',
    credentialSubject: {
      id: 'did:example:ebfeb1f712ebc6f1c276e12ec21', type: ['AchievementSubject'],
      achievement: {
        id: 'https://university.example/achievements/degree-cs', type: ['Achievement'],
        name: 'Bachelor of Science in Computer Science',
        description: 'Awarded for the successful completion of the undergraduate program in Computer Science.',
        criteria: { type: 'Criteria', narrative: 'Completion of 124 credit hours including the capstone project, with a cumulative GPA of 2.0 or higher.' },
        alignment: [
          { type: ['Alignment'], targetName: 'CS Curriculum Standard', targetUrl: 'https://credentialengineregistry.org/resources/ce-6369c51f', targetType: 'ceterms:Certification' },
          { type: ['Alignment'], targetName: 'European Qualifications Framework Level 6', targetUrl: 'https://europa.eu/europass/eqf/6', targetType: 'ceterms:QualityAssuranceCredential' },
        ],
      },
      result: [{ type: ['Result'], value: '3.7', status: 'Completed' }],
    },
  }
  const dcc = {
    '@context': ['https://www.w3.org/ns/credentials/v2', OB_URL],
    id: 'urn:uuid:2fe53dc9-b2ec-4939-9b2c-0d00f6663b6c',
    type: ['VerifiableCredential', 'OpenBadgeCredential'],
    issuer: { id: 'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC', type: ['Profile'], name: 'DCC Test Issuer', url: 'https://digitalcredentials.mit.edu', image: { id: 'https://certificates.cs50.io/static/success.jpg', type: 'Image' } },
    validFrom: '2026-01-01T00:00:00Z',
    name: 'Successful Installation',
    credentialSubject: {
      type: ['AchievementSubject'], name: 'Me!',
      achievement: { id: 'urn:uuid:bd6d9316-f7ae-4073-a1e5-2f7f5bd22922', type: ['Achievement'], achievementType: 'Diploma', name: 'Your Installation', description: 'This badge certifies the successful installation of the DCC issuer.', criteria: { type: 'Criteria', narrative: 'Successfully installed the DCC issuer and issued a test credential.' } },
    },
  }
  const synth = (bn) => ({
    '@context': [{ '@version': 1.1, id: '@id', type: '@type', '@vocab': 'https://example.com/vocab#',
      VerifiableCredential: `${CRED_NS}VerifiableCredential`,
      issuer: { '@id': `${CRED_NS}issuer`, '@type': '@id' },
      credentialSubject: `${CRED_NS}credentialSubject` }],
    id: 'urn:example:cred:synthetic', type: 'VerifiableCredential', issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:sub', evidence: Array.from({ length: bn }, (_, i) => ({ type: 'Evidence', narrative: `evidence item ${i}`, weight: String(i) })) },
  })

  const docs = {
    'jsonld-complex/simple/normalize': { doc: VC_DOC, n: Math.max(Math.floor(N / 2), 50), opts: {} },
    'jsonld-complex/ob3/normalize': { doc: ob3, n: Math.max(Math.floor(N / 10), 20), opts: { documentLoader: loader } },
    'jsonld-complex/dcc/normalize': { doc: dcc, n: Math.max(Math.floor(N / 10), 20), opts: { documentLoader: loader } },
    'jsonld-complex/synth-bn10/normalize': { doc: synth(10), n: Math.max(Math.floor(N / 2), 50), opts: {} },
    'jsonld-complex/synth-bn50/normalize': { doc: synth(50), n: Math.max(Math.floor(N / 10), 20), opts: {} },
  }
  for (const [key, { doc, n, opts }] of Object.entries(docs)) {
    await benchAsync(key, n, async () => {
      await jsonld.normalize(doc, { algorithm: 'URDNA2015', format: 'application/n-quads', safe: false, ...opts })
    })
  }
}

// ── shared helpers for the auxiliary suites ──────────────────────────────
function makeAttrs(n) {
  const attrs = {}
  for (let i = 0; i < n; i++) attrs[`attr_${String(i).padStart(3, '0')}`] = `value_${String(i).padStart(3, '0')}`
  return attrs
}
const VOCAB = 'https://example.com/vocab#'
const ntLit = (s) => JSON.stringify(s)
function attrNormalize(credId, issuerId, subjectId, attrs) {
  const quads = []
  quads.push(`<${credId}> <${RDF_TYPE}> <${CRED_NS}VerifiableCredential> .`)
  quads.push(`<${credId}> <${CRED_NS}issuer> <${issuerId}> .`)
  quads.push(`<${credId}> <${CRED_NS}credentialSubject> <${subjectId}> .`)
  for (const [k, v] of Object.entries(attrs)) quads.push(`<${subjectId}> <${VOCAB}${k}> ${ntLit(v)} .`)
  return quads.sort().join('\n') + '\n'
}

// ── breakdown: JSON-LD signing pipeline breakdown ────────────────────────
async function runBreakdown() {
  const jsonld = (await import('jsonld')).default
  const { privateKey } = crypto.generateKeyPairSync('ed25519')
  const opts = { algorithm: 'URDNA2015', format: 'application/n-quads', safe: false }
  await benchAsync('breakdown/normalize', N, async () => { await jsonld.normalize(VC_DOC, opts) })
  const nq = await jsonld.normalize(VC_DOC, opts)
  const hashInput = Buffer.from(nq)
  bench('breakdown/hash', N, () => {
    crypto.createHash('sha256').update(hashInput).digest()
  })
  const hash0 = crypto.createHash('sha256').update(hashInput).digest()
  bench('breakdown/sign', N, () => {
    crypto.sign(null, hash0, privateKey)
  })
  // full pipeline (for comparison with the sum of the individual steps)
  await benchAsync('breakdown/full-pipeline-sign', N, async () => {
    const norm = await jsonld.normalize(VC_DOC, opts)
    crypto.sign(null, crypto.createHash('sha256').update(norm).digest(), privateKey)
  })
}

// ── serial: serialization speed, no cryptographic processing ─────────────
async function runSerial() {
  const jsonld = (await import('jsonld')).default
  const { encode: cborEncode, decode: cborDecode } = await import('cbor-x')
  const canonicalize = (await import('canonicalize')).default

  // SD-JWT VC: encode/decode
  const sdPayload = {
    iss: 'https://issuer.example.com', iat: 0, exp: 3600,
    vct: 'https://credentials.example.com/identity', sub: 'did:example:holder123',
    given_name: 'Taro', family_name: 'Yamada', birthdate: '1990-01-01',
  }
  const sdHeader = b64url(Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'vc+sd-jwt' })))
  bench('serial/sdjwt/encode', N, () => {
    void `${sdHeader}.${b64url(Buffer.from(JSON.stringify(sdPayload)))}.AAABBB`
  })
  const sdToken = `${sdHeader}.${b64url(Buffer.from(JSON.stringify(sdPayload)))}.AAABBB`
  meta['serial/sdjwt/payloadBytes'] = sdToken.length
  bench('serial/sdjwt/decode', N, () => {
    const [h64, p64] = sdToken.split('.')
    JSON.parse(Buffer.from(h64, 'base64url').toString())
    JSON.parse(Buffer.from(p64, 'base64url').toString())
  })

  // JSON-LD VC: encode/decode + URDNA2015 normalize (jsonld library)
  const jldStr = JSON.stringify(VC_DOC)
  bench('serial/jsonld/encode', N, () => { JSON.stringify(VC_DOC) })
  bench('serial/jsonld/decode', N, () => { JSON.parse(jldStr) })
  const nOpts = { algorithm: 'URDNA2015', format: 'application/n-quads', safe: false }
  await benchAsync('serial/jsonld/normalize-lib', N, async () => { await jsonld.normalize(VC_DOC, nOpts) })
  meta['serial/jsonld/normalizedBytes'] = Buffer.byteLength(await jsonld.normalize(VC_DOC, nOpts))

  // JCS canonicalize
  bench('serial/jsonld-jcs/canonicalize', N, () => { jcsCanonical(VC_DOC) })
  bench('serial/jsonld-jcs/canonicalize-lib', N, () => { canonicalize(VC_DOC) })
  meta['serial/jsonld-jcs/canonicalBytes'] = Buffer.byteLength(jcsCanonical(VC_DOC))

  // mdoc: cbor-x encode/decode
  const mdocLibDoc = {
    docType: 'org.iso.18013.5.1.mDL',
    items: MDOC_FIELDS.map(([k, v], i) => ({ digestID: i, elementIdentifier: k, elementValue: v })),
  }
  const mdocEncoded = cborEncode(mdocLibDoc)
  meta['serial/mdoc/payloadBytes'] = mdocEncoded.length
  bench('serial/mdoc/encode', N, () => { cborEncode(mdocLibDoc) })
  bench('serial/mdoc/decode', N, () => { cborDecode(mdocEncoded) })
}

// ── scaling: attribute-count scaling ─────────────────────────────────────
async function runScaling() {
  const jsonld = (await import('jsonld')).default
  const { encode: cborEncode } = await import('cbor-x')
  for (const size of [5, 20, 100, 500]) {
    const attrs = makeAttrs(size)
    const attrEntries = Object.entries(attrs)

    const sdHeader = b64url(Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'vc+sd-jwt' })))
    const sdPayload = { iss: 'did:example:issuer', sub: 'did:example:sub', ...attrs }
    bench(`scaling/sdjwt/${size}`, N, () => {
      void `${sdHeader}.${b64url(Buffer.from(JSON.stringify(sdPayload)))}.SIG`
    })
    meta[`scaling/sdjwt/${size}/payloadBytes`] = `${sdHeader}.${b64url(Buffer.from(JSON.stringify(sdPayload)))}.SIG`.length

    const vcDoc = {
      '@context': [{ '@version': 1.1, id: '@id', type: '@type', '@vocab': VOCAB,
        VerifiableCredential: `${CRED_NS}VerifiableCredential`,
        issuer: { '@id': `${CRED_NS}issuer`, '@type': '@id' },
        credentialSubject: `${CRED_NS}credentialSubject` }],
      id: 'urn:example:cred:scaling', type: 'VerifiableCredential',
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:sub', ...attrs },
    }
    const nOpts = { algorithm: 'URDNA2015', format: 'application/n-quads', safe: false }
    const nJld = size >= 100 ? Math.max(Math.floor(N / 5), 20) : N
    await benchAsync(`scaling/jsonld/${size}`, nJld, async () => { await jsonld.normalize(vcDoc, nOpts) })
    meta[`scaling/jsonld/${size}/payloadBytes`] = Buffer.byteLength(await jsonld.normalize(vcDoc, nOpts))

    bench(`scaling/jsonld-jcs/${size}`, N, () => { jcsCanonical(vcDoc) })
    meta[`scaling/jsonld-jcs/${size}/payloadBytes`] = Buffer.byteLength(jcsCanonical(vcDoc))

    const mdocDoc = {
      docType: 'org.iso.18013.5.1.mDL',
      items: attrEntries.map(([k, v], i) => ({ digestID: i, elementIdentifier: k, elementValue: v })),
    }
    bench(`scaling/mdoc/${size}`, N, () => { cborEncode(mdocDoc) })
    meta[`scaling/mdoc/${size}/payloadBytes`] = cborEncode(mdocDoc).length
  }
}

// ── seldisc: selective disclosure ────────────────────────────────────────
async function runSelDisc() {
  const { encode: cborEncode } = await import('cbor-x')
  const TOTAL = 20
  const attrs = makeAttrs(TOTAL)
  const attrEntries = Object.entries(attrs)
  const CRED_ID = 'urn:example:cred:seldisc'
  const ISSUER_ID = 'did:example:issuer'
  const SUBJ_ID = 'did:example:subject:001'

  const makeDisclosure = (key, value) => {
    const salt = b64url(crypto.randomBytes(16))
    const disclosure = b64url(Buffer.from(JSON.stringify([salt, key, value])))
    const hash = b64url(crypto.createHash('sha256').update(disclosure).digest())
    return { hash, disclosure, key }
  }
  const allDisclosures = attrEntries.map(([k, v]) => makeDisclosure(k, v))
  const allMdocItems = attrEntries.map(([k, v], idx) =>
    cborEncode(new Map([['digestID', idx], ['random', new Uint8Array(8)], ['elementIdentifier', k], ['elementValue', v]])))

  for (const n of [1, 3, 5, 10, 20]) {
    const hidden = allDisclosures.slice(n)
    const revealed = allDisclosures.slice(0, n)
    bench(`seldisc/sdjwt/${n}of${TOTAL}`, N, () => {
      const payload = {
        iss: ISSUER_ID, vct: 'https://example.com/vc',
        _sd: hidden.map(d => d.hash),
        ...Object.fromEntries(revealed.map(d => [d.key, attrs[d.key]])),
      }
      const hdr = b64url('{"alg":"EdDSA","typ":"vc+sd-jwt"}')
      const pay = b64url(Buffer.from(JSON.stringify(payload)))
      void `${hdr}.${pay}.FAKESIG~${revealed.map(d => d.disclosure).join('~')}`
    })

    const selectedItems = allMdocItems.slice(0, n)
    const NS_MDL = 'org.iso.18013.5.1'
    bench(`seldisc/mdoc/${n}of${TOTAL}`, N, () => {
      cborEncode(new Map([
        ['docType', 'org.iso.18013.5.1.mDL'],
        ['issuerSigned', new Map([
          ['nameSpaces', new Map([[NS_MDL, selectedItems]])],
          ['issuerAuth', [new Uint8Array([0xa1, 0x01, 0x26]), new Map(), new Uint8Array(16), new Uint8Array(64)]],
        ])],
      ]))
    })

    const revealedAttrs = Object.fromEntries(attrEntries.slice(0, n))
    bench(`seldisc/jsonld/${n}of${TOTAL}`, N, () => {
      attrNormalize(CRED_ID, ISSUER_ID, SUBJ_ID, revealedAttrs)
    })

    const jcsDoc = {
      '@context': ['https://www.w3.org/2018/credentials/v1', { '@vocab': VOCAB }],
      id: CRED_ID, type: ['VerifiableCredential'], issuer: ISSUER_ID,
      credentialSubject: { id: SUBJ_ID, ...revealedAttrs },
    }
    bench(`seldisc/jsonld-jcs/${n}of${TOTAL}`, N, () => { jcsCanonical(jcsDoc) })
  }
}

// ── unified: Ed25519-unified benchmark ───────────────────────────────────
async function runUnified() {
  const jsonld = (await import('jsonld')).default
  const { encode: cborEncode } = await import('cbor-x')
  const FIELDS = makeAttrs(5)

  // SD-JWT VC (node:crypto, same implementation level as the main benchmark, 5 attributes)
  {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519')
    const header = b64url(Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'vc+sd-jwt' })))
    const payloadB64 = b64url(Buffer.from(JSON.stringify({ iss: 'did:example:issuer', sub: 'did:example:sub', ...FIELDS })))
    const sigInput = `${header}.${payloadB64}`
    bench('unified/sdjwt/sign', N, () => {
      const s = crypto.sign(null, Buffer.from(sigInput), privateKey)
      void `${sigInput}.${b64url(s)}`
    })
    const token = `${sigInput}.${b64url(crypto.sign(null, Buffer.from(sigInput), privateKey))}`
    bench('unified/sdjwt/verify', N, () => {
      const parts = token.split('.')
      crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), publicKey, Buffer.from(parts[2], 'base64url'))
    })
  }

  // JSON-LD VC (jsonld URDNA2015 + Ed25519, 5 attributes)
  {
    const { privateKey } = crypto.generateKeyPairSync('ed25519')
    const publicKey = crypto.createPublicKey(privateKey)
    const vcDoc = {
      '@context': [{ '@version': 1.1, id: '@id', type: '@type', '@vocab': VOCAB,
        VerifiableCredential: `${CRED_NS}VerifiableCredential`,
        issuer: { '@id': `${CRED_NS}issuer`, '@type': '@id' },
        credentialSubject: `${CRED_NS}credentialSubject` }],
      type: 'VerifiableCredential', issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:sub', ...FIELDS },
    }
    const nOpts = { algorithm: 'URDNA2015', format: 'application/n-quads', safe: false }
    await benchAsync('unified/jsonld/sign', N, async () => {
      const norm = await jsonld.normalize(vcDoc, nOpts)
      crypto.sign(null, crypto.createHash('sha256').update(norm).digest(), privateKey)
    })
    const sig0 = crypto.sign(null, crypto.createHash('sha256').update(await jsonld.normalize(vcDoc, nOpts)).digest(), privateKey)
    await benchAsync('unified/jsonld/verify', N, async () => {
      const norm = await jsonld.normalize(vcDoc, nOpts)
      crypto.verify(null, crypto.createHash('sha256').update(norm).digest(), publicKey, sig0)
    })
  }

  // mdoc（cbor-x COSE_Sign1 + Ed25519, alg -8）
  {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519')
    const buildSigStruct = () => {
      const digestMap = new Map()
      let id = 0
      for (const [k, v] of Object.entries(FIELDS)) {
        const item = cborEncode({ digestID: id, elementIdentifier: k, elementValue: v })
        digestMap.set(id++, new Uint8Array(crypto.createHash('sha256').update(item).digest()))
      }
      const protHdr = cborEncode(new Map([[1, -8]])) // alg: EdDSA
      const msoPayload = cborEncode({ docType: 'org.iso.18013.5.1.mDL', valueDigests: digestMap })
      return cborEncode(['Signature1', protHdr, new Uint8Array(0), msoPayload])
    }
    bench('unified/mdoc/sign', N, () => {
      crypto.sign(null, buildSigStruct(), privateKey)
    })
    const ss0 = buildSigStruct()
    const sig0 = crypto.sign(null, ss0, privateKey)
    bench('unified/mdoc/verify', N, () => {
      crypto.verify(null, ss0, publicKey, sig0)
    })
  }
}

// ── main ─────────────────────────────────────────────────────────
// ── end-to-end: issue -> present (5 of 20 disclosed) -> verify ───
// Parameterised by signature algorithm so that the same scenario can be run
// with each format's native choice (the configuration deployments actually
// use) and with a single algorithm across all three, which separates the
// algorithm's contribution from the pipeline's.
function makeAlg(kind) {
  if (kind === 'ed25519') {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519')
    return {
      jwsAlg: 'EdDSA', coseAlg: -8, diSuite: 'eddsa-rdfc-2022',
      sign: (buf) => crypto.sign(null, buf, privateKey),
      verify: (buf, sig) => crypto.verify(null, buf, publicKey, sig),
    }
  }
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const o = { key: privateKey, dsaEncoding: 'ieee-p1363' }
  const v = { key: publicKey, dsaEncoding: 'ieee-p1363' }
  return {
    jwsAlg: 'ES256', coseAlg: -7, diSuite: 'ecdsa-rdfc-2019',
    sign: (buf) => crypto.sign('sha256', buf, o),
    verify: (buf, sig) => crypto.verify('sha256', buf, v, sig),
  }
}

async function runE2EWith(prefix, algFor) {
  const { encode: cborEncode, decode: cborDecode } = await import('cbor-x')
  const jsonld = (await import('jsonld')).default
  const TOTAL = 20, DISCLOSE = 5
  const attrs = makeAttrs(TOTAL)
  const entries = Object.entries(attrs)
  const shown = entries.slice(0, DISCLOSE)
  const CRED_ID = 'urn:example:cred:e2e'
  const ISSUER_ID = 'did:example:issuer'
  const SUBJ_ID = 'did:example:subject:001'

  // ---- SD-JWT VC : issue = sign + build disclosures, verify = JWS + digest match
  {
    const A = algFor('sdjwt')
    const mkDisclosure = (k, v) => {
      const salt = b64url(crypto.randomBytes(16))
      const d = b64url(Buffer.from(JSON.stringify([salt, k, v])))
      return { d, hash: b64url(sha256b(Buffer.from(d))) }
    }
    const issue = () => {
      const ds = entries.map(([k, v]) => mkDisclosure(k, v))
      const header = b64url(Buffer.from(JSON.stringify({ alg: A.jwsAlg, typ: 'vc+sd-jwt' })))
      const payload = b64url(Buffer.from(JSON.stringify({
        iss: ISSUER_ID, sub: SUBJ_ID, vct: 'https://example.com/vct', iat: 1714000000,
        _sd_alg: 'sha-256', _sd: ds.map((x) => x.hash),
      })))
      const input = `${header}.${payload}`
      return { token: `${input}.${b64url(A.sign(Buffer.from(input)))}`, ds }
    }
    const issued = issue()
    const present = (o) => `${o.token}~${o.ds.slice(0, DISCLOSE).map((x) => x.d).join('~')}~`
    const presented = present(issued)
    const verify = (vp) => {
      const [token, ...disclosures] = vp.split('~').filter(Boolean)
      const [h, p, sg] = token.split('.')
      if (!A.verify(Buffer.from(`${h}.${p}`), Buffer.from(sg, 'base64url'))) throw new Error('bad signature')
      const payload = JSON.parse(Buffer.from(p, 'base64url').toString())
      const set = new Set(payload._sd)
      for (const d of disclosures) {
        if (!set.has(b64url(sha256b(Buffer.from(d))))) throw new Error('digest mismatch')
        JSON.parse(Buffer.from(d, 'base64url').toString())
      }
      return true
    }
    if (verify(presented) !== true) throw new Error('sdjwt self-check failed')
    bench(`${prefix}/sdjwt/issue`, N, () => issue())
    bench(`${prefix}/sdjwt/present`, N, () => present(issued))
    bench(`${prefix}/sdjwt/verify`, N, () => verify(presented))
    bench(`${prefix}/sdjwt/full`, N, () => verify(present(issue())))
    meta[`${prefix}/sdjwt/vpBytes`] = Buffer.byteLength(presented)
  }

  // ---- VCDM 2.0 + Data Integrity : both canonicalizations, 64-byte hashData
  // eddsa-rdfc-2022 has no selective disclosure, so presenting a subset means
  // re-canonicalizing and re-signing it: the verifier then checks the holder's
  // signature, not the issuer's. The guarantee differs from the other two
  // formats and is reported as such in the paper.
  {
    const A = algFor('vcdm')
    const E2E_CONTEXT = [...VC_CONTEXT, { '@vocab': VOCAB }]
    const docOf = (pairs) => ({
      '@context': E2E_CONTEXT,
      id: CRED_ID, type: ['VerifiableCredential'], issuer: ISSUER_ID,
      credentialSubject: { id: SUBJ_ID, ...Object.fromEntries(pairs) },
    })
    const fullDoc = docOf(entries)
    const subsetDoc = docOf(shown)
    const proofOptions = diProofOptions(A.diSuite)
    const issue = async () => A.sign(await diHashData(jsonld, fullDoc, proofOptions))
    const present = async () => ({ sig: A.sign(await diHashData(jsonld, subsetDoc, proofOptions)) })
    const vp = await present()
    const verify = async (p) => {
      if (!A.verify(await diHashData(jsonld, subsetDoc, proofOptions), p.sig)) throw new Error('verify failed')
      return true
    }
    if (await verify(vp) !== true) throw new Error('vcdm self-check failed')
    await benchAsync(`${prefix}/jsonld/issue`, N, async () => { await issue() })
    await benchAsync(`${prefix}/jsonld/present`, N, async () => { await present() })
    await benchAsync(`${prefix}/jsonld/verify`, N, async () => { await verify(vp) })
    await benchAsync(`${prefix}/jsonld/full`, N, async () => { await issue(); await verify(await present()) })
    const subsetNQ = await jsonld.normalize(subsetDoc, RDFC_OPTS)
    meta[`${prefix}/jsonld/vpBytes`] = Buffer.byteLength(JSON.stringify({ ...subsetDoc, proof: { ...proofOptions, proofValue: b64url(vp.sig) } }))
    meta[`${prefix}/jsonld/signingInputBytes`] = Buffer.byteLength(subsetNQ)
    meta[`${prefix}/jsonld/disclosureGuarantee`] = 'holder re-signs the disclosed subset; the issuer signature does not survive'
  }

  // ---- mdoc : issue = per-element digests + MSO + COSE_Sign1,
  //      verify = CBOR decode + COSE_Sign1 + per-element digest match by digestID
  {
    const A = algFor('mdoc')
    const items = entries.map(([k, v], i) => ({
      digestID: i, random: crypto.randomBytes(16), elementIdentifier: k, elementValue: v,
    }))
    const issue = () => {
      const encoded = items.map((it) => cborEncode(it))
      const digests = Object.fromEntries(items.map((it, i) => [it.digestID, sha256b(encoded[i])]))
      const mso = cborEncode({
        version: '1.0', digestAlgorithm: 'SHA-256', docType: `${MDOC_NS}.mDL`,
        valueDigests: { [MDOC_NS]: digests },
        validityInfo: { signed: '2024-01-01T00:00:00Z', validFrom: '2024-01-01T00:00:00Z', validUntil: '2029-01-01T00:00:00Z' },
      })
      const protectedHdr = cborEncode({ 1: A.coseAlg })
      const sigStruct = cborEncode(['Signature1', protectedHdr, Buffer.alloc(0), mso])
      return { encoded, mso, protectedHdr, sig: A.sign(sigStruct) }
    }
    const issued = issue()
    const present = (o) => cborEncode({
      docType: `${MDOC_NS}.mDL`,
      issuerSigned: {
        nameSpaces: { [MDOC_NS]: o.encoded.slice(0, DISCLOSE) },
        issuerAuth: [o.protectedHdr, {}, o.mso, o.sig],
      },
    })
    const presented = present(issued)
    const verify = (vpBytes) => {
      const doc = cborDecode(vpBytes)
      const [protectedHdr, , mso, sig] = doc.issuerSigned.issuerAuth
      const sigStruct = cborEncode(['Signature1', protectedHdr, Buffer.alloc(0), mso])
      if (!A.verify(sigStruct, sig)) throw new Error('bad signature')
      const digests = cborDecode(mso).valueDigests[MDOC_NS]
      for (const enc of doc.issuerSigned.nameSpaces[MDOC_NS]) {
        const it = cborDecode(enc)
        if (!Buffer.from(digests[it.digestID]).equals(sha256b(Buffer.from(enc)))) throw new Error('digest mismatch')
      }
      return true
    }
    if (verify(presented) !== true) throw new Error('mdoc self-check failed')
    bench(`${prefix}/mdoc/issue`, N, () => issue())
    bench(`${prefix}/mdoc/present`, N, () => present(issued))
    bench(`${prefix}/mdoc/verify`, N, () => verify(presented))
    bench(`${prefix}/mdoc/full`, N, () => verify(present(issue())))
    meta[`${prefix}/mdoc/vpBytes`] = presented.length
  }
}

// native: each format's own default (SD-JWT VC and VCDM on Ed25519, mdoc on P-256)
const NATIVE = { sdjwt: 'ed25519', vcdm: 'ed25519', mdoc: 'p256' }
async function runE2E() {
  const cache = {}
  await runE2EWith('e2e', (f) => (cache[NATIVE[f]] ??= makeAlg(NATIVE[f])))
}
async function runE2EEd25519() {
  const a = makeAlg('ed25519')
  await runE2EWith('e2e-ed25519', () => a)
}
async function runE2EP256() {
  const a = makeAlg('p256')
  await runE2EWith('e2e-p256', () => a)
}

// ── selective disclosure that preserves the issuer signature (ecdsa-sd-2023) ──
// eddsa-rdfc-2022 has no derivation step, so the e2e suite above has the holder
// re-sign the disclosed subset and the issuer signature does not survive. This
// suite measures the Data Integrity cryptosuite that does preserve it, so that
// the comparison with SD-JWT VC and mdoc is between mechanisms offering the
// same guarantee. Pointers follow RFC 6901 (JSON Pointer).
async function runSelDiscSd() {
  let jsigs, DataIntegrityProof, EcdsaMultikey, sd, credCtx, diCtx, mkCtx
  try {
    jsigs = (await import('jsonld-signatures')).default
    ;({ DataIntegrityProof } = await import('@digitalbazaar/data-integrity'))
    EcdsaMultikey = await import('@digitalbazaar/ecdsa-multikey')
    sd = await import('@digitalbazaar/ecdsa-sd-2023-cryptosuite')
    credCtx = await import('@digitalbazaar/credentials-context')
    diCtx = await import('@digitalbazaar/data-integrity-context')
    mkCtx = await import('@digitalbazaar/multikey-context')
  } catch (e) {
    process.stderr.write(`  [seldisc-sd] skipped, packages unavailable: ${e.message}\n`)
    meta['seldisc-sd/skipped'] = String(e.message)
    return
  }
  const { purposes: { AssertionProofPurpose } } = jsigs

  const ctxMap = new Map()
  for (const mod of [credCtx, diCtx, mkCtx]) {
    const contexts = (mod.default ?? mod).contexts
    for (const [u, d] of contexts) ctxMap.set(u, d)
  }
  let KEYDOC = null
  const documentLoader = async (url) => {
    if (ctxMap.has(url)) return { contextUrl: null, document: ctxMap.get(url), documentUrl: url }
    if (KEYDOC && url === KEYDOC.id) return { contextUrl: null, document: KEYDOC, documentUrl: url }
    if (KEYDOC && url === KEYDOC.controller) {
      return { contextUrl: null, documentUrl: url, document: {
        '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
        id: KEYDOC.controller, assertionMethod: [KEYDOC],
      } }
    }
    throw new Error(`Context not embedded: ${url}`)
  }

  const TOTAL = 20
  const kp = await EcdsaMultikey.generate({
    curve: 'P-256', id: 'did:example:issuer#key-1', controller: 'did:example:issuer',
  })
  KEYDOC = await kp.export({ publicKey: true, includeContext: true })

  const credential = {
    '@context': ['https://www.w3.org/ns/credentials/v2', { '@vocab': VOCAB }],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject:001', ...makeAttrs(TOTAL) },
  }

  const signSuite = () => new DataIntegrityProof({
    signer: kp.signer(),
    cryptosuite: sd.createSignCryptosuite({ mandatoryPointers: ['/issuer'] }),
  })
  const issue = async () => jsigs.sign(structuredClone(credential), {
    suite: signSuite(), purpose: new AssertionProofPurpose(), documentLoader,
  })
  const base = await issue()
  meta['seldisc-sd/baseBytes'] = Buffer.byteLength(JSON.stringify(base))

  const deriveSuite = (n) => new DataIntegrityProof({
    cryptosuite: sd.createDiscloseCryptosuite({
      selectivePointers: Array.from({ length: n }, (_, i) => `/credentialSubject/attr_${String(i).padStart(3, '0')}`),
    }),
  })
  const derive = async (n) => jsigs.derive(base, {
    suite: deriveSuite(n), purpose: new AssertionProofPurpose(), documentLoader,
  })
  const verifySuite = () => new DataIntegrityProof({ cryptosuite: sd.createVerifyCryptosuite() })
  const verify = async (doc) => {
    const r = await jsigs.verify(doc, {
      suite: verifySuite(), purpose: new AssertionProofPurpose(), documentLoader,
    })
    if (!r.verified) throw new Error(`verify failed: ${r.error?.errors?.[0]?.message ?? 'unknown'}`)
    return true
  }

  // issuance is independent of the number disclosed; measured once
  const NSD = Math.max(Math.floor(N / 20), 20)
  await benchAsync('seldisc-sd/issue', NSD, async () => { await issue() })

  for (const n of [1, 2, 5, 10, 20]) {
    const derived = await derive(n)
    if (await verify(derived) !== true) throw new Error('seldisc-sd self-check failed')
    meta[`seldisc-sd/disclose-${n}/vpBytes`] = Buffer.byteLength(JSON.stringify(derived))
    await benchAsync(`seldisc-sd/disclose-${n}/derive`, NSD, async () => { await derive(n) })
    await benchAsync(`seldisc-sd/disclose-${n}/verify`, NSD, async () => { await verify(derived) })
  }
  meta['seldisc-sd/note'] =
    'ecdsa-sd-2023 (P-256): the issuer signature survives derivation, unlike the eddsa-rdfc-2022 path in the e2e suite'
}

// ── cryptographic primitive baseline ────────────────────────────
// The per-format benchmarks mix a signature algorithm with a serialization
// pipeline, so a cross-language difference in one format cannot be attributed
// to either without a baseline. This suite measures the primitives alone, with
// no credential structure around them.
async function runPrimitives() {
  const msg = Buffer.from('a'.repeat(256))
  const ed = crypto.generateKeyPairSync('ed25519')
  const edPub = crypto.createPublicKey(ed.privateKey)
  const edSig = crypto.sign(null, msg, ed.privateKey)
  bench('prim/ed25519/sign', N, () => { crypto.sign(null, msg, ed.privateKey) })
  bench('prim/ed25519/verify', N, () => {
    if (!crypto.verify(null, msg, edPub, edSig)) throw new Error('verify failed')
  })

  const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const ecPriv = { key: ec.privateKey, dsaEncoding: 'ieee-p1363' }
  const ecPub = { key: crypto.createPublicKey(ec.privateKey), dsaEncoding: 'ieee-p1363' }
  const ecSig = crypto.sign('sha256', msg, ecPriv)
  bench('prim/p256/sign', N, () => { crypto.sign('sha256', msg, ecPriv) })
  bench('prim/p256/verify', N, () => {
    if (!crypto.verify('sha256', msg, ecPub, ecSig)) throw new Error('verify failed')
  })

  bench('prim/sha256', N, () => { sha256b(msg) })
  meta['prim/messageBytes'] = msg.length
}

// ── poison graph / call-limit suite ──────────────────────────────────────
// Blank-node graph families used as adversarial input to RDFC-1.0, plus a
// sweep of the rdf-canonize call limit (maxDeepIterations). Unlike the other
// suites, each condition records its outcome (completed / aborted by the call
// limit / truncated by the time budget) instead of discarding exceptions.
async function runPoison() {
  const jsonld = (await import('jsonld')).default
  const BASE = { algorithm: 'URDNA2015', format: 'application/n-quads', safe: false }

  // Every node carries an explicit blank node identifier, so the references
  // below really do form cycles. (A generator that omits @id yields a forest
  // of disjoint trees, which is not a worst case for RDFC-1.0.)
  const node = (i, targets) => ({
    '@id': `_:b${i}`,
    'http://example.org/link': targets.map((j) => ({ '@id': `_:b${j}` })),
  })
  const FAMILIES = {
    // K_n: every blank node references every other one
    complete: (n) => ({ '@graph': Array.from({ length: n }, (_, i) =>
      node(i, Array.from({ length: n }, (_, j) => j).filter((j) => j !== i))) }),
    // bidirectional ring C_n
    ring: (n) => ({ '@graph': Array.from({ length: n }, (_, i) =>
      node(i, [(i + 1) % n, (i + n - 1) % n])) }),
    // 3-regular circulant graph
    cubic: (n) => ({ '@graph': Array.from({ length: n }, (_, i) =>
      node(i, [(i + 1) % n, (i + n - 1) % n, (i + Math.floor(n / 2)) % n])) }),
    // acyclic forest produced by a generator that omits @id (kept for comparison)
    forest: (n) => ({ '@graph': Array.from({ length: n }, (_, i) => [
      { '@type': 'http://example.org/Node', 'http://example.org/link': { '@id': `_:b${(i + 1) % n}` } },
      { '@type': 'http://example.org/Node', 'http://example.org/link': { '@id': `_:b${i}` } },
    ]).flat() }),
  }

  // Legitimate (non-adversarial) inputs, used to check that a call limit does
  // not reject well-formed credentials.
  let ob = null
  const ctxMap = new Map()
  try {
    const obCtx = await import('@digitalcredentials/open-badges-context')
    ob = obCtx.default ?? obCtx
    const ccCtx = await import('@digitalbazaar/credentials-context')
    const cc = ccCtx.default ?? ccCtx
    for (const [url, doc] of ob.contexts) ctxMap.set(url, doc)
    for (const [url, doc] of cc.contexts) ctxMap.set(url, doc)
  } catch (e) {
    process.stderr.write(`  [poison] OB3 context package unavailable, skipping legit-ob3: ${e.message}\n`)
  }
  const loader = (url) => {
    const doc = ctxMap.get(url)
    if (!doc) throw new Error(`Context not embedded: ${url}`)
    return { contextUrl: null, document: doc, documentUrl: url }
  }
  const synth = (bn) => ({
    '@context': [...VC_CONTEXT, { '@vocab': VOCAB }],
    id: 'urn:example:synth', type: ['VerifiableCredential'], issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:sub', evidence: Array.from({ length: bn }, (_, i) => ({ type: 'Evidence', narrative: `evidence item ${i}`, weight: String(i) })) },
  })

  // Runs one condition under a wall-clock budget. Returns the outcome so that
  // aborted and truncated conditions are reported rather than silently timed.
  const BUDGET_MS = Number(process.env.POISON_BUDGET_MS ?? 20000)
  async function measure(key, doc, opts, maxIter) {
    const o = { ...BASE, ...opts }
    let outcome = 'completed'
    let err = null
    // one warmup pass (also establishes the outcome)
    const w0 = process.hrtime.bigint()
    try { await jsonld.normalize(doc, o) } catch (e) { outcome = 'aborted'; err = String(e.message || e).split('\n')[0] }
    const first = Number(process.hrtime.bigint() - w0)
    // size the run so that one condition never exceeds the budget
    const perIterMs = first / 1e6
    let n = Math.max(1, Math.min(maxIter, Math.floor(BUDGET_MS / Math.max(perIterMs, 0.001))))
    if (n > 1) for (let i = 0; i < Math.min(WARMUP, n); i++) { try { await jsonld.normalize(doc, o) } catch {} }
    const t = new Array(n)
    const start = process.hrtime.bigint()
    let done = 0
    for (let i = 0; i < n; i++) {
      const s = process.hrtime.bigint()
      try { await jsonld.normalize(doc, o) } catch { /* outcome already recorded */ }
      t[i] = Number(process.hrtime.bigint() - s)
      done = i + 1
      if (Number(process.hrtime.bigint() - start) / 1e6 > BUDGET_MS) break
    }
    benches[key] = { n: done, warmup: n > 1 ? Math.min(WARMUP, n) : 0, timings_ns: t.slice(0, done) }
    meta[`${key}/outcome`] = outcome
    if (err) meta[`${key}/error`] = err
    if (done < maxIter) meta[`${key}/truncated`] = `budget ${BUDGET_MS} ms`
    process.stderr.write(`  ${key}: ${outcome} (n=${done}, first=${perIterMs.toFixed(3)} ms)\n`)
  }

  // Input shapes are reported so that "n" is unambiguous (the number of blank
  // nodes after expansion is not always the generator's parameter).
  async function shapeOf(doc) {
    const nq = await jsonld.normalize(doc, BASE)
    const lines = nq.trim().split('\n').filter(Boolean)
    const bn = new Set()
    for (const l of lines) for (const m of l.matchAll(/_:c14n\d+/g)) bn.add(m[0])
    const subj = new Set(lines.map((l) => l.split(' ')[0]).filter((s) => s.startsWith('_:')))
    const objs = new Set(lines.map((l) => l.split(' ')[2]).filter((s) => s.startsWith('_:')))
    return { quads: lines.length, blankNodes: bn.size, cyclic: [...subj].filter((s) => objs.has(s)).length > 0,
             bytes: Buffer.byteLength(JSON.stringify(doc)) }
  }

  // 1) baseline
  await measure('poison/baseline/normalize', VC_DOC, {}, Math.max(Math.floor(N / 2), 50))

  // 2) family x size sweep with the library defaults (no call limit)
  const SWEEP = {
    complete: [3, 4, 5, 6, 7, 8],
    cubic: [6, 8, 10, 12, 16],
    ring: [8, 16, 32, 64, 128],
    forest: [20, 100, 500],
  }
  for (const [fam, sizes] of Object.entries(SWEEP)) {
    for (const n of sizes) {
      const doc = FAMILIES[fam](n)
      const key = `poison/${fam}-${n}/normalize`
      try { meta[`${key}/shape`] = await shapeOf(doc) } catch (e) { meta[`${key}/shape`] = String(e.message || e) }
      await measure(key, doc, {}, 200)
    }
  }

  // 3) call-limit sweep (rdf-canonize maxDeepIterations)
  const LIMITS = [1, 4, 16, 64]
  const CASES = {
    'legit-simple': { doc: VC_DOC, opts: {} },
    'legit-bn10': { doc: synth(10), opts: {} },
    'legit-bn50': { doc: synth(50), opts: {} },
    'legit-ob3': { doc: null, opts: { documentLoader: loader } },   // filled below
    'attack-complete-5': { doc: FAMILIES.complete(5), opts: {} },
    'attack-complete-7': { doc: FAMILIES.complete(7), opts: {} },
    'attack-cubic-10': { doc: FAMILIES.cubic(10), opts: {} },
    'attack-ring-16': { doc: FAMILIES.ring(16), opts: {} },
    'attack-ring-64': { doc: FAMILIES.ring(64), opts: {} },
    'attack-forest-20': { doc: FAMILIES.forest(20), opts: {} },
  }
  if (!ob) delete CASES['legit-ob3']
  else CASES['legit-ob3'].doc = {
    '@context': ['https://www.w3.org/ns/credentials/v2', ob.CONTEXT_URL_V3_0_3],
    id: 'urn:uuid:a63a60be-f4af-491c-87fc-2c8fd3007a58',
    type: ['VerifiableCredential', 'OpenBadgeCredential'],
    issuer: { id: 'https://university.example/issuers/565049', type: ['Profile'], name: 'Example University' },
    validFrom: '2026-01-01T00:00:00Z',
    credentialSubject: { id: 'did:example:ebfeb1f712ebc6f1c276e12ec21', type: ['AchievementSubject'],
      achievement: { id: 'https://university.example/achievements/degree-cs', type: ['Achievement'],
        name: 'Bachelor of Science in Computer Science',
        criteria: { type: 'Criteria', narrative: 'Completion of 124 credit hours.' },
        alignment: [{ type: ['Alignment'], targetName: 'CS Curriculum Standard', targetUrl: 'https://credentialengineregistry.org/resources/ce-6369c51f' }] },
      result: [{ type: ['Result'], value: '3.7' }] },
  }
  for (const [label, { doc, opts }] of Object.entries(CASES)) {
    for (const k of LIMITS) {
      await measure(`poison/limit-k${k}/${label}`, doc, { ...opts, maxDeepIterations: k }, 100)
    }
  }
}

// ── security tests (attack vectors) ──────────────────────────────────────
// Node-side replacement for the browser tests that previously lived in the
// VC Format Comparison Tool. Each case records a verdict (rejected / accepted
// / observed) rather than a latency, so that the evidence status of every row
// in the security results table is produced by the same kit as the timings.
async function runSecurity() {
  const jsonld = (await import('jsonld')).default
  const { encode: cborEncode, decode: cborDecode } = await import('cbor-x')
  const sha256 = (b) => crypto.createHash('sha256').update(b).digest()
  const verdicts = {}
  const record = (key, verdict, detail) => {
    verdicts[key] = { verdict, detail }
    meta[`security/${key}`] = `${verdict}: ${detail}`
    process.stderr.write(`  security/${key}: ${verdict} (${detail})\n`)
  }

  // ---- SD-JWT VC: alg:none ----------------------------------------------
  {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519')
    const ALLOWED = ['EdDSA']
    const verify = (token) => {
      const [h, p, s] = token.split('.')
      const hdr = JSON.parse(Buffer.from(h, 'base64url').toString())
      if (!ALLOWED.includes(hdr.alg)) throw new Error(`alg not allowed: ${hdr.alg}`)
      if (!crypto.verify(null, Buffer.from(`${h}.${p}`), publicKey, Buffer.from(s, 'base64url'))) {
        throw new Error('bad signature')
      }
      return true
    }
    const payload = b64url(Buffer.from(JSON.stringify({ iss: 'https://issuer.example.com', vct: 'identity' })))
    const good = (() => {
      const h = b64url(Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'vc+sd-jwt' })))
      return `${h}.${payload}.${b64url(crypto.sign(null, Buffer.from(`${h}.${payload}`), privateKey))}`
    })()
    try { verify(good) } catch (e) { record('sdjwt/baseline', 'FAIL', `legitimate token rejected: ${e.message}`) }
    const none = `${b64url(Buffer.from(JSON.stringify({ alg: 'none', typ: 'vc+sd-jwt' })))}.${payload}.`
    try { verify(none); record('sdjwt/alg-none', 'ACCEPTED', 'unsigned token passed verification') }
    catch (e) { record('sdjwt/alg-none', 'REJECTED', e.message) }
    // algorithm confusion: an HMAC token whose key is the Ed25519 public key
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' })
    const h2 = b64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'vc+sd-jwt' })))
    const forged = `${h2}.${payload}.${b64url(crypto.createHmac('sha256', pubPem).update(`${h2}.${payload}`).digest())}`
    try { verify(forged); record('sdjwt/alg-confusion', 'ACCEPTED', 'HMAC token forged with the public key passed') }
    catch (e) { record('sdjwt/alg-confusion', 'REJECTED', e.message) }
  }

  // ---- mdoc: data element tampering and COSE header tampering -----------
  {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const items = [['family_name', 'Yamada'], ['birth_date', '1990-01-01']]
      .map(([k, v], i) => ({ digestID: i, random: crypto.randomBytes(16), elementIdentifier: k, elementValue: v }))
    const encoded = items.map((it) => cborEncode(it))
    const mso = cborEncode({ version: '1.0', digestAlgorithm: 'SHA-256', docType: 'org.iso.18013.5.1.mDL',
      valueDigests: { 'org.iso.18013.5.1': Object.fromEntries(items.map((it, i) => [it.digestID, sha256(encoded[i])])) } })
    const protectedHdr = cborEncode({ 1: -7 })
    const sigStruct = (ph, payload) => cborEncode(['Signature1', ph, Buffer.alloc(0), payload])
    const sig = crypto.sign('sha256', sigStruct(protectedHdr, mso), { key: privateKey, dsaEncoding: 'ieee-p1363' })
    const verify = (ph, elems, msoBytes, signature) => {
      if (!crypto.verify('sha256', sigStruct(ph, msoBytes), { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature)) {
        throw new Error('COSE_Sign1 signature verification failed')
      }
      const digests = cborDecode(msoBytes).valueDigests['org.iso.18013.5.1']
      for (const enc of elems) {
        const it = cborDecode(enc)
        if (!Buffer.from(digests[it.digestID]).equals(sha256(Buffer.from(enc)))) throw new Error('digest mismatch')
      }
      return true
    }
    try { verify(protectedHdr, encoded, mso, sig) } catch (e) { record('mdoc/baseline', 'FAIL', `legitimate mdoc rejected: ${e.message}`) }
    const tampered = [...encoded]
    tampered[0] = cborEncode({ ...cborDecode(encoded[0]), elementValue: 'Attacker' })
    try { verify(protectedHdr, tampered, mso, sig); record('mdoc/element-tamper', 'ACCEPTED', 'modified element value was not detected') }
    catch (e) { record('mdoc/element-tamper', 'REJECTED', e.message) }
    const badHdr = cborEncode({ 1: -8 })   // claim EdDSA instead of ES256
    try { verify(badHdr, encoded, mso, sig); record('mdoc/cose-header-tamper', 'ACCEPTED', 'modified protected header was not detected') }
    catch (e) { record('mdoc/cose-header-tamper', 'REJECTED', e.message) }
  }

  // ---- W3C VCDM: context injection --------------------------------------
  {
    const OPTS = { algorithm: 'URDNA2015', format: 'application/n-quads', safe: false }
    const honest = { '@context': [{ '@version': 1.1, name: 'http://schema.org/name' }],
      '@id': 'https://example.com/c/1', name: 'Taro' }
    const injected = { '@context': [{ '@version': 1.1, name: 'http://attacker.example.com/vocab#displayName' }],
      '@id': 'https://example.com/c/1', name: 'Taro' }
    const a = await jsonld.normalize(honest, OPTS)
    let b, err = null
    try { b = await jsonld.normalize(injected, OPTS) } catch (e) { err = e.message }
    const iriOf = (nq) => (nq.match(/<([^>]+)>\s+"/) || [])[1]
    if (err) record('vcdm/context-injection', 'REJECTED', err)
    else record('vcdm/context-injection', iriOf(a) === iriOf(b) ? 'UNCHANGED' : 'OBSERVED',
      `term IRI ${iriOf(a)} -> ${iriOf(b)}; canonicalization ${a === b ? 'identical' : 'differs'}`)
  }

  // ---- W3C VCDM: does the processor reach for an attacker-controlled URL?
  // A recording document loader observes the request at the loader boundary
  // without any packet leaving the process, so reachability is established by
  // observation rather than by reading the source.
  {
    const OPTS = { algorithm: 'URDNA2015', format: 'application/n-quads', safe: false }
    const requested = []
    const recordingLoader = async (url) => { requested.push(url); throw new Error(`blocked: ${url}`) }
    const evil = { '@context': ['http://169.254.169.254/latest/meta-data/'], '@id': 'https://example.com/c/1' }
    try { await jsonld.normalize(evil, { ...OPTS, documentLoader: recordingLoader }) } catch { /* expected */ }
    record('vcdm/ssrf-reachability', requested.length ? 'OBSERVED' : 'NOT-OBSERVED',
      `loader was asked for: ${requested.join(', ') || '(nothing)'}`)
  }
  meta['security/verdicts'] = verdicts
}

// ── context loader comparison ────────────────────────────────────────────
// Replaces the browser-mode measurement with three Node-side conditions: a
// statically embedded context, a loader with an injected delay (the delay is
// reported so the resulting gap is not mistaken for a measured network cost),
// and a real retrieval over the loopback interface from a server this process
// starts itself.
async function runLoader() {
  const jsonld = (await import('jsonld')).default
  const http = await import('node:http')
  const OPTS = { algorithm: 'URDNA2015', format: 'application/n-quads', safe: false }
  const CTX_URL = 'https://ctx.example/v1'
  const CTX_DOC = { '@context': { '@version': 1.1, type: '@type', id: '@id', name: 'http://schema.org/name' } }
  const DOC = { '@context': CTX_URL, id: 'https://example.com/c/1', name: 'Taro' }
  const DELAY_MS = Number(process.env.LOADER_DELAY_MS ?? 50)

  const staticLoader = async (url) => {
    if (url !== CTX_URL) throw new Error(`Context not embedded: ${url}`)
    return { contextUrl: null, document: CTX_DOC, documentUrl: url }
  }
  const delayedLoader = async (url) => {
    await new Promise((r) => setTimeout(r, DELAY_MS))
    return staticLoader(url)
  }

  const server = http.createServer((_, res) => {
    res.setHeader('content-type', 'application/ld+json')
    res.end(JSON.stringify(CTX_DOC))
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const port = server.address().port
  const LOOPBACK_URL = `http://127.0.0.1:${port}/v1`
  const loopbackDoc = { ...DOC, '@context': LOOPBACK_URL }
  const loopbackLoader = async (url) => {
    const res = await fetch(url)
    return { contextUrl: null, document: await res.json(), documentUrl: url }
  }

  const n = Math.max(Math.floor(N / 20), 20)
  await benchAsync('loader/static/normalize', Math.max(Math.floor(N / 2), 50),
    async () => { await jsonld.normalize(DOC, { ...OPTS, documentLoader: staticLoader }) })
  await benchAsync('loader/delayed/normalize', n,
    async () => { await jsonld.normalize(DOC, { ...OPTS, documentLoader: delayedLoader }) })
  await benchAsync('loader/loopback/normalize', n,
    async () => { await jsonld.normalize(loopbackDoc, { ...OPTS, documentLoader: loopbackLoader }) })
  meta['loader/injectedDelayMs'] = DELAY_MS
  meta['loader/note'] = 'delayed = static loader plus an injected delay of injectedDelayMs; loopback = real HTTP retrieval from a server started by this process (no external network)'
  await new Promise((r) => server.close(r))
}

const RUNNERS = {
  sdjwt: runSdJwt,
  primitives: runPrimitives,
  jsonld: runJsonLd,
  'jsonld-jcs': runJcs,
  mdoc: runMdoc,
  'jsonld-complex': runJsonLdComplex,
  breakdown: runBreakdown,
  serial: runSerial,
  scaling: runScaling,
  seldisc: runSelDisc,
  'seldisc-sd': runSelDiscSd,
  unified: runUnified,
  e2e: runE2E,
  'e2e-ed25519': runE2EEd25519,
  'e2e-p256': runE2EP256,
  poison: runPoison,
  security: runSecurity,
  loader: runLoader,
}

async function main() {
  const targets = FORMAT === 'all' ? Object.keys(RUNNERS) : [FORMAT]
  for (const f of targets) {
    if (!RUNNERS[f]) { console.error(`unknown format: ${f}`); process.exit(1) }
    process.stderr.write(`[node] format=${f}\n`)
    await RUNNERS[f]()
  }
  const result = {
    lang: 'node',
    format: FORMAT,
    n: N, warmup: WARMUP,
    env: {
      node: process.version, v8: process.versions.v8, openssl: process.versions.openssl,
      platform: `${process.platform} ${process.arch}`, osRelease: os.release(),
      cpu: os.cpus()[0]?.model ?? 'unknown', cores: os.cpus().length,
      libraries: Object.fromEntries(['jose', 'jsonld', 'rdf-canonize', 'cbor-x', 'canonicalize'].map(p => {
        try { return [p, require(`${p}/package.json`).version] } catch { return [p, 'n/a'] }
      })),
      timestamp: new Date().toISOString(),
    },
    meta,
    benches,
  }
  const json = JSON.stringify(result)
  if (OUT) { fs.writeFileSync(OUT, json); process.stderr.write(`wrote ${OUT}\n`) }
  else process.stdout.write(json + '\n')
}

main().catch(e => { console.error(e); process.exit(1) })
