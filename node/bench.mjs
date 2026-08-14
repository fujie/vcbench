#!/usr/bin/env node
/**
 * linux-bench Node.js engine — VCフォーマット別 署名/検証ベンチマーク
 *
 * 計測方式は論文4.3.1と同一:
 *   - process.hrtime.bigint()（ナノ秒精度）で各イテレーションを個別記録
 *   - ウォームアップ後に本計測
 *   - 統計計算は行わず生タイミング(ns)を出力（統計は ../aggregate.mjs が一元計算）
 *
 * 使い方:
 *   node bench.mjs --format <FORMAT> [--n 2000] [--warmup 50] [--out results.json]
 *
 * FORMAT:
 *   sdjwt | jsonld | jsonld-jcs | mdoc   基本の署名/検証（全言語共通のスイート）
 *   jsonld-complex                       OB3/DCC/合成BNの正規化（論文表16）
 *   breakdown                            JSON-LD署名処理の内訳（論文表5）
 *   serial                               シリアライズ速度・暗号なし（論文表9）
 *   scaling                              属性数スケーリング（論文表11）
 *   seldisc                              選択的開示（論文表12）
 *   unified                              Ed25519統一ベンチ（論文表15）
 *   all                                  上記すべて
 */
import crypto from 'node:crypto'
import os from 'node:os'
import fs from 'node:fs'
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)

// jose v6 はグローバル crypto（WebCrypto）を前提とする。
// Node 19 未満ではグローバル定義が無いため node:crypto.webcrypto をポリフィルする。
if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = crypto.webcrypto
}
const NODE_MAJOR = Number(process.versions.node.split('.')[0])
if (NODE_MAJOR < 20) {
  process.stderr.write(
    `WARN: Node ${process.version} を検出。論文計測は v22 系で実施しています。` +
    `結果の比較可能性のため Node 22 の使用を推奨します（nvm install 22）。\n`)
}

// ── CLI ──────────────────────────────────────────────────────────
const args = {}
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, '')] = process.argv[i + 1]
const FORMAT = args.format ?? 'all'
const N = Number(args.n ?? 2000)
const WARMUP = Number(args.warmup ?? 50)
const OUT = args.out ?? null

const benches = {}
const meta = {}   // ペイロードサイズ等の付帯情報（aggregate が summary に転記）

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

// 共通クレデンシャル（論文4.3.1と同一ペイロード）
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

// ── SD-JWT VC ────────────────────────────────────────────────────
async function runSdJwt() {
  // stdcrypto: node:crypto 直接（論文の「ライブラリあり/なし共通」実装）
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

  // jose: フルJWTパイプライン（参考値）
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

// ── JSON-LD VC (URDNA2015) ───────────────────────────────────────
async function runJsonLd() {
  const jsonld = (await import('jsonld')).default
  const { privateKey } = crypto.generateKeyPairSync('ed25519')
  const publicKey = crypto.createPublicKey(privateKey)
  const normalize = () => jsonld.normalize(VC_DOC, { algorithm: 'URDNA2015', format: 'application/n-quads', safe: false })

  await benchAsync('jsonld/jsonld-lib/sign', N, async () => {
    const norm = await normalize()
    crypto.sign(null, crypto.createHash('sha256').update(norm).digest(), privateKey)
  })
  const sig0 = crypto.sign(null, crypto.createHash('sha256').update(await normalize()).digest(), privateKey)
  await benchAsync('jsonld/jsonld-lib/verify', N, async () => {
    const norm = await normalize()
    crypto.verify(null, crypto.createHash('sha256').update(norm).digest(), publicKey, sig0)
  })
  await benchAsync('jsonld/jsonld-lib/normalize-only', N, async () => { await normalize() })

  // noLib: インラインN-Quads
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
    crypto.sign(null, crypto.createHash('sha256').update(inlineNorm()).digest(), kp2.privateKey)
  })
  const sig1 = crypto.sign(null, crypto.createHash('sha256').update(inlineNorm()).digest(), kp2.privateKey)
  bench('jsonld/nolib/verify', N, () => {
    crypto.verify(null, crypto.createHash('sha256').update(inlineNorm()).digest(), pub2, sig1)
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

async function runMdoc() {
  const { encode: cborEncode } = await import('cbor-x')
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })

  const buildSigStructLib = () => {
    const digestMap = new Map()
    let id = 0
    for (const [k, v] of MDOC_FIELDS) {
      const item = cborEncode({ digestID: id, elementIdentifier: k, elementValue: v })
      digestMap.set(id++, new Uint8Array(crypto.createHash('sha256').update(item).digest()))
    }
    const protHdr = cborEncode(new Map([[1, -7]]))
    const msoPayload = cborEncode({ docType: 'org.iso.18013.5.1.mDL', valueDigests: digestMap })
    return cborEncode(['Signature1', protHdr, new Uint8Array(0), msoPayload])
  }
  bench('mdoc/cbor-x/sign', N, () => {
    crypto.sign('SHA256', buildSigStructLib(), { key: privateKey, dsaEncoding: 'ieee-p1363' })
  })
  const ss0 = buildSigStructLib()
  const sig0 = crypto.sign('SHA256', ss0, { key: privateKey, dsaEncoding: 'ieee-p1363' })
  bench('mdoc/cbor-x/verify', N, () => {
    crypto.verify('SHA256', ss0, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sig0)
  })

  // noLib: 手書きCBOR
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
      const item = cborMap(cborUint(0), cborUint(i), cborText('elementIdentifier'), cborText(k), cborText('elementValue'), cborText(v))
      digestMap.push(cborUint(i), cborBytes(crypto.createHash('sha256').update(item).digest()))
    }
    const msoPayload = cborMap(cborText('docType'), cborText('org.iso.18013.5.1.mDL'), cborText('valueDigests'), cborMap(...digestMap))
    return cborArray(cborText('Signature1'), cborBytes(protHdr), cborBytes(Buffer.alloc(0)), cborBytes(msoPayload))
  }
  bench('mdoc/nolib/sign', N, () => {
    crypto.sign('SHA256', buildSigStructManual(), { key: privateKey, dsaEncoding: 'ieee-p1363' })
  })
  const ss1 = buildSigStructManual()
  const sig1 = crypto.sign('SHA256', ss1, { key: privateKey, dsaEncoding: 'ieee-p1363' })
  bench('mdoc/nolib/verify', N, () => {
    crypto.verify('SHA256', ss1, { key: publicKey, dsaEncoding: 'ieee-p1363' }, sig1)
  })
}

// ── JSON-LD 複雑クレデンシャル (OB3 / DCC / 合成) — Nodeのみ ─────
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

// ── 補助スイート共通ヘルパー ─────────────────────────────────────
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

// ── breakdown: JSON-LD署名処理の内訳（論文表5） ──────────────────
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
  // 全体パイプライン（内訳合計との比較用）
  await benchAsync('breakdown/full-pipeline-sign', N, async () => {
    const norm = await jsonld.normalize(VC_DOC, opts)
    crypto.sign(null, crypto.createHash('sha256').update(norm).digest(), privateKey)
  })
}

// ── serial: シリアライズ速度・暗号処理なし（論文表9） ────────────
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

  // JSON-LD VC: encode/decode + URDNA2015 normalize（jsonldライブラリ）
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

// ── scaling: 属性数スケーリング（論文表11） ──────────────────────
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

// ── seldisc: 選択的開示（論文表12） ──────────────────────────────
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

// ── unified: Ed25519統一ベンチ（論文表15） ───────────────────────
async function runUnified() {
  const jsonld = (await import('jsonld')).default
  const { encode: cborEncode } = await import('cbor-x')
  const FIELDS = makeAttrs(5)

  // SD-JWT VC（node:crypto、表4と同一実装水準、5属性）
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

  // JSON-LD VC（jsonld URDNA2015 + Ed25519、5属性）
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
const RUNNERS = {
  sdjwt: runSdJwt,
  jsonld: runJsonLd,
  'jsonld-jcs': runJcs,
  mdoc: runMdoc,
  'jsonld-complex': runJsonLdComplex,
  breakdown: runBreakdown,
  serial: runSerial,
  scaling: runScaling,
  seldisc: runSelDisc,
  unified: runUnified,
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
