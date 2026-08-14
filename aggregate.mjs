#!/usr/bin/env node
/**
 * aggregate.mjs — 全言語・全フォーマットの生タイミングを一元集計
 *
 * 各エンジン（node/go/python）が出力した生タイミング(ns)から、
 * 論文4.3.1と同一の統計量を計算する:
 *   - 平均・標本標準偏差(σ)・95%CI・p50/p90/p95/p99（線形補間）・min/max
 *   - 外れ値: Tukey基準(1.5×IQR)で検出・件数報告（除去しない）
 *   - トリム平均（Tukey外れ値除外、参考値）
 * 複数run（独立プロセス実行）がある場合は、各統計量のrun間中央値を採用。
 *
 * 使い方: node aggregate.mjs <resultsディレクトリ> [出力プレフィックス]
 *   → <prefix>.json（機械可読）と <prefix>.md（Markdownサマリ）を出力
 */
import fs from 'node:fs'
import path from 'node:path'

const dir = process.argv[2] ?? 'results'
const prefix = process.argv[3] ?? path.join(dir, 'summary')

// ── 統計 ─────────────────────────────────────────────────────────
function computeStats(timingsNs) {
  const t = [...timingsNs].sort((a, b) => a - b)
  const n = t.length
  const mean = t.reduce((s, v) => s + v, 0) / n
  const variance = t.reduce((s, v) => s + (v - mean) ** 2, 0) / (n - 1)
  const sd = Math.sqrt(variance)
  const q = (p) => {
    const idx = p * (n - 1)
    const lo = Math.floor(idx), hi = Math.ceil(idx)
    return t[lo] + (t[hi] - t[lo]) * (idx - lo)
  }
  const q1 = q(0.25), q3 = q(0.75), iqr = q3 - q1
  const loF = q1 - 1.5 * iqr, hiF = q3 + 1.5 * iqr
  const inliers = t.filter(v => v >= loF && v <= hiF)
  const toMs = v => v / 1e6
  return {
    n,
    meanMs: toMs(mean), sdMs: toMs(sd),
    ci95Ms: toMs(1.96 * sd / Math.sqrt(n)),
    p50Ms: toMs(q(0.50)), p90Ms: toMs(q(0.90)), p95Ms: toMs(q(0.95)), p99Ms: toMs(q(0.99)),
    minMs: toMs(t[0]), maxMs: toMs(t[n - 1]),
    opsPerSec: 1e9 / mean, opsPerSecP50: 1e9 / q(0.50),
    outlierCount: n - inliers.length,
    outlierPct: ((n - inliers.length) / n) * 100,
    trimmedMeanMs: toMs(inliers.reduce((s, v) => s + v, 0) / inliers.length),
  }
}

const median = (arr) => {
  const s = [...arr].sort((a, b) => a - b)
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2
}

// ── 読み込み ─────────────────────────────────────────────────────
const files = fs.readdirSync(dir).filter(f => f.endsWith('.json') && !f.startsWith('summary'))
if (!files.length) { console.error(`no result JSON in ${dir}`); process.exit(1) }

// key: `${lang}::${benchKey}` → [statsRun1, statsRun2, ...]
const perRun = new Map()
const envs = {}
const metas = {}
for (const f of files) {
  const doc = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'))
  envs[doc.lang] = doc.env
  if (doc.meta) for (const [k, v] of Object.entries(doc.meta)) metas[`${doc.lang}::${k}`] = v
  for (const [bk, raw] of Object.entries(doc.benches)) {
    const key = `${doc.lang}::${bk}`
    if (!perRun.has(key)) perRun.set(key, [])
    perRun.get(key).push(computeStats(raw.timings_ns))
  }
}

// ── run間中央値 ──────────────────────────────────────────────────
const STAT_KEYS = ['meanMs', 'sdMs', 'ci95Ms', 'p50Ms', 'p90Ms', 'p95Ms', 'p99Ms',
  'minMs', 'maxMs', 'opsPerSec', 'opsPerSecP50', 'outlierPct', 'trimmedMeanMs']
const agg = {}
for (const [key, runs] of perRun) {
  const a = { runs: runs.length, n: runs[0].n }
  for (const s of STAT_KEYS) a[s] = median(runs.map(r => r[s]))
  const p50s = runs.map(r => r.p50Ms)
  a.p50RunSpreadPct = ((Math.max(...p50s) - Math.min(...p50s)) / a.p50Ms) * 100
  agg[key] = a
}

// ── 出力 ─────────────────────────────────────────────────────────
fs.writeFileSync(`${prefix}.json`, JSON.stringify({ generatedAt: new Date().toISOString(), envs, meta: metas, results: agg }, null, 2))

const f3 = v => v.toFixed(3)
const f1 = v => v.toFixed(1)
let md = `# VC Format Benchmark Summary\n\n生成: ${new Date().toISOString()}\n\n`
md += `統計: 各run内で 平均/σ/95%CI/p50/p95（ns精度、パーセンタイルは線形補間、外れ値はTukey 1.5×IQRで検出のみ）を計算し、run間の中央値を表示。\n\n`

const langs = [...new Set([...perRun.keys()].map(k => k.split('::')[0]))].sort()
for (const lang of langs) {
  md += `## ${lang}\n\n`
  const e = envs[lang] ?? {}
  md += `環境: ${JSON.stringify(e.libraries ?? {})} / ${e.node ?? e.go ?? e.python ?? ''} ${e.platform ?? ''}\n\n`
  md += `| ベンチマーク | runs | N | 平均(ms) | σ(ms) | 95%CI(±ms) | p50(ms) | p95(ms) | 外れ値% | ops/sec(mean) | p50 run変動% |\n`
  md += `|---|---|---|---|---|---|---|---|---|---|---|\n`
  const keys = [...perRun.keys()].filter(k => k.startsWith(lang + '::')).sort()
  for (const k of keys) {
    const a = agg[k]
    md += `| ${k.split('::')[1]} | ${a.runs} | ${a.n} | ${f3(a.meanMs)} | ${f3(a.sdMs)} | ${f3(a.ci95Ms)} | ${f3(a.p50Ms)} | ${f3(a.p95Ms)} | ${f1(a.outlierPct)} | ${Math.round(a.opsPerSec).toLocaleString()} | ${f1(a.p50RunSpreadPct)} |\n`
  }
  md += `\n`
}
if (Object.keys(metas).length) {
  md += `## メタ情報（ペイロードサイズ等、bytes）\n\n`
  for (const [k, v] of Object.entries(metas).sort()) md += `- ${k}: ${v}\n`
  md += `\n`
}
fs.writeFileSync(`${prefix}.md`, md)
console.log(`wrote ${prefix}.json / ${prefix}.md (${perRun.size} benches, ${files.length} files)`)
