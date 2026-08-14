# vcbench — Verifiable Credential Format Benchmark

**English** | [日本語](README.ja.md)

A self-contained measurement kit that reproduces, on a Linux server, the performance
evaluation reported in the paper *"A Reproducible Benchmark and Security Analysis of
Verifiable Credential Formats: Comparing SD-JWT VC, JSON-LD VC, and mdoc."*

It measures the signing and verification performance of SD-JWT VC / JSON-LD VC /
JSON-LD VC (JCS) / mdoc across three languages — Node.js, Go, and Python — using an
**identical methodology and identical statistical processing**.

- Nanosecond-precision timers (each language's monotonic clock)
- Each engine emits only raw timings; all statistics are computed by a single shared script
- Outliers are detected and reported with Tukey's fences, never removed; the median (p50) is the primary statistic
- The median of each statistic across five independent runs is reported as the final value

## 1. Layout

```
vcbench/
├── README.md            This document
├── README.ja.md         Japanese version
├── config.sh            Measurement parameters (N, RUNS, CPU pinning, etc.)
├── run-all.sh           One-shot runner (measurement through aggregation)
├── aggregate.mjs        Aggregation (shared statistics, cross-run medians, Markdown summary)
├── node/
│   ├── bench.mjs        Node.js engine
│   └── package.json     Dependencies: jose, jsonld, cbor-x, canonicalize, OB3 contexts
├── go/
│   ├── main.go          Go engine
│   └── go.mod           Dependencies: piprate/json-gold, fxamacker/cbor
├── python/
│   ├── bench.py         Python engine
│   └── requirements.txt Dependencies: cryptography, PyLD, cbor2
└── results/             Measurement results (created at run time)
```

### Coverage matrix (language × format)

| Format | node | go | python | Contents |
|---|---|---|---|---|
| `sdjwt` | ✓ (node:crypto + jose reference) | ✓ (stdlib) | ✓ (cryptography) | Ed25519 JWT signing/verification |
| `jsonld` | ✓ (jsonld + noLib) | ✓ (json-gold + noLib) | ✓ (PyLD + noLib) | URDNA2015 canonicalization + SHA-256 + Ed25519; canonicalization alone is also measured |
| `jsonld-jcs` | ✓ (canonicalize + noLib) | ✓ (noLib) | ✓ (noLib) | JCS (RFC 8785) + SHA-256 + Ed25519 |
| `mdoc` | ✓ (cbor-x + hand-written CBOR) | ✓ (fxamacker/cbor) | ✓ (cbor2) | CBOR/COSE_Sign1 + ECDSA P-256 (raw r‖s) |
| `jsonld-complex` | ✓ (**node only**) | — | — | URDNA2015 canonicalization of Open Badges v3.0 / DCC-style / synthetic blank-node (10, 50) credentials (paper Table 16) |
| `breakdown` | ✓ (**node only**) | — | — | JSON-LD signing breakdown: canonicalization / hashing / signing measured individually (Table 5) |
| `serial` | ✓ (**node only**) | — | — | Serialization speed without cryptography + payload sizes (Table 9) |
| `scaling` | ✓ (**node only**) | — | — | Attribute-count scaling 5/20/100/500 + payload sizes (Table 11) |
| `seldisc` | ✓ (**node only**) | — | — | Selective disclosure 1/3/5/10/20 of 20 (Table 12) |
| `unified` | ✓ (**node only**) | — | — | Ed25519-unified benchmark (mdoc uses COSE alg -8) (Table 15) |

The credential payloads and implementation approaches are identical to those described in
Sections 4.3.1 and 4.3.5 of the paper.

## 2. Requirements

- Linux x86_64 / arm64 (verified on Ubuntu 22.04)
- Node.js **v22 or later** (paper measurements used v24.18.0; `nvm install 22` or later is recommended)
- Go **1.21 or later** (only if you use the `go` engine)
- Python **3.10 or later** (only if you use the `python` engine)
- Internet access is required **only during setup** (npm / go mod / pip). No external
  communication occurs during measurement — all JSON-LD contexts are statically embedded.

## 3. Setup

```bash
# Place the kit on the measurement server
git clone https://github.com/fujie/vcbench.git && cd vcbench

# --- Node.js ---
cd node && npm install && cd ..

# --- Go ---
cd go && go mod tidy && go build -o vc-bench . && cd ..

# --- Python ---
python3 -m venv .venv && source .venv/bin/activate
pip install -r python/requirements.txt
```

If you installed Python dependencies in a virtualenv, either pass
`PYTHON_BIN=$PWD/.venv/bin/python3` at run time or activate the venv before running
`run-all.sh`.

### Recommended OS settings for bare metal (optional, requires root)

To minimize measurement noise, apply the following where possible (these address the
variance factors discussed in Sections 7 and 8 of the paper):

```bash
# Pin the CPU governor to performance
sudo cpupower frequency-set -g performance
# (if cpupower is unavailable)
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Disable turbo boost (Intel)
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
# (AMD) echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost

# Disable SMT (hyper-threading)
echo off | sudo tee /sys/devices/system/cpu/smt/control

# Pin the measurement process to a specific core (via CPU_PIN in run-all.sh)
CPU_PIN="2" ./run-all.sh
```

None of these are mandatory. Whatever settings are in effect are recorded automatically in
`results/<timestamp>/environment.txt`.

## 4. Running

### One-shot run (recommended)

```bash
./run-all.sh
```

By default this runs **all three languages × four formats (plus the node-only suites) at
N=2,000 iterations × 5 independent runs** and writes the raw data and aggregation
(`summary.md` / `summary.json`) to `results/<timestamp>/`.
Expect a few minutes, depending on machine performance.

Targets and parameters can be overridden with environment variables:

```bash
N=500 RUNS=3 ./run-all.sh                          # shortened run (smoke test)
LANGS="node" FORMATS="sdjwt jsonld" ./run-all.sh   # only two formats on Node
LANGS="go python" NODE_EXTRA_FORMATS="" ./run-all.sh
CPU_PIN="2" ./run-all.sh                           # pin to core 2
```

### Running a single language / format

All engines share the same CLI (`--format` / `--n` / `--warmup` / `--out`):

```bash
# Node.js
node node/bench.mjs --format sdjwt --n 2000 --warmup 50 --out results/node_sdjwt_run1.json

# Go (pre-built binary)
./go/vc-bench -format mdoc -n 2000 -warmup 50 -out results/go_mdoc_run1.json

# Python
python3 python/bench.py --format jsonld --n 2000 --warmup 50 --out results/python_jsonld_run1.json

# Complex credentials (node only)
node node/bench.mjs --format jsonld-complex --n 2000 --out results/node_complex_run1.json
```

Results produced by individual runs can be aggregated by collecting them in one directory:

```bash
node aggregate.mjs results/ results/summary
```

## 5. Methodology (identical to Section 4.3.1 of the paper)

1. **Timers**: Node = `process.hrtime.bigint()`, Go = `time.Now()` (monotonic),
   Python = `time.perf_counter_ns()` — all nanosecond precision.
2. **Procedure**: 50 warmup iterations (to stabilize JIT and caches) → N=2,000 measured
   iterations. **Each iteration is timed individually** (never in batches).
3. **Engines emit only raw timings (ns)**; statistics are computed by `aggregate.mjs`
   with logic shared across all languages:
   - Mean, sample standard deviation (σ), 95% confidence interval
   - p50/p90/p95/p99 (linear interpolation), min/max
   - Outliers: Tukey's fences (outside Q1−1.5×IQR … Q3+1.5×IQR) are **detected and
     counted only**, never removed
   - Trimmed mean (excluding Tukey outliers; a reference value for cross-checking p50)
4. **Five independent runs**: the suite is repeated in separate processes RUNS times and
   the **cross-run median of each statistic** is reported as the final value. The
   "p50 run variation %" column in `summary.md` shows run-to-run stability (within 3% for
   most benchmarks in the paper).
5. **Representative value**: because the distributions have a long right tail, the primary
   statistic for comparison is the **median (p50)**; the mean is reported for reference.

## 6. Output format

### Raw data (`<lang>_<format>_run<k>.json`)

```json
{
  "lang": "node", "format": "sdjwt", "n": 2000, "warmup": 50,
  "env": { "node": "v24.18.0", "libraries": { "jose": "6.2.3", ... }, ... },
  "benches": {
    "sdjwt/stdcrypto/sign": { "n": 2000, "warmup": 50, "timings_ns": [26208, ...] }
  }
}
```

Benchmark keys follow the form `format/implementation(library)/operation` —
for example `jsonld/json-gold/verify`, `mdoc/cbor2/sign`, `jsonld-complex/ob3/normalize`.

### Aggregation (`summary.md` / `summary.json`)

A Markdown table per language (mean, σ, 95%CI, p50, p95, outlier %, ops/sec, and p50
run-to-run variation %, all to three decimal places). `summary.json` is the
machine-readable form used when updating the tables in the paper.

## 7. Mapping to the paper

| Paper table / figure | Key in summary.md |
|---|---|
| Tables 4 and 8 (Node signing/verification) | `node :: sdjwt/*`, `jsonld/*`, `jsonld-jcs/*`, `mdoc/*` |
| jose reference rows in Table 8 | `node :: sdjwt/jose/*` |
| Figure 2 (Python) | `python :: */sign, */verify` |
| Figure 3 (Go) | `go :: */sign, */verify` |
| Table 16 / Figure 6 (complex credentials) | `node :: jsonld-complex/*/normalize` |
| Table 5 (signing breakdown) | `node :: breakdown/normalize\|hash\|sign` (full pipeline: `breakdown/full-pipeline-sign`) |
| Table 9 (serialization speed) | `node :: serial/*` (payload sizes are in the metadata section, `serial/*/payloadBytes`) |
| Table 11 / Figure 4 (attribute scaling) | `node :: scaling/<fmt>/<attributes>` (sizes in metadata) |
| Table 12 / Figure 5 (selective disclosure) | `node :: seldisc/<fmt>/<disclosed>of20` |
| Table 15 (Ed25519-unified) | `node :: unified/<fmt>/sign\|verify` |

Table 2 of the paper (execution environment) is populated from
`results/<timestamp>/environment.txt` (CPU model, SMT/governor settings, and so on).

## 8. Troubleshooting

- **`npm install` fails to build a native module**: `cbor-x` falls back to building from
  source where no prebuilt binary exists. Install `build-essential`, or simply proceed —
  it also works via its pure-JS fallback.
- **Fetching `json-gold` fails in Go**: set `GOPROXY` if you are behind a proxy.
- **`pyld` is slow in Python**: this is expected (a pure Python implementation). The paper
  states explicitly that cross-language comparison targets relative ordering and trends.
- **Large run-to-run variation (p50 run variation %)**: interference from other processes
  is likely. Consider using `CPU_PIN`, pinning the CPU governor, or increasing RUNS
  (for example `RUNS=9`).

## 9. Measurement conditions reported in the paper

Tables 4–16 and Figures 1–6 of the paper are based on running this kit under the
following conditions.

| Item | Value |
|---|---|
| Hardware | AMD EPYC 7763 (x86_64); 2 of 4 vCPUs taken offline with SMT disabled, measurement process pinned to a single core with taskset |
| OS | Ubuntu Linux (kernel 6.17.0-azure) |
| Runtimes | Node.js v24.18.0 (OpenSSL 3.5.7) / Go 1.22.2 / Python 3.12.3 |
| Libraries | jose 6.2.3, jsonld 8.3.3 (rdf-canonize 3.4.0), cbor-x 1.6.4, canonicalize 1.0.8, PyLD 3.1.0, cbor2 6.1.3, cryptography 49.0.0, piprate/json-gold v0.8.0, fxamacker/cbor v2.9.2 |
| Parameters | N=2,000 / 50 warmup iterations / 5 independent runs |

Command used:

```bash
CPU_PIN="2" ./run-all.sh
```

## 10. License

MIT License (see `LICENSE`).
