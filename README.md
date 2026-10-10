# vcbench — Verifiable Credential Format Benchmark

**English** | [日本語](README.ja.md)

A self-contained measurement kit that reproduces, on a Linux server, the performance
evaluation reported in the paper *"An Empirical Evaluation of Signature and Verification
Performance of Verifiable Credential Formats: A Cross-Language Benchmark of SD-JWT VC,
W3C VCDM, and mdoc."* The canonicalization-cost measurements it produces are also used by
the companion paper *"A Security Analysis of Verifiable Credential Verification Pipelines."*

It measures the signing and verification performance of SD-JWT VC / W3C VCDM (the W3C
Verifiable Credentials Data Model 2.0 combined with the Data Integrity cryptosuite
eddsa-rdfc-2022) / W3C VCDM (JCS) / mdoc across three languages — Node.js, Go, and
Python — using an **identical methodology and identical statistical processing**.

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
| `jsonld` | ✓ (jsonld + noLib) | ✓ (json-gold + noLib) | ✓ (PyLD + noLib) | RDFC-1.0 canonicalization + SHA-256 + Ed25519; canonicalization alone is also measured. (The `jsonld` library exposes RDFC-1.0 under the algorithm identifier `URDNA2015`.) |
| `jsonld-jcs` | ✓ (canonicalize + noLib) | ✓ (noLib) | ✓ (noLib) | JCS (RFC 8785) + SHA-256 + Ed25519 |
| `mdoc` | ✓ (cbor-x + hand-written CBOR) | ✓ (fxamacker/cbor) | ✓ (cbor2) | CBOR/COSE_Sign1 + ECDSA P-256 (raw r‖s) |
| `jsonld-complex` | ✓ (**node only**) | — | — | RDFC-1.0 canonicalization of Open Badges v3.0 / DCC-style / synthetic blank-node (10, 50) credentials (paper Table 14) |
| `breakdown` | ✓ (**node only**) | — | — | W3C VCDM signing breakdown: canonicalization / hashing / signing measured individually (Table 7) |
| `serial` | ✓ (**node only**) | — | — | Serialization speed without cryptography + payload sizes (Table 10) |
| `scaling` | ✓ (**node only**) | — | — | Attribute-count scaling 5/20/100/500 + payload sizes (Table 11) |
| `seldisc` | ✓ (**node only**) | — | — | Selective disclosure 1/3/5/10/20 of 20 (Table 12) |
| `unified` | ✓ (**node only**) | — | — | Ed25519-unified benchmark (mdoc uses COSE alg -8) (Table 13) |
| `e2e` | ✓ (**node only**) | — | — | End-to-end issue → present → verify with selective disclosure (5 of 20 attributes). Unlike the per-format suites, every format includes disclosure creation and digest matching, so the measured scope is identical across formats. `full` times one issue → present → verify pass per iteration for every format (Table 6). |
| `primitives` | ✓ (node:crypto) | ✓ (stdlib) | ✓ (cryptography) | Cryptographic primitive baseline: Ed25519 and ECDSA P-256 sign/verify and SHA-256 over a fixed 256-byte message, with no credential structure. Lets a cross-language difference in a format benchmark be attributed to the algorithm implementation rather than inferred. |
| `e2e-ed25519` | ✓ (**node only**) | — | — | The `e2e` scenario with Ed25519 for all three formats (mdoc uses COSE alg -8). |
| `e2e-p256` | ✓ (**node only**) | — | — | The `e2e` scenario with ECDSA P-256 for all three formats (SD-JWT VC uses ES256, Data Integrity uses ecdsa-rdfc-2019). Together with `e2e-ed25519` this separates the algorithm's contribution to the end-to-end totals from the pipeline's. |
| `seldisc-sd` | ✓ (**node only**) | — | — | Selective disclosure that preserves the issuer signature, using the `ecdsa-sd-2023` Data Integrity cryptosuite (P-256): issue, derive and verify for 1/2/5/10/20 of 20 attributes. The `e2e` and `seldisc` suites use `eddsa-rdfc-2022`, which has no derivation step, so the holder re-signs the disclosed subset and the issuer signature does not survive; this suite is the like-for-like comparison against SD-JWT VC and mdoc. |
| `poison` | ✓ (**node only**) | — | — | Blank-node graph families (complete, 3-regular, bidirectional ring, and the acyclic forest produced by a generator that omits `@id`) swept over size, plus a sweep of the rdf-canonize call limit `maxDeepIterations`. Each condition records its outcome (completed / aborted by the limit / truncated by the time budget) and the shape of the input (quads, blank nodes, whether it is cyclic, bytes). |
| `security` | ✓ (**node only**) | — | — | Attack vectors as verdicts rather than timings: alg:none and algorithm confusion against SD-JWT VC, data element and COSE protected header tampering against mdoc, term overriding through an unprotected `@context`, and SSRF reachability observed with a recording document loader that logs the requested URL without issuing any request. |
| `loader` | ✓ (**node only**) | — | — | JSON-LD context loader comparison under three conditions: a statically embedded context, the same loader with an injected delay (reported separately so the gap is not read as a measured network cost), and a real HTTP retrieval over the loopback interface from a server this process starts. |

The credential payloads and implementation approaches are identical to those described in
Sections 4.2 and 4.3 of the paper.

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
  "env": { "node": "v24.18.0", "libraries": { "jose": "6.2.8", ... }, ... },
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
| Table 9 (Node signing/verification) | `node :: sdjwt/*`, `jsonld/*`, `jsonld-jcs/*`, `mdoc/*` |
| Table 6 (end-to-end with selective disclosure) | `node :: e2e/<fmt>/issue\|present\|verify\|full` |
| jose reference rows in Table 9 | `node :: sdjwt/jose/*` |
| Figure 2 (Python) | `python :: */sign, */verify` |
| Figure 3 (Go) | `go :: */sign, */verify` |
| Table 14 / Figure 6 (complex credentials) | `node :: jsonld-complex/*/normalize` |
| Table 7 (signing breakdown) | `node :: breakdown/normalize\|hash\|sign` (full pipeline: `breakdown/full-pipeline-sign`) |
| Table 10 (serialization speed) | `node :: serial/*` (payload sizes are in the metadata section, `serial/*/payloadBytes`) |
| Table 11 / Figure 4 (attribute scaling) | `node :: scaling/<fmt>/<attributes>` (sizes in metadata) |
| Table 12 / Figure 5 (selective disclosure) | `node :: seldisc/<fmt>/<disclosed>of20` |
| Table 13 (Ed25519-unified) | `node :: unified/<fmt>/sign\|verify` |
| Algorithm-unified end-to-end | `node :: e2e-ed25519/<fmt>/...`, `node :: e2e-p256/<fmt>/...` |
| Issuer-signature-preserving selective disclosure | `node :: seldisc-sd/issue`, `seldisc-sd/disclose-<n>/derive\|verify` |
| Cryptographic primitive baseline | `<lang> :: prim/ed25519\|p256/sign\|verify`, `prim/sha256` |

Table 4 of the paper (execution environments) is populated from
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

Tables 4–15 and Figures 1–6 of the paper are based on running this kit under the
following conditions (Environment A; Environment B is the bare-metal cross-check).

| Item | Value |
|---|---|
| Hardware | AMD EPYC 7763 (x86_64); 2 of 4 vCPUs taken offline with SMT disabled, measurement process pinned to a single core with taskset |
| OS | Ubuntu Linux (kernel 6.17.0-azure) |
| Runtimes | Node.js v24.18.0 (OpenSSL 3.5.7) / Go 1.22.2 / Python 3.12.3 |
| Libraries | jose 6.2.8, jsonld 8.3.3 (rdf-canonize 3.4.0), cbor-x 1.6.5, canonicalize 1.0.8, PyLD 3.3.0, cbor2 6.1.5, cryptography 50.0.2, piprate/json-gold v0.8.0, fxamacker/cbor v2.9.2 |
| Parameters | N=2,000 / 50 warmup iterations / 5 independent runs |
| Environment B (cross-check) | Intel Celeron N5095 (2 cores, x86_64), SMT not supported, governor `performance`, turbo off; Linux kernel 7.0.0-38-generic; Node.js v22.22.1 / Go 1.26.0 / Python 3.14.4 |

Command used:

```bash
CPU_PIN="2" ./run-all.sh
```

## 10. License

MIT License (see `LICENSE`).

> **Data Integrity signing input.** The `jsonld` and `e2e` suites canonicalize the document *and*
> the proof options and sign `sha256(proofOptionsNQuads) || sha256(documentNQuads)` (64 bytes), as
> `eddsa-rdfc-2022` and `ecdsa-rdfc-2019` require. Earlier revisions canonicalized the document only,
> which understated the cost of the cryptosuite. `jsonld/jsonld-lib/normalize-only` and
> `normalize-both` report the two canonicalizations separately.
>
> **mdoc verification.** `mdoc/cbor-x/verify` and the `e2e` mdoc verification decode the CBOR,
> reconstruct and verify the COSE_Sign1 `Sig_structure`, and match every disclosed element's digest
> against the MSO **by `digestID`** (matching by position breaks on a disclosed subset). Every
> benchmark checks its verification result and throws on failure, so a silently failing verification
> cannot be reported as a fast one.

> **Record the OpenSSL that `cryptography` bundles.** Between cryptography 49.0.0 and 50.0.2 the
> Ed25519 primitive changed by a factor of three on macOS/arm64 (signing 3.2--3.3x, verification 2.5x),
> while the Python version made under 1% difference and ECDSA P-256 moved by at most 1.18x. The Python
> engine therefore records `openssl` alongside the package versions in every result file; compare that
> field before attributing a cross-run difference to anything else.
