# linux-bench configuration file (sourced by run-all.sh)

# iterations per benchmark (paper: 2000)
N=${N:-2000}

# warmup iterations (paper: 50)
WARMUP=${WARMUP:-50}

# number of independent process runs (paper: 5; the cross-run median of each statistic is used)
RUNS=${RUNS:-5}

# languages to measure (space separated): node go python
LANGS=${LANGS-"node go python"}

# formats to measure (space separated):
#   sdjwt jsonld jsonld-jcs mdoc primitives (supported by all languages)
#   primitives = cryptographic primitive baseline (Ed25519 / P-256 / SHA-256 alone)
FORMATS=${FORMATS-"sdjwt jsonld jsonld-jcs mdoc primitives"}

# node-only additional suites (leave empty to disable):
#   jsonld-complex (complex credentials)  breakdown (signing breakdown)  serial (serialization)
#   scaling (attribute scaling)  seldisc (selective disclosure)  unified (Ed25519-unified)
#   e2e (end-to-end issue -> present -> verify, 5 of 20 attributes disclosed)
#   e2e-ed25519 / e2e-p256 (the same scenario with one algorithm across all three formats)
#   seldisc-sd (ecdsa-sd-2023: selective disclosure that preserves the issuer signature)
#   poison security loader (security suites; see the security paper)
NODE_EXTRA_FORMATS=${NODE_EXTRA_FORMATS-"jsonld-complex breakdown serial scaling seldisc seldisc-sd unified e2e e2e-ed25519 e2e-p256"}

# CPU pinning (e.g. "0" or "2,3"; empty disables it)
# On bare metal, pinning to a dedicated core avoids interference from other processes
CPU_PIN=${CPU_PIN:-""}

# results output directory
RESULTS_DIR=${RESULTS_DIR:-"results/$(date +%Y%m%d_%H%M%S)"}

# Toolchain selections that setup.sh resolved against versions.env (NODE_BIN,
# GOTOOLCHAIN, GO_BUILD_FLAGS). Sourcing them here is what makes `./run-all.sh` measure with the
# pinned versions rather than whatever happens to be first on PATH. Values already
# set in the environment still win, so an explicit override works as before.
if [[ -f "$(dirname "${BASH_SOURCE[0]}")/.toolchain" ]]; then
  _vcb_node_pre="${NODE_BIN:-}"
  # shellcheck disable=SC1090,SC1091
  . "$(dirname "${BASH_SOURCE[0]}")/.toolchain"
  [[ -n "$_vcb_node_pre" ]] && NODE_BIN="$_vcb_node_pre"
  unset _vcb_node_pre
fi

# per-language execution commands
NODE_BIN=${NODE_BIN:-node}
# Python interpreter. Defaults to the repository-local virtual environment that
# setup.sh creates, so that `./run-all.sh` needs no environment variables and the
# system Python is never touched; falls back to python3 when there is no .venv.
if [[ -z "${PYTHON_BIN:-}" && -x "$(dirname "${BASH_SOURCE[0]}")/.venv/bin/python" ]]; then
  PYTHON_BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.venv/bin/python"
fi
PYTHON_BIN=${PYTHON_BIN:-python3}
GO_BENCH_BIN=${GO_BENCH_BIN:-./go/vc-bench}
