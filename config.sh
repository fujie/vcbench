# linux-bench configuration file (sourced by run-all.sh)

# iterations per benchmark (paper: 2000)
N=${N:-2000}

# warmup iterations (paper: 50)
WARMUP=${WARMUP:-50}

# number of independent process runs (paper: 5; the cross-run median of each statistic is used)
RUNS=${RUNS:-5}

# languages to measure (space separated): node go python
LANGS=${LANGS:-"node go python"}

# formats to measure (space separated):
#   sdjwt jsonld jsonld-jcs mdoc (supported by all languages)
FORMATS=${FORMATS:-"sdjwt jsonld jsonld-jcs mdoc"}

# node-only additional suites (leave empty to disable):
#   jsonld-complex (complex credentials)  breakdown (signing breakdown)  serial (serialization)
#   scaling (attribute scaling)  seldisc (selective disclosure)  unified (Ed25519-unified)
#   e2e (end-to-end issue -> present -> verify, 5 of 20 attributes disclosed)
NODE_EXTRA_FORMATS=${NODE_EXTRA_FORMATS:-"jsonld-complex breakdown serial scaling seldisc unified e2e"}

# CPU pinning (e.g. "0" or "2,3"; empty disables it)
# On bare metal, pinning to a dedicated core avoids interference from other processes
CPU_PIN=${CPU_PIN:-""}

# results output directory
RESULTS_DIR=${RESULTS_DIR:-"results/$(date +%Y%m%d_%H%M%S)"}

# per-language execution commands
NODE_BIN=${NODE_BIN:-node}
PYTHON_BIN=${PYTHON_BIN:-python3}
GO_BENCH_BIN=${GO_BENCH_BIN:-./go/vc-bench}
