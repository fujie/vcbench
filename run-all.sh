#!/usr/bin/env bash
# run-all.sh — 全言語 × 全フォーマット × RUNS回 の計測を一括実行し、集計する。
#
#   ./run-all.sh                    # config.sh の既定値で実行
#   N=500 RUNS=3 ./run-all.sh       # 環境変数で上書き
#   LANGS="node" FORMATS="sdjwt" ./run-all.sh   # 対象を絞る
#   CPU_PIN="2" ./run-all.sh        # CPUコア2に固定して実行
set -euo pipefail
cd "$(dirname "$0")"
source ./config.sh

mkdir -p "$RESULTS_DIR"
echo "== linux-bench =="
echo "N=$N WARMUP=$WARMUP RUNS=$RUNS"
echo "LANGS=$LANGS FORMATS=$FORMATS"
echo "RESULTS_DIR=$RESULTS_DIR"

PIN=""
if [[ -n "$CPU_PIN" ]]; then
  PIN="taskset -c $CPU_PIN"
  echo "CPU_PIN=$CPU_PIN (taskset)"
fi

# ── 事前チェック / ビルド ────────────────────────────────────────
for lang in $LANGS; do
  case "$lang" in
    node)
      command -v "$NODE_BIN" >/dev/null || { echo "ERROR: node が見つかりません"; exit 1; }
      [[ -d node/node_modules ]] || { echo "ERROR: 先に (cd node && npm install) を実行してください"; exit 1; }
      ;;
    go)
      if [[ ! -x "$GO_BENCH_BIN" ]]; then
        command -v go >/dev/null || { echo "ERROR: go が見つかりません（または事前に go/vc-bench をビルドして配置）"; exit 1; }
        echo "-- building go/vc-bench"
        (cd go && go build -o vc-bench .)
      fi
      ;;
    python)
      command -v "$PYTHON_BIN" >/dev/null || { echo "ERROR: python3 が見つかりません"; exit 1; }
      "$PYTHON_BIN" -c "import cryptography, pyld, cbor2" 2>/dev/null || {
        echo "ERROR: 先に $PYTHON_BIN -m pip install -r python/requirements.txt を実行してください"; exit 1; }
      ;;
  esac
done

# ── 環境情報スナップショット ─────────────────────────────────────
{
  echo "date: $(date -Iseconds)"
  echo "kernel: $(uname -srmo)"
  command -v lscpu >/dev/null && lscpu | grep -E "Model name|CPU\(s\)|MHz|Vendor" || true
  echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
  echo "turbo(no_turbo): $(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo n/a)"
  echo "smt: $(cat /sys/devices/system/cpu/smt/control 2>/dev/null || echo n/a)"
} > "$RESULTS_DIR/environment.txt"
echo "-- environment snapshot -> $RESULTS_DIR/environment.txt"

# ── 計測本体 ─────────────────────────────────────────────────────
run_one() {  # $1=lang $2=format $3=run
  local lang=$1 fmt=$2 run=$3
  local out="$RESULTS_DIR/${lang}_${fmt}_run${run}.json"
  echo "== [$lang / $fmt] run $run/$RUNS -> $out"
  case "$lang" in
    node)   $PIN "$NODE_BIN" node/bench.mjs --format "$fmt" --n "$N" --warmup "$WARMUP" --out "$out" ;;
    go)     $PIN "$GO_BENCH_BIN" -format "$fmt" -n "$N" -warmup "$WARMUP" -out "$out" ;;
    python) $PIN "$PYTHON_BIN" python/bench.py --format "$fmt" --n "$N" --warmup "$WARMUP" --out "$out" ;;
  esac
}

for run in $(seq 1 "$RUNS"); do
  for lang in $LANGS; do
    for fmt in $FORMATS; do
      run_one "$lang" "$fmt" "$run"
    done
    if [[ "$lang" == "node" && -n "${NODE_EXTRA_FORMATS// /}" ]]; then
      for fmt in $NODE_EXTRA_FORMATS; do
        run_one node "$fmt" "$run"
      done
    fi
  done
done

# ── 集計 ─────────────────────────────────────────────────────────
echo "== aggregate"
"$NODE_BIN" aggregate.mjs "$RESULTS_DIR" "$RESULTS_DIR/summary"
echo "== done: $RESULTS_DIR/summary.md"
