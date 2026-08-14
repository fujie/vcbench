# linux-bench 設定ファイル（run-all.sh が source する）

# ベンチマークあたりのイテレーション数（論文: 2000）
N=${N:-2000}

# ウォームアップ回数（論文: 50）
WARMUP=${WARMUP:-50}

# 独立プロセス実行の回数（論文: 5。各統計量のrun間中央値を採用）
RUNS=${RUNS:-5}

# 計測する言語（スペース区切り）: node go python
LANGS=${LANGS:-"node go python"}

# 計測するフォーマット（スペース区切り）:
#   sdjwt jsonld jsonld-jcs mdoc（全言語対応）
FORMATS=${FORMATS:-"sdjwt jsonld jsonld-jcs mdoc"}

# node のみの追加スイート（空にすると無効）:
#   jsonld-complex（論文表16） breakdown（表5） serial（表9）
#   scaling（表11） seldisc（表12） unified（表15）
NODE_EXTRA_FORMATS=${NODE_EXTRA_FORMATS:-"jsonld-complex breakdown serial scaling seldisc unified"}

# CPUピニング（例: "0" や "2,3"。空なら無効）
# ベアメタルでは特定コアに固定して他プロセスの干渉を避けることを推奨
CPU_PIN=${CPU_PIN:-""}

# 結果出力ディレクトリ
RESULTS_DIR=${RESULTS_DIR:-"results/$(date +%Y%m%d_%H%M%S)"}

# 各言語の実行コマンド
NODE_BIN=${NODE_BIN:-node}
PYTHON_BIN=${PYTHON_BIN:-python3}
GO_BENCH_BIN=${GO_BENCH_BIN:-./go/vc-bench}
