# vcbench — Verifiable Credential フォーマット比較ベンチマーク

[English](README.md) | **日本語**

論文「Verifiable Credential フォーマットの再現可能なベンチマークとセキュリティ分析：
SD-JWT VC、JSON-LD VC、mdoc の比較」の性能計測を、Linuxサーバ上で言語別・
クレデンシャルフォーマット別に再現するための自己完結型の計測キットです。

SD-JWT VC / JSON-LD VC / JSON-LD VC (JCS) / mdoc の署名・検証性能を、
Node.js・Go・Python の3言語で**同一手法・同一統計処理**により計測します。

- 計測タイマはナノ秒精度（各言語のモノトニッククロック）
- 各エンジンは生タイミングのみ出力し、統計計算は全言語共通スクリプトで実施
- 外れ値は Tukey 基準で検出・報告のみ（除去しない）、代表値は中央値(p50)
- 独立5回実行の統計量中央値を最終値として報告

## 1. 構成

```
vcbench/
├── README.md            英語版ドキュメント
├── README.ja.md         このドキュメント
├── config.sh            計測パラメータ設定（N, RUNS, CPUピニング等）
├── run-all.sh           一括実行スクリプト（計測→集計まで）
├── aggregate.mjs        統計集計（全言語共通の統計計算・run間中央値・Markdownサマリ）
├── node/
│   ├── bench.mjs        Node.jsエンジン
│   └── package.json     依存: jose, jsonld, cbor-x, canonicalize, OB3コンテキスト
├── go/
│   ├── main.go          Goエンジン
│   └── go.mod           依存: piprate/json-gold, fxamacker/cbor
├── python/
│   ├── bench.py         Pythonエンジン
│   └── requirements.txt 依存: cryptography, PyLD, cbor2
└── results/             計測結果（実行時に生成）
```

### 対応マトリクス（言語 × フォーマット）

| フォーマット | node | go | python | 内容 |
|---|---|---|---|---|
| `sdjwt` | ✓（node:crypto + jose参考値） | ✓（stdlib） | ✓（cryptography） | Ed25519 JWT の署名/検証 |
| `jsonld` | ✓（jsonld + noLib） | ✓（json-gold + noLib） | ✓（PyLD + noLib） | URDNA2015正規化 + SHA-256 + Ed25519。normalize単体も計測 |
| `jsonld-jcs` | ✓（canonicalize + noLib） | ✓（noLib） | ✓（noLib） | JCS (RFC 8785) + SHA-256 + Ed25519 |
| `mdoc` | ✓（cbor-x + 手書きCBOR） | ✓（fxamacker/cbor） | ✓（cbor2） | CBOR/COSE_Sign1 + ECDSA P-256（raw r‖s） |
| `jsonld-complex` | ✓（**nodeのみ**） | — | — | OpenBadges v3.0 / DCC型 / 合成ブランクノード10・50 のURDNA2015正規化（論文表16） |
| `breakdown` | ✓（**nodeのみ**） | — | — | JSON-LD署名処理の内訳: 正規化/ハッシュ/署名を個別計測（論文表5） |
| `serial` | ✓（**nodeのみ**） | — | — | シリアライズ速度・暗号処理なし + ペイロードサイズ（論文表9） |
| `scaling` | ✓（**nodeのみ**） | — | — | 属性数スケーリング 5/20/100/500 + ペイロードサイズ（論文表11） |
| `seldisc` | ✓（**nodeのみ**） | — | — | 選択的開示 1/3/5/10/20 of 20（論文表12） |
| `unified` | ✓（**nodeのみ**） | — | — | Ed25519統一ベンチ（mdocはCOSE alg -8）（論文表15） |

クレデンシャルのペイロード・実装方式は論文4.3.1／4.3.5節と同一です。

## 2. 前提環境

- Linux x86_64 / arm64（Ubuntu 22.04 で動作確認）
- Node.js **v22以降**（論文計測: v24.18.0。`nvm install 22` 以降を推奨）
- Go **1.21以上**（`go` エンジンを使う場合）
- Python **3.10以上**（`python` エンジンを使う場合）
- インターネット接続は**セットアップ時のみ**必要（npm/go mod/pip）。計測中の外部通信はありません
  （JSON-LDコンテキストはすべて静的埋め込み）。

## 3. セットアップ

```bash
# 計測サーバへ配置
git clone https://github.com/fujie/vcbench.git && cd vcbench

# --- Node.js ---
cd node && npm install && cd ..

# --- Go ---
cd go && go mod tidy && go build -o vc-bench . && cd ..

# --- Python ---
python3 -m venv .venv && source .venv/bin/activate
pip install -r python/requirements.txt
```

Python を venv で入れた場合は、実行時に `PYTHON_BIN=$PWD/.venv/bin/python3` を指定するか、
venv を activate した状態で `run-all.sh` を実行してください。

### ベアメタルでの推奨OS設定（任意・要root）

計測ノイズを最小化するため、可能であれば以下を設定します（論文7章・8章の変動要因対策）:

```bash
# CPUガバナを performance に固定
sudo cpupower frequency-set -g performance
#（cpupowerが無い場合）
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# ターボブースト無効化（Intel）
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
# （AMD） echo 0 | sudo tee /sys/devices/system/cpu/cpufreq/boost

# SMT（ハイパースレッディング）無効化
echo off | sudo tee /sys/devices/system/cpu/smt/control

# 計測プロセスを特定コアに固定（run-all.sh の CPU_PIN で指定）
CPU_PIN="2" ./run-all.sh
```

これらは必須ではありません。設定内容は `results/<日時>/environment.txt` に自動記録されます。

## 4. 実行方法

### 一括実行（推奨）

```bash
./run-all.sh
```

既定では **全3言語 × 4フォーマット（+ node の jsonld-complex）を、N=2,000イテレーション × 独立5回**
実行し、`results/<日時>/` に生データと集計（`summary.md` / `summary.json`）を出力します。
所要時間の目安: 数分（jsonld-complex を含む。マシン性能に依存）。

対象・パラメータは環境変数で上書きできます:

```bash
N=500 RUNS=3 ./run-all.sh                    # 短縮実行（動作確認用）
LANGS="node" FORMATS="sdjwt jsonld" ./run-all.sh   # Nodeの2フォーマットだけ
LANGS="go python" NODE_EXTRA_FORMATS="" ./run-all.sh
CPU_PIN="2" ./run-all.sh                     # コア2に固定
```

### 言語別・フォーマット別の個別実行

各エンジンは共通のCLIを持ちます（`--format`/`--n`/`--warmup`/`--out`）:

```bash
# Node.js
node node/bench.mjs --format sdjwt --n 2000 --warmup 50 --out results/node_sdjwt_run1.json

# Go（ビルド済みバイナリ）
./go/vc-bench -format mdoc -n 2000 -warmup 50 -out results/go_mdoc_run1.json

# Python
python3 python/bench.py --format jsonld --n 2000 --warmup 50 --out results/python_jsonld_run1.json

# 複雑クレデンシャル（nodeのみ）
node node/bench.mjs --format jsonld-complex --n 2000 --out results/node_complex_run1.json
```

個別実行した結果も、同じディレクトリに集めて集計できます:

```bash
node aggregate.mjs results/ results/summary
```

## 5. 計測方法（論文4.3.1節と同一）

1. **タイマ**: Node = `process.hrtime.bigint()`、Go = `time.Now()`（モノトニック）、
   Python = `time.perf_counter_ns()`。いずれもナノ秒精度。
2. **手順**: ウォームアップ50回（JIT・キャッシュ安定化）→ 本計測N=2,000回。
   **各イテレーションの所要時間を個別に記録**します（バッチ計測はしない）。
3. **エンジンは生タイミング(ns)のみ出力**し、統計計算は `aggregate.mjs` が全言語共通ロジックで行います:
   - 平均・標本標準偏差(σ)・95%信頼区間
   - p50/p90/p95/p99（線形補間）・min/max
   - 外れ値: Tukey基準（Q1−1.5×IQR 〜 Q3+1.5×IQR の外側）を**検出・件数報告のみ**（除去しない）
   - トリム平均（Tukey外れ値除外。p50との一致確認用の参考値）
4. **独立5回実行**: プロセスを分けてRUNS回繰り返し、**各統計量のrun間中央値**を最終値とします。
   `summary.md` の「p50 run変動%」列でrun間の安定性を確認できます（論文では大半が3%以内）。
5. **代表値**: 分布が右裾に長いため、比較の主たる統計量は**中央値(p50)**、平均は参考値です。

## 6. 出力形式

### 生データ（`<lang>_<format>_run<k>.json`）

```json
{
  "lang": "node", "format": "sdjwt", "n": 2000, "warmup": 50,
  "env": { "node": "v24.18.0", "libraries": { "jose": "6.2.3", ... }, ... },
  "benches": {
    "sdjwt/stdcrypto/sign": { "n": 2000, "warmup": 50, "timings_ns": [26208, ...] }
  }
}
```

ベンチマークキーは `フォーマット/実装(ライブラリ)/操作` の形式です。
例: `jsonld/json-gold/verify`, `mdoc/cbor2/sign`, `jsonld-complex/ob3/normalize`。

### 集計（`summary.md` / `summary.json`）

言語ごとのMarkdown表（平均・σ・95%CI・p50・p95・外れ値%・ops/sec・p50 run変動%、すべて小数第3位）。
`summary.json` は論文の表を差し替える際の機械可読データです。

## 7. 論文への反映

| 論文の表・図 | summary.md の対応キー |
|---|---|
| 表4・表8（Node署名/検証） | `node :: sdjwt/*`, `jsonld/*`, `jsonld-jcs/*`, `mdoc/*` |
| 表8のjose参考行 | `node :: sdjwt/jose/*` |
| 図2（Python） | `python :: */sign, */verify` |
| 図3（Go） | `go :: */sign, */verify` |
| 表16・図6（複雑クレデンシャル） | `node :: jsonld-complex/*/normalize` |
| 表5（署名処理内訳） | `node :: breakdown/normalize|hash|sign`（全体は `breakdown/full-pipeline-sign`） |
| 表9（シリアライズ速度） | `node :: serial/*`（ペイロードサイズはメタ情報 `serial/*/payloadBytes`） |
| 表11・図4（属性数スケーリング） | `node :: scaling/<fmt>/<属性数>`（サイズはメタ情報） |
| 表12・図5（選択的開示） | `node :: seldisc/<fmt>/<開示数>of20` |
| 表15（Ed25519統一） | `node :: unified/<fmt>/sign|verify` |

表2（実行環境）には `results/<日時>/environment.txt` の内容（CPU型番・SMT/ガバナ設定等）を反映します。

## 8. トラブルシューティング

- `npm install` でネイティブビルドに失敗する: `cbor-x` はプリビルトバイナリが無い環境で
  ソースビルドにフォールバックします。`build-essential` を導入するか、失敗しても
  pure-JS フォールバックで動作します。
- Go の `json-gold` 取得に失敗する: プロキシ環境では `GOPROXY` を設定してください。
- Python で `pyld` が遅い: 仕様どおりです（pure Python実装）。論文でも言語間比較は
  相対順位の確認が目的である旨を明記しています。
- run間変動（p50 run変動%）が大きい: 他プロセスの干渉が疑われます。`CPU_PIN` の利用、
  ガバナ固定、RUNS を増やす（例: `RUNS=9`）ことを検討してください。

## 9. 論文で報告した計測条件

論文の表4〜16および図1〜6は、本キットを以下の条件で実行した結果に基づきます。

| 項目 | 値 |
|---|---|
| ハードウェア | AMD EPYC 7763 (x86_64)。4 vCPU中2コアをオフライン化しSMT無効、tasksetで単一コアに固定 |
| OS | Ubuntu Linux (kernel 6.17.0-azure) |
| ランタイム | Node.js v24.18.0 (OpenSSL 3.5.7) / Go 1.22.2 / Python 3.12.3 |
| ライブラリ | jose 6.2.3, jsonld 8.3.3 (rdf-canonize 3.4.0), cbor-x 1.6.4, canonicalize 1.0.8, PyLD 3.1.0, cbor2 6.1.3, cryptography 49.0.0, piprate/json-gold v0.8.0, fxamacker/cbor v2.9.2 |
| パラメータ | N=2,000 / ウォームアップ50回 / 独立5回実行 |

実行コマンド:

```bash
CPU_PIN="2" ./run-all.sh
```

## 10. ライセンス

MIT License（`LICENSE` を参照）。
