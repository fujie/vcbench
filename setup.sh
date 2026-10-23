#!/usr/bin/env bash
# setup.sh — prepares a machine to run ./run-all.sh, and reports what it ended up with.
#
#   ./setup.sh              # prepare everything (Node, Go, Python)
#   ./setup.sh node python  # prepare only the listed languages
#
# Python is installed into a virtual environment inside the repository (.venv), which
# config.sh then picks up automatically, so the system Python is left untouched and
# `python3 -m pip` is never needed. Everything is pinned: node/package-lock.json,
# python/requirements.txt and go/go.mod hold the versions the papers report.
set -uo pipefail
cd "$(dirname "$0")"

WANT="${*:-node go python}"
VENV=".venv"
fail=0
note() { printf '%s\n' "$*"; }
ok()   { printf '  OK   %s\n' "$*"; }
bad()  { printf '  FAIL %s\n' "$*"; fail=1; }
hint() { printf '       -> %s\n' "$*"; }

note "== vcbench setup =="
note "targets: $WANT"
note ""

# ──────────────────────────────────────────────────────────── Node
if [[ " $WANT " == *" node "* ]]; then
  note "-- Node.js"
  if ! command -v node >/dev/null; then
    bad "node not found"
    hint "install Node.js 24.x (the papers used v24.18.0)"
  else
    ok "node $(node -v)"
    if [[ -f node/package-lock.json ]]; then
      note "     npm ci (restoring the pinned dependency versions)"
      if (cd node && npm ci --silent) ; then
        ok "node/node_modules restored from package-lock.json"
      else
        bad "npm ci failed"
        hint "try (cd node && npm ci) by hand to see the error"
      fi
    else
      bad "node/package-lock.json missing"
    fi
  fi
  note ""
fi

# ──────────────────────────────────────────────────────────── Go
if [[ " $WANT " == *" go "* ]]; then
  note "-- Go"
  if [[ -x go/vc-bench ]]; then
    ok "go/vc-bench already built"
  elif ! command -v go >/dev/null; then
    bad "go not found and go/vc-bench is not built"
    hint "install Go 1.22.x (the papers used go1.22.2), or copy a prebuilt go/vc-bench"
  else
    ok "go $(go version | awk '{print $3}')"
    if [[ ! -f go/go.sum ]]; then
      note "     go/go.sum is absent, so 'go build' will resolve and record the"
      note "     dependency versions itself and leave go/go.mod modified. The"
      note "     versions still come from the require lines in go/go.mod, but the"
      note "     checksums are not pinned. Commit go/go.sum (and the go.mod that"
      note "     'go mod tidy' produces) to close that gap."
    fi
    note "     building go/vc-bench"
    if (cd go && go build -o vc-bench .) ; then
      ok "go/vc-bench built"
      vers=$(cd go && go list -m -f '{{.Path}} {{.Version}}' \
               github.com/piprate/json-gold github.com/fxamacker/cbor/v2 2>/dev/null \
             | tr '\n' ' ')
      [[ -n "$vers" ]] && note "     resolved: $vers"
    else
      bad "go build failed"
    fi
  fi
  note ""
fi

# ──────────────────────────────────────────────────────────── Python
if [[ " $WANT " == *" python "* ]]; then
  note "-- Python"
  PY=""
  if [[ -x "$VENV/bin/python" ]]; then
    PY="$VENV/bin/python"
    ok "existing $VENV found ($($PY -V 2>&1))"
  else
    # Find an interpreter to build the venv from. Prefer 3.12, which the papers used.
    base=""
    for cand in python3.12 python3 python; do
      command -v "$cand" >/dev/null && { base="$cand"; break; }
    done
    if [[ -z "$base" ]]; then
      bad "no python3 found"
      hint "install Python 3.12 (the papers used 3.12.3)"
    else
      note "     creating $VENV from $base ($($base -V 2>&1))"
      if "$base" -m venv "$VENV" 2>/dev/null; then
        PY="$VENV/bin/python"
        ok "$VENV created"
      else
        bad "$base -m venv failed (the venv module is probably not installed)"
        hint "Debian/Ubuntu: sudo apt install python3-venv"
        hint "RHEL/Fedora:   sudo dnf install python3-virtualenv"
        hint "or, if pip exists for that interpreter: $base -m pip install -r python/requirements.txt"
        hint "and then run:  PYTHON_BIN=$base ./run-all.sh"
      fi
    fi
  fi

  if [[ -n "$PY" ]]; then
    if ! "$PY" -m pip --version >/dev/null 2>&1; then
      note "     bootstrapping pip with ensurepip"
      "$PY" -m ensurepip --upgrade >/dev/null 2>&1 || true
    fi
    if "$PY" -m pip --version >/dev/null 2>&1; then
      note "     installing python/requirements.txt (pinned)"
      if "$PY" -m pip install -q -r python/requirements.txt ; then
        ok "dependencies installed"
      else
        bad "pip install failed"
        hint "network or wheel availability problem; run the command without -q to see it"
      fi
    else
      bad "$PY has no pip and ensurepip did not provide one"
      hint "Debian/Ubuntu: sudo apt install python3-venv python3-pip"
    fi

    if "$PY" -c "import cryptography, pyld, cbor2" 2>/dev/null; then
      vers=$("$PY" -c 'import importlib.metadata as m; print(", ".join(n+" "+m.version(n) for n in ("cryptography","PyLD","cbor2")))' 2>/dev/null)
      ok "imports fine: ${vers:-(version lookup failed)}"
      want=$(grep -E "^[a-zA-Z]" python/requirements.txt | tr -d " " | tr "\n" " ")
      note "     requirements.txt asks for: $want"
    else
      bad "cryptography / pyld / cbor2 still not importable"
      hint "$PY -c 'import cryptography, pyld, cbor2'   # shows which one"
    fi
  fi
  note ""
fi

# ──────────────────────────────────────────────────────────── summary
note "== result =="
if [[ $fail -eq 0 ]]; then
  note "Ready. config.sh picks up $VENV automatically, so no environment variables are needed:"
  note ""
  note "    ./run-all.sh                                   # the paper's full suite set"
  note "    LANGS=\"node\" FORMATS=\"\" \\"
  note "      NODE_EXTRA_FORMATS=\"poison security loader\" \\"
  note "      ./run-all.sh                                 # the security suites only"
  note ""
  note "Add CPU_PIN=<core> to pin the measurement process, and RESULTS_DIR=<dir> to name"
  note "the output directory. The conditions are recorded in <dir>/environment.txt."
else
  note "Something is missing; see the FAIL lines above. The other languages can still be"
  note "measured on their own, for example LANGS=\"node go\" ./run-all.sh, and the remaining"
  note "language can be added later into the same RESULTS_DIR: the aggregation reads every"
  note "result file in the directory, so a two-pass run produces one complete summary."
  exit 1
fi
