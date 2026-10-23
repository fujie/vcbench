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
# The minor version the papers report. The runtime itself makes under about 1% of
# difference to these benchmarks -- the dependency versions are what matter -- but a
# result file that records a different interpreter than the paper's table cannot be
# compared against it, so a mismatch is an error here rather than a warning.
# Set ALLOW_PY_MISMATCH=1 to proceed anyway and record the version you actually used.
WANT_PY="3.12"
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
      # Without go.sum, 'go build' resolves the dependencies itself and adds the
      # indirect requires to go.mod, which both leaves the checkout dirty and
      # leaves the checksums unpinned. Produce it here instead of reporting it.
      note "     go/go.sum is absent; running 'go mod tidy' to create it"
      if (cd go && go mod tidy) ; then
        ok "go/go.sum written ($(grep -c . go/go.sum 2>/dev/null) entries)"
      else
        bad "go mod tidy failed"
        hint "network access to the module proxy is needed the first time"
        hint "offline with a module cache: (cd go && GOFLAGS=-mod=mod go mod tidy)"
      fi
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
  minor_of() { "$1" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null; }

  if [[ -x "$VENV/bin/python" ]]; then
    got=$(minor_of "$VENV/bin/python")
    if [[ "$got" == "$WANT_PY" || -n "${ALLOW_PY_MISMATCH:-}" ]]; then
      PY="$VENV/bin/python"
      ok "existing $VENV found ($($PY -V 2>&1))"
      [[ "$got" != "$WANT_PY" ]] && note "     NOTE: $got, not $WANT_PY -- record this version with your results"
    else
      bad "existing $VENV is Python $got, but the papers used $WANT_PY"
      hint "rm -rf $VENV && ./setup.sh        # rebuild it on $WANT_PY"
      hint "ALLOW_PY_MISMATCH=1 ./setup.sh    # keep $got and report it instead"
    fi
  else
    # Find an interpreter to build the venv from. python3 is deliberately last:
    # on Homebrew and pyenv machines it is whatever is newest, not what we want.
    base=""
    for cand in "python$WANT_PY" \
                "/opt/homebrew/opt/python@$WANT_PY/bin/python$WANT_PY" \
                "/usr/local/opt/python@$WANT_PY/bin/python$WANT_PY" \
                "$HOME/.pyenv/versions/$WANT_PY"*/bin/python \
                python3 python; do
      [[ -x "$cand" ]] && { base="$cand"; break; }
      command -v "$cand" >/dev/null 2>&1 && { base="$cand"; break; }
    done
    if [[ -z "$base" ]]; then
      bad "no Python interpreter found"
      hint "install Python $WANT_PY (the papers used 3.12.3 and 3.12.15)"
    elif [[ "$(minor_of "$base")" != "$WANT_PY" && -z "${ALLOW_PY_MISMATCH:-}" ]]; then
      bad "only Python $(minor_of "$base") is available ($base); the papers used $WANT_PY"
      hint "macOS (Homebrew):  brew install python@$WANT_PY"
      hint "Debian/Ubuntu:     sudo apt install python$WANT_PY python$WANT_PY-venv"
      hint "pyenv:             pyenv install $WANT_PY && pyenv local $WANT_PY"
      hint "ALLOW_PY_MISMATCH=1 ./setup.sh    # use $(minor_of "$base") and report it instead"
      hint "(the interpreter version changes these benchmarks by under about 1%, but"
      hint " the paper's environment table has to match whatever you actually run)"
    else
      note "     creating $VENV from $base ($($base -V 2>&1))"
      if "$base" -m venv "$VENV" 2>/dev/null; then
        PY="$VENV/bin/python"
        ok "$VENV created ($($PY -V 2>&1))"
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

# ─────────────────────────────── did setup leave tracked Go files changed? ──
# run-all.sh stamps the kit commit into environment.txt and marks it "(dirty)" if
# anything is uncommitted, so an archive is easier to interpret if these are
# committed before measuring rather than after.
if command -v git >/dev/null && git rev-parse --git-dir >/dev/null 2>&1; then
  godirty=$(git status --porcelain -- go/go.mod go/go.sum 2>/dev/null)
  if [[ -n "$godirty" ]]; then
    note "-- note: setup changed the Go module files"
    printf '%s\n' "$godirty" | sed 's/^/       /'
    note "       Committing them keeps environment.txt from recording \"(dirty)\":"
    note "         git add go/go.mod go/go.sum && git commit -m 'build: pin the Go module checksums'"
    note ""
  fi
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
