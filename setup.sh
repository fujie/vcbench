#!/usr/bin/env bash
# setup.sh — prepares a machine to run ./run-all.sh, and reports what it ended up with.
#
#   ./setup.sh              # prepare everything (Node, Go, Python)
#   ./setup.sh node python  # prepare only the listed languages
#
# Python is installed into a virtual environment inside the repository (.venv), which
# config.sh then picks up automatically, so the system Python is left untouched and
# `python3 -m pip` is never needed.
#
# Two things are pinned and both are enforced here rather than left to the machine:
#   runtimes     -- versions.env (Node exact, Go exact via GOTOOLCHAIN, Python minor)
#   dependencies -- node/package-lock.json, go/go.sum, python/requirements.txt
# A version that cannot be met is an error, not a warning, because a result file
# recording a different runtime than another cannot be placed beside it. Override
# per language with ALLOW_NODE_MISMATCH / ALLOW_GO_MISMATCH / ALLOW_PY_MISMATCH=1,
# which proceeds and prints the version to record in the environment table.
set -uo pipefail
cd "$(dirname "$0")"

WANT="${*:-node go python}"
VENV=".venv"
TOOLCHAIN_FILE=".toolchain"     # written for config.sh; gitignored

# versions.env is the single source of truth, but an explicitly exported value still
# wins, so that one-off checks do not require editing the pin file.
_env_node="${NODE_VERSION:-}"; _env_go="${GO_VERSION:-}"; _env_py="${PYTHON_MINOR:-}"
# shellcheck disable=SC1091
[[ -f versions.env ]] && . ./versions.env
NODE_VERSION="${_env_node:-${NODE_VERSION:-24.18.0}}"
GO_VERSION="${_env_go:-${GO_VERSION:-1.22.12}}"
PYTHON_MINOR="${_env_py:-${PYTHON_MINOR:-3.12}}"
unset _env_node _env_go _env_py
WANT_PY="$PYTHON_MINOR"

fail=0
note() { printf '%s\n' "$*"; }
ok()   { printf '  OK   %s\n' "$*"; }
bad()  { printf '  FAIL %s\n' "$*"; fail=1; }
hint() { printf '       -> %s\n' "$*"; }

# Pins are collected here and merged into $TOOLCHAIN_FILE at the end. They are not
# written as we go: ./setup.sh accepts a subset of the languages, and truncating the
# file up front would drop the pins a previous run recorded for the others.
PINS=()
pin() { PINS+=("$1"); }

write_toolchain() {  # keys this run is responsible for: $@
  local keep=() line key owned
  if [[ -f "$TOOLCHAIN_FILE" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" && "$line" != \#* ]] || continue
      key=${line#export }; key=${key%%=*}
      owned=0
      for k in "$@"; do [[ "$key" == "$k" ]] && owned=1; done
      [[ $owned -eq 0 ]] && keep+=("$line")
    done < "$TOOLCHAIN_FILE"
  fi
  {
    printf '# written by setup.sh from versions.env; sourced by config.sh. Do not edit.\n'
    ((${#keep[@]})) && printf '%s\n' "${keep[@]}"
    ((${#PINS[@]})) && printf '%s\n' "${PINS[@]}"
  } > "$TOOLCHAIN_FILE"
}

note "== vcbench setup =="
note "targets: $WANT"
note "pinned:  node v$NODE_VERSION / go$GO_VERSION / python $PYTHON_MINOR.x  (versions.env)"
note ""

# ──────────────────────────────────────────────────────────── Node
if [[ " $WANT " == *" node "* ]]; then
  note "-- Node.js (pinned v$NODE_VERSION)"
  NODE_BIN=""
  # The node on PATH first, then the copies the common version managers keep, so
  # that having the right version installed is enough -- no shell activation needed.
  for cand in "$(command -v node 2>/dev/null)" \
              "$HOME/.nvm/versions/node/v$NODE_VERSION/bin/node" \
              "$HOME/.local/share/fnm/node-versions/v$NODE_VERSION/installation/bin/node" \
              "$HOME/Library/Application Support/fnm/node-versions/v$NODE_VERSION/installation/bin/node" \
              "$HOME/.volta/tools/image/node/$NODE_VERSION/bin/node" \
              "/usr/local/n/versions/node/$NODE_VERSION/bin/node"; do
    [[ -n "$cand" && -x "$cand" ]] || continue
    if [[ "$("$cand" -v 2>/dev/null)" == "v$NODE_VERSION" ]]; then NODE_BIN="$cand"; break; fi
  done

  # Nothing installed matched, so fetch the official build for this platform. Go
  # already self-provisions through GOTOOLCHAIN and Python through the venv; this
  # is the same for Node, and it means a measurement machine needs no version
  # manager at all. Set VCBENCH_NO_FETCH=1 to require a preinstalled Node instead.
  if [[ -z "$NODE_BIN" && -z "${VCBENCH_NO_FETCH:-}" ]]; then
    case "$(uname -s)-$(uname -m)" in
      Linux-x86_64)   plat=linux-x64 ;;
      Linux-aarch64)  plat=linux-arm64 ;;
      Darwin-arm64)   plat=darwin-arm64 ;;
      Darwin-x86_64)  plat=darwin-x64 ;;
      *)              plat="" ;;
    esac
    local_node=".toolchains/node-v$NODE_VERSION-$plat/bin/node"
    if [[ -x "$local_node" && "$("$local_node" -v 2>/dev/null)" == "v$NODE_VERSION" ]]; then
      NODE_BIN="$local_node"
      note "     using the copy fetched earlier"
    elif [[ -z "$plat" ]]; then
      note "     no official build is published for $(uname -s)-$(uname -m); install Node yourself"
    elif ! command -v curl >/dev/null && ! command -v wget >/dev/null; then
      note "     neither curl nor wget is available, so Node cannot be fetched"
    else
      tgz="node-v$NODE_VERSION-$plat.tar.xz"
      base="https://nodejs.org/dist/v$NODE_VERSION"
      note "     Node v$NODE_VERSION not installed; fetching $tgz from nodejs.org"
      mkdir -p .toolchains
      get() {  # $1=url $2=dest
        if command -v curl >/dev/null; then curl -fsSL --retry 2 -o "$2" "$1"
        else wget -q -O "$2" "$1"; fi
      }
      if get "$base/$tgz" ".toolchains/$tgz" && get "$base/SHASUMS256.txt" ".toolchains/SHASUMS256.txt"; then
        want_sum=$(awk -v f="$tgz" '$2==f{print $1; exit}' .toolchains/SHASUMS256.txt)
        if command -v sha256sum >/dev/null; then
          got_sum=$(sha256sum ".toolchains/$tgz" | awk '{print $1}')
        else
          got_sum=$(shasum -a 256 ".toolchains/$tgz" | awk '{print $1}')
        fi
        if [[ -z "$want_sum" ]]; then
          bad "$tgz is not listed in SHASUMS256.txt -- is v$NODE_VERSION a real release?"
        elif [[ "$want_sum" != "$got_sum" ]]; then
          bad "checksum mismatch on $tgz (expected $want_sum, got $got_sum)"
          hint "the download is corrupt or tampered with; it has not been unpacked"
          rm -f ".toolchains/$tgz"
        elif tar xf ".toolchains/$tgz" -C .toolchains && [[ -x "$local_node" ]]; then
          rm -f ".toolchains/$tgz"
          NODE_BIN="$local_node"
          note "     unpacked; checksum verified against SHASUMS256.txt"
        else
          bad "could not unpack $tgz"
        fi
      else
        bad "could not download Node v$NODE_VERSION from nodejs.org"
        hint "no network? install it by hand and re-run, or use VCBENCH_NO_FETCH=1"
      fi
    fi
  fi

  if [[ -z "$NODE_BIN" ]]; then
    have=$(command -v node >/dev/null && node -v || echo "none")
    if [[ -n "${ALLOW_NODE_MISMATCH:-}" && "$have" != "none" ]]; then
      NODE_BIN="$(command -v node)"
      ok "node $have"
      note "     NOTE: not v$NODE_VERSION -- record $have in the environment table"
    else
      bad "Node.js v$NODE_VERSION not found (on PATH: $have)"
      if [[ -n "${VCBENCH_NO_FETCH:-}" ]]; then
        hint "VCBENCH_NO_FETCH is set, so the official build was not downloaded"
      else
        hint "the automatic download from nodejs.org did not succeed (see above)"
      fi
      hint "check that v$NODE_VERSION in versions.env is a real release, or install it:"
      hint "  nvm install $NODE_VERSION / fnm install $NODE_VERSION / volta install node@$NODE_VERSION"
      hint "  or unpack https://nodejs.org/dist/v$NODE_VERSION/ yourself and put it on PATH"
      hint "ALLOW_NODE_MISMATCH=1 ./setup.sh    # use $have and report it instead"
    fi
  else
    # Absolute, because npm ci runs from inside node/ and run-all.sh may be invoked
    # from anywhere; a relative path would break in both places.
    NODE_BIN="$(cd "$(dirname "$NODE_BIN")" && pwd)/$(basename "$NODE_BIN")"
    ok "node $("$NODE_BIN" -v)  ($NODE_BIN)"
  fi

  if [[ -n "$NODE_BIN" ]]; then
    pin "NODE_BIN=\"$NODE_BIN\""
    if [[ -f node/package-lock.json ]]; then
      # Run npm through the Node we just selected. The npm on PATH may belong to a
      # different Node, and installing native modules with a mismatched ABI is the
      # kind of thing that fails later and for no obvious reason.
      npm_cli="$(cd "$(dirname "$NODE_BIN")/.." && pwd)/lib/node_modules/npm/bin/npm-cli.js"
      if [[ -f "$npm_cli" ]]; then
        npm_cmd=("$NODE_BIN" "$npm_cli")
      elif command -v npm >/dev/null; then
        npm_cmd=(npm)
        note "     NOTE: using the npm on PATH ($(npm -v)); it may belong to another Node"
      else
        npm_cmd=()
        bad "no npm found next to $NODE_BIN or on PATH"
      fi
      if ((${#npm_cmd[@]})); then
        note "     npm ci (restoring the pinned dependency versions)"
        if (cd node && "${npm_cmd[@]}" ci --silent) ; then
          ok "node/node_modules restored from package-lock.json"
        else
          bad "npm ci failed"
          hint "try (cd node && ${npm_cmd[*]} ci) by hand to see the error"
        fi
      fi
    else
      bad "node/package-lock.json missing"
    fi
  fi
  note ""
fi

# ──────────────────────────────────────────────────────────── Go
if [[ " $WANT " == *" go "* ]]; then
  note "-- Go (pinned go$GO_VERSION)"
  # The version recorded in the result files is the toolchain that compiled
  # go/vc-bench, so the binary has to be rebuilt whenever the pin changes.
  # GOTOOLCHAIN makes any Go 1.21 or newer fetch and run exactly the pinned
  # toolchain, which is why no separate Go installation is required.
  export GOTOOLCHAIN="go$GO_VERSION"
  go_ok=0
  if ! command -v go >/dev/null; then
    if [[ -x go/vc-bench ]]; then
      bad "go not found, and the prebuilt go/vc-bench cannot be checked against the pin"
      hint "install any Go 1.21+ and re-run; GOTOOLCHAIN will fetch go$GO_VERSION itself"
      hint "or remove go/vc-bench and measure without Go: LANGS=\"node python\" ./run-all.sh"
    else
      bad "go not found and go/vc-bench is not built"
      hint "install any Go 1.21 or newer; GOTOOLCHAIN then fetches go$GO_VERSION"
    fi
  else
    # GOTOOLCHAIN=local asks the go on PATH about itself; without it the query
    # would be answered by the pinned toolchain we just exported.
    driver=$(GOTOOLCHAIN=local go version 2>/dev/null | awk '{print $3}')
    actual=$(GOTOOLCHAIN="go$GO_VERSION" go version 2>/dev/null | awk '{print $3}')
    if [[ "$actual" != "go$GO_VERSION" ]]; then
      if [[ -n "${ALLOW_GO_MISMATCH:-}" ]]; then
        unset GOTOOLCHAIN
        actual=$driver
        go_ok=1
        ok "go $actual"
        note "     NOTE: not go$GO_VERSION -- record $actual in the environment table"
      else
        bad "could not get go$GO_VERSION (the go on PATH is $driver, which resolved to ${actual:-nothing})"
        hint "a Go older than 1.21 cannot switch toolchains; install a newer one"
        hint "offline: go install golang.org/dl/go$GO_VERSION@latest && go$GO_VERSION download"
        hint "ALLOW_GO_MISMATCH=1 ./setup.sh    # build with $driver and report it instead"
      fi
    else
      go_ok=1
      ok "go $actual  (via GOTOOLCHAIN; the go on PATH is $driver)"
    fi
  fi

  if [[ $go_ok -eq 1 ]]; then
    [[ -n "${GOTOOLCHAIN:-}" ]] && pin "export GOTOOLCHAIN=\"$GOTOOLCHAIN\""
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
    # Build flags. -trimpath keeps local paths out of the binary. On macOS the Go
    # linker in 1.22 omits LC_UUID unless -B=gobuildid is given, and a recent dyld
    # refuses to start such a binary ("missing LC_UUID load command", abort trap 6);
    # the build itself succeeds, so only running it catches this.
    GOBUILD_FLAGS=(-trimpath)
    [[ "$(uname -s)" == "Darwin" ]] && GOBUILD_FLAGS+=(-ldflags=-B=gobuildid)
    pin "GO_BUILD_FLAGS=\"${GOBUILD_FLAGS[*]}\""

    # Always rebuild: the recorded version comes from the compiling toolchain, so a
    # binary left over from a different pin would keep reporting the old version.
    note "     building go/vc-bench with $actual (${GOBUILD_FLAGS[*]})"
    if (cd go && go build "${GOBUILD_FLAGS[@]}" -o vc-bench .) ; then
      # `go version -m <bin>` prints "<path>: go1.22.12" on the first line and then
      # tab-indented path/mod/dep/build lines, so the version is the last field of
      # line 1 -- there is no line whose first field is "go".
      built=$(go version go/vc-bench 2>/dev/null | awk 'NR==1{print $NF; exit}')
      if [[ -z "$built" ]]; then
        bad "could not read the version out of go/vc-bench"
        hint "go version go/vc-bench   # expected '<path>: go$GO_VERSION'"
      elif [[ "$built" != "go$GO_VERSION" && -z "${ALLOW_GO_MISMATCH:-}" ]]; then
        bad "the binary reports $built, not go$GO_VERSION"
        hint "this is the version the result files will record; fix it before measuring"
      else
        # A binary that builds but cannot start would otherwise be found by
        # run-all.sh, a suite into the run.
        if ./go/vc-bench -format sdjwt -n 1 -warmup 0 -out /dev/null >/dev/null 2>&1; then
          ok "go/vc-bench built and runs (compiled by $built)"
        else
          bad "go/vc-bench was built by $built but will not run"
          hint "./go/vc-bench -format sdjwt -n 1 -warmup 0 -out /dev/null   # shows the error"
          hint "on macOS, 'missing LC_UUID load command' means -B=gobuildid did not apply"
        fi
      fi
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
  note "-- Python (pinned $WANT_PY.x)"
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
    pbs_fetch() {
      # Fetch a relocatable CPython from python-build-standalone -- the same builds
      # uv installs -- so that a machine with no uv, no pyenv and no distro package
      # for this minor version can still be prepared. Needs no root: it unpacks into
      # .toolchains/ like the Node build does.
      local triple api name tag url dest sums want got
      case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)  triple=x86_64-unknown-linux-gnu ;;
        Linux-aarch64) triple=aarch64-unknown-linux-gnu ;;
        Darwin-arm64)  triple=aarch64-apple-darwin ;;
        Darwin-x86_64) triple=x86_64-apple-darwin ;;
        *) return 1 ;;
      esac
      dest=".toolchains/cpython-$WANT_PY-$triple"
      if [[ -x "$dest/bin/python3" ]]; then printf '%s\n' "$dest/bin/python3"; return 0; fi
      command -v curl >/dev/null || return 1
      api="https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest"
      name=$(curl -fsSL --retry 2 "$api" 2>/dev/null \
             | grep -o "\"cpython-$WANT_PY\.[0-9]*+[0-9]*-$triple-install_only\.tar\.gz\"" \
             | head -1 | tr -d '"')
      [[ -n "$name" ]] || return 1
      tag=${name#*+}; tag=${tag%%-*}
      url="https://github.com/astral-sh/python-build-standalone/releases/download/$tag/${name/+/%2B}"
      mkdir -p .toolchains
      note "     fetching $name (python-build-standalone)" >&2
      curl -fsSL --retry 2 -o ".toolchains/$name" "$url" || return 1
      # The release publishes one SHA256SUMS for all assets.
      sums=$(curl -fsSL --retry 2 \
        "https://github.com/astral-sh/python-build-standalone/releases/download/$tag/SHA256SUMS" 2>/dev/null)
      want=$(printf '%s\n' "$sums" | awk -v f="$name" '$2==f{print $1; exit}')
      if command -v sha256sum >/dev/null; then got=$(sha256sum ".toolchains/$name" | awk '{print $1}')
      else got=$(shasum -a 256 ".toolchains/$name" | awk '{print $1}'); fi
      if [[ -z "$want" || "$want" != "$got" ]]; then
        note "     checksum check failed for $name; not unpacking" >&2
        rm -f ".toolchains/$name"; return 1
      fi
      rm -rf "$dest.tmp"; mkdir -p "$dest.tmp"
      tar xzf ".toolchains/$name" -C "$dest.tmp" || return 1
      rm -f ".toolchains/$name"
      # install_only tarballs unpack to a single "python" directory.
      rm -rf "$dest"; mv "$dest.tmp/python" "$dest" && rm -rf "$dest.tmp"
      [[ -x "$dest/bin/python3" ]] || return 1
      note "     unpacked to $dest; checksum verified" >&2
      printf '%s\n' "$dest/bin/python3"
    }
    for cand in "python$WANT_PY" \
                "/opt/homebrew/opt/python@$WANT_PY/bin/python$WANT_PY" \
                "/usr/local/opt/python@$WANT_PY/bin/python$WANT_PY" \
                "$HOME/.pyenv/versions/$WANT_PY"*/bin/python \
                "$HOME/.local/share/uv/python/cpython-$WANT_PY"*/bin/"python$WANT_PY" \
                "$HOME/.local/share/uv/python/cpython-$WANT_PY"*/bin/python3 \
                python3 python; do
      [[ -x "$cand" ]] && [[ "$(minor_of "$cand")" == "$WANT_PY" ]] && { base="$cand"; break; }
      if command -v "$cand" >/dev/null 2>&1 && [[ "$(minor_of "$cand")" == "$WANT_PY" ]]; then
        base="$cand"; break
      fi
    done
    # Nothing installed is $WANT_PY, so fetch a standalone build, the same way the
    # Node section does. Only then fall back to complaining.
    if [[ -z "$base" && -z "${VCBENCH_NO_FETCH:-}" ]]; then
      base=$(pbs_fetch || true)
    fi
    if [[ -z "$base" ]]; then
      for cand in "python3" "python"; do
        command -v "$cand" >/dev/null 2>&1 && { have_py="$cand"; break; }
      done
      if [[ -n "${ALLOW_PY_MISMATCH:-}" && -n "${have_py:-}" ]]; then
        base="$have_py"
        note "     NOTE: $(minor_of "$base"), not $WANT_PY -- record this version with your results"
      else
        if [[ -n "${have_py:-}" ]]; then
          bad "Python $WANT_PY not found (on PATH: $("$have_py" -V 2>&1))"
        else
          bad "no Python interpreter found at all; the pin is $WANT_PY"
        fi
        if [[ -n "${VCBENCH_NO_FETCH:-}" ]]; then
          hint "VCBENCH_NO_FETCH is set, so the standalone build was not downloaded"
        else
          hint "the automatic download from python-build-standalone did not succeed"
        fi
        hint "uv:                uv python install $WANT_PY"
        hint "macOS (Homebrew):  brew install python@$WANT_PY"
        hint "Debian/Ubuntu:     sudo apt install python$WANT_PY python$WANT_PY-venv"
        hint "pyenv:             pyenv install $WANT_PY && pyenv local $WANT_PY"
        hint "ALLOW_PY_MISMATCH=1 ./setup.sh    # use what is installed and report it"
        hint "(the interpreter version changes these benchmarks by under about 1%, but"
        hint " the paper's environment table has to match whatever you actually run)"
      fi
    fi
    if [[ -n "$base" ]]; then
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

# ─────────────────────────────── record the toolchain selections ────────────
# Each language owns its own keys, so preparing one language leaves the others' pins
# in place. A failed language writes no key, which makes config.sh fall back to PATH
# rather than silently reusing a stale selection.
keys=()
[[ " $WANT " == *" node "* ]] && keys+=("NODE_BIN")
[[ " $WANT " == *" go "*   ]] && keys+=("GOTOOLCHAIN" "GO_BUILD_FLAGS")
((${#keys[@]})) && write_toolchain "${keys[@]}"

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
