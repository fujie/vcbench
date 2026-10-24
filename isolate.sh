#!/usr/bin/env bash
# isolate.sh — apply and verify the measurement isolation, then report what stuck.
#
#   sudo ./isolate.sh azure     # Environment A: 2 of 4 vCPUs offline, SMT off
#   sudo ./isolate.sh baremetal # Environment B: governor performance, turbo off
#   ./isolate.sh check          # report the current state, change nothing
#
# Why this exists: the isolation is what the papers' environment table claims, and
# it does not survive a reboot or a VM resize. In the 2026-10-23/24 round both
# machines were measured without it -- Environment A with SMT on and all vCPUs
# online, Environment B with the powersave governor and turbo enabled (max clock
# 2900 MHz instead of the 2000 MHz base) -- which is not visible in the numbers
# themselves, only in environment.txt afterwards. Run this before ./run-all.sh.
set -uo pipefail
cd "$(dirname "$0")"

MODE="${1:-check}"
w() { printf '  %-30s %s\n' "$1" "$2"; }
need_root() {
  [[ $EUID -eq 0 ]] || { echo "this mode changes kernel settings; run it with sudo"; exit 1; }
}

report() {
  echo "== current state"
  if [[ -r /sys/devices/system/cpu/smt/control ]]; then
    w "SMT" "$(cat /sys/devices/system/cpu/smt/control)"
  else
    w "SMT" "no sysfs control (not supported, or macOS)"
  fi
  if command -v lscpu >/dev/null; then
    w "online CPUs"  "$(lscpu | awk -F: '/On-line/{gsub(/ /,"",$2); print $2}')"
    w "offline CPUs" "$(lscpu | awk -F: '/Off-line/{gsub(/ /,"",$2); print $2}')"
    w "max MHz"      "$(lscpu | awk -F: '/max MHz|最大 MHz/{gsub(/ /,"",$2); print $2; exit}')"
    w "scaling MHz"  "$(lscpu | awk -F: '/scaling MHz|スケーリング MHz/{gsub(/ /,"",$2); print $2; exit}')"
  fi
  w "governor" "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
  w "intel no_turbo" "$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo n/a)"
  w "amd boost" "$(cat /sys/devices/system/cpu/cpufreq/boost 2>/dev/null || echo n/a)"
}

case "$MODE" in
  azure)
    need_root
    echo "== Environment A: taking vCPUs 1 and 3 offline, disabling SMT"
    for c in 1 3; do
      [[ -w /sys/devices/system/cpu/cpu$c/online ]] && echo 0 > /sys/devices/system/cpu/cpu$c/online
    done
    [[ -w /sys/devices/system/cpu/smt/control ]] && echo off > /sys/devices/system/cpu/smt/control
    echo
    report
    echo
    echo "Expected: SMT off, online 0,2, offline 1,3."
    echo "Then measure WITHOUT core pinning (this VM's spread is worse when pinned):"
    echo "  RESULTS_DIR=\"results/\$(date +%Y%m%d_%H%M%S)-perf\" ./run-all.sh"
    ;;
  baremetal)
    need_root
    echo "== Environment B: governor performance, turbo off"
    if command -v cpupower >/dev/null; then
      cpupower frequency-set -g performance >/dev/null 2>&1 \
        && echo "  cpupower: governor set to performance"
    else
      for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        [[ -w "$g" ]] && echo performance > "$g"
      done
      echo "  wrote performance to scaling_governor (cpupower not installed)"
    fi
    if [[ -w /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
      echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo
      echo "  intel_pstate: no_turbo=1"
    elif [[ -w /sys/devices/system/cpu/cpufreq/boost ]]; then
      echo 0 > /sys/devices/system/cpu/cpufreq/boost
      echo "  cpufreq: boost=0"
    else
      echo "  WARNING: found no way to disable turbo on this host"
    fi
    echo
    report
    echo
    echo "Expected: governor performance, no_turbo 1, max MHz at the base clock"
    echo "(2000 MHz on the N5095 -- 2900 means turbo is still on)."
    echo "Then measure as before, with the same CPU_PIN you used previously."
    ;;
  check)
    report
    echo
    echo "Nothing was changed. Use 'sudo ./isolate.sh azure' or 'baremetal' to apply."
    ;;
  *)
    echo "usage: $0 [azure|baremetal|check]"; exit 2 ;;
esac
