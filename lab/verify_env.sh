#!/usr/bin/env bash
# Captures the host configuration into env.json and refuses to benchmark if it
# deviates from the pre-registered profile (docs/plan/02 §5.4, docs/plan/12 §4).
# usage: lab/verify_env.sh <profile: host-a|host-b|host-c> <out-dir> <iface>...
set -uo pipefail
profile="${1:?profile}"; out="${2:?output dir}"; shift 2
mkdir -p "$out"
fail=0
check() { if ! eval "$2"; then echo "MISMATCH: $1" >&2; fail=1; fi; }

cmdline=$(cat /proc/cmdline)
case "$profile" in
  host-a|host-b)
    for opt in "isolcpus=managed_irq,domain,8-15" "nohz_full=8-15" "rcu_nocbs=8-15" "nvme.poll_queues=2" "hugepagesz=1G" "panic=5"; do
      check "kernel cmdline lacks $opt" "grep -q -- '$opt' <<<\"\$cmdline\""
    done
    check "SMT enabled" "[[ \$(cat /sys/devices/system/cpu/smt/active 2>/dev/null || echo 0) == 0 ]]"
    check "hugetlbfs not mounted at /mnt/lle-huge" "mountpoint -q /mnt/lle-huge"
    ;;
  host-c) ;;
  *) echo "unknown profile $profile" >&2; exit 64 ;;
esac
check "invariant TSC missing" "grep -q constant_tsc /proc/cpuinfo && grep -q nonstop_tsc /proc/cpuinfo"
check "irqbalance running" "! systemctl is-active -q irqbalance"
for ifc in "$@"; do
  drv=$(ethtool -i "$ifc" 2>/dev/null | awk '/^driver:/{print $2}')
  check "$ifc driver is $drv, expected mlx5_core" "[[ \"$drv\" == mlx5_core ]]"
  check "$ifc lacks hardware-transmit timestamps" "ethtool -T $ifc | grep -q hardware-transmit"
  check "$ifc lacks rx-filter all" "ethtool -T $ifc | grep -qE '^\s*all'"
  check "$ifc tx_port_ts is on" "! ethtool --show-priv-flags $ifc 2>/dev/null | grep -qE 'tx_port_ts\s*:\s*on'"
done

{
  echo "{"
  echo "  \"profile\": \"$profile\","
  echo "  \"uname\": \"$(uname -r)\","
  echo "  \"cmdline\": \"$cmdline\","
  echo "  \"cpu\": \"$(lscpu | awk -F: '/Model name/{gsub(/^ +/,"",$2); print $2; exit}')\","
  echo "  \"microcode\": \"$(awk '/microcode/{print $3; exit}' /proc/cpuinfo)\","
  echo "  \"governor\": \"$(cat /sys/devices/system/cpu/cpu8/cpufreq/scaling_governor 2>/dev/null)\","
  echo "  \"hugepages_1g\": \"$(cat /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages 2>/dev/null)\","
  echo "  \"nics\": ["
  first=1
  for ifc in "$@"; do
    [[ $first -eq 1 ]] || echo ","
    first=0
    printf '    {"iface": "%s", "driver": "%s", "firmware": "%s", "phc": "%s"}' "$ifc" \
      "$(ethtool -i "$ifc" | awk '/^driver:/{print $2}')" \
      "$(ethtool -i "$ifc" | awk -F': ' '/^firmware-version:/{print $2}')" \
      "$(ethtool -T "$ifc" | awk -F': ' '/PTP Hardware Clock/{print $2}')"
  done
  echo ""
  echo "  ],"
  echo "  \"ok\": $([[ $fail -eq 0 ]] && echo true || echo false)"
  echo "}"
} > "$out/env.json"
turbostat --quiet -n1 --show Core,CPU,Bzy_MHz,IRQ,SMI > "$out/turbostat.txt" 2>/dev/null || true

[[ $fail -eq 0 ]] && echo "verify_env: OK ($profile) -> $out/env.json" || { echo "verify_env: REFUSING TO BENCHMARK" >&2; exit 1; }
