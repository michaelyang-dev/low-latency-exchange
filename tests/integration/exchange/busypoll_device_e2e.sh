#!/usr/bin/env bash
# Busy-poll device settings of variants (ii) and (ii-s) through exchanged itself (07 §1,
# METHODOLOGY §14): the node applies them on a netdevsim device ([net] ifname,
# device_setup = true; root) and reports the device as the variant requires, which the
# e2e harness checks at every node stop. netdevsim queues have NAPI instances, so the
# IRQ-suspend sub-variant's per-NAPI irq-suspend-timeout is set and read back. The
# traffic itself stays on loopback: this checks the device path, not busy polling's effect.
#
# usage: busypoll_device_e2e.sh <busypoll|busypoll-irq-suspend> <test binary> [gtest args...]
# Needs root, Linux and netdevsim, else exits 77.
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then echo "SKIP: not Linux"; exit 77; fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "SKIP: needs root (netdevsim, sysfs, netdev netlink)"; exit 77; fi
VARIANT=$1; TEST=$2; shift 2
modprobe netdevsim 2>/dev/null || { echo "SKIP: no netdevsim"; exit 77; }
[[ -w /sys/bus/netdevsim/new_device ]] || { echo "SKIP: no netdevsim bus"; exit 77; }
ID=$(( $$ % 10000 + 200 ))
MARK=$(mktemp)
cleanup() {
  echo "$ID" > /sys/bus/netdevsim/del_device 2>/dev/null || true
  # Metrics segments the node made as root would block later unprivileged runs.
  find /dev/shm -maxdepth 1 -name 'lle-stats-*' -user root -newer "$MARK" -delete 2>/dev/null || true
  rm -f "$MARK"
}
trap cleanup EXIT
echo "$ID 1 4" > /sys/bus/netdevsim/new_device   # one port, four queues
sleep 0.3
IF=$(ls /sys/bus/netdevsim/devices/netdevsim$ID/net/ | head -1)
[[ -n "$IF" ]] || { echo "SKIP: netdevsim created no interface"; exit 77; }
ip link set "$IF" up
echo "=== $(basename "$TEST") as $VARIANT, device settings on $IF ($*)"
rc=0
env LLE_E2E_BACKEND="$VARIANT" LLE_E2E_NET_IF="$IF" LLE_E2E_DEVICE_SETUP=1 "$TEST" "$@" || rc=$?
echo "$IF: napi_defer_hard_irqs $(cat /sys/class/net/$IF/napi_defer_hard_irqs) gro_flush_timeout $(cat /sys/class/net/$IF/gro_flush_timeout)"
exit $rc
