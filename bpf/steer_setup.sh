#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
# NIC steering for the AF_XDP variant (07 §2.3; R3a §1.6). Puts the market-data feed
# and the utcp order flow on one dedicated queue and keeps RSS traffic off it, reserves
# utcp's local ports from the kernel, and enables hardware timestamping. Run as root on
# the lab host before starting the AF_XDP processes; idempotent where ethtool allows.
#
# usage: steer_setup.sh IFACE QUEUE [options]
#   --feed GROUP:PORT     multicast feed to steer (repeatable)   e.g. 233.54.12.1:26400
#   --utcp PEER:PORT      utcp flow to steer: remote address and remote port of the session
#   --utcp-local PORT     utcp local port (also reserved via ip_local_reserved_ports)
#   --reserve LO-HI       extra local port range to reserve (utcp ephemeral ports)
#   --dry-run             print the commands only
#
# mlx5/ice/i40e accept the ntuple rules below; igc only supports ETHER_FLOW rules (steer
# by the group's multicast MAC instead: ethtool -N IF flow-type ether dst 01:00:5e:xx:xx:xx
# action Q). See docs/verification/network.md for the lab checklist (bpftool net,
# XDP_OPTIONS_ZEROCOPY, ethtool -T).
set -euo pipefail
IF=${1:?iface}; Q=${2:?queue}; shift 2
DRY=0; FEEDS=(); UTCP=(); LPORT=""; RESERVE=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --feed) FEEDS+=("$2"); shift 2 ;;
    --utcp) UTCP+=("$2"); shift 2 ;;
    --utcp-local) LPORT=$2; shift 2 ;;
    --reserve) RESERVE=$2; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
done
run() { echo "+ $*"; [[ $DRY -eq 1 ]] || "$@"; }

QUEUES=$(ethtool -l "$IF" 2>/dev/null | awk '/Current hardware settings/{f=1} f && /Combined/{print $2; exit}')
QUEUES=${QUEUES:-$((Q + 1))}
if [[ $Q -ge $QUEUES ]]; then echo "queue $Q >= $QUEUES combined channels"; exit 2; fi

run ethtool -K "$IF" ntuple on
# RSS over queues 0..Q-1 only, so nothing else lands on the AF_XDP queue Q (assumes Q is
# the last queue, as in 07 §2.3 with 4 channels and Q = 3).
run ethtool -X "$IF" equal "$Q"
for f in "${FEEDS[@]}"; do
  run ethtool -N "$IF" flow-type udp4 dst-ip "${f%:*}" dst-port "${f#*:}" action "$Q"
done
for u in "${UTCP[@]}"; do
  if [[ -n "$LPORT" ]]; then
    run ethtool -N "$IF" flow-type tcp4 src-ip "${u%:*}" src-port "${u#*:}" dst-port "$LPORT" action "$Q"
  else
    run ethtool -N "$IF" flow-type tcp4 src-ip "${u%:*}" src-port "${u#*:}" action "$Q"
  fi
done
# The kernel must never pick utcp's ports for its own sockets (07 §2.3).
PORTS=""
[[ -n "$LPORT" ]] && PORTS=$LPORT
[[ -n "$RESERVE" ]] && PORTS=${PORTS:+$PORTS,}$RESERVE
[[ -n "$PORTS" ]] && run sysctl -w net.ipv4.ip_local_reserved_ports="$PORTS"
# Hardware timestamps on every packet (07 §2.5): rx-filter all, tx on. mlx5 returns
# -ENODATA from the RX-metadata kfunc otherwise.
if ethtool --help 2>&1 | grep -q -- --set-hwtimestamp-cfg; then
  run ethtool --set-hwtimestamp-cfg "$IF" tx on rx-filter all || true
elif command -v hwstamp_ctl >/dev/null; then
  run hwstamp_ctl -i "$IF" -t 1 -r 1 || true
fi
# Interrupt coalescing off for the latency path (07 §1 pilot cell `rx-usecs 0`).
run ethtool -C "$IF" adaptive-rx off adaptive-tx off rx-usecs 0 tx-usecs 0 || true
run ethtool -n "$IF"
