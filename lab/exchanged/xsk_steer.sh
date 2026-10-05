#!/usr/bin/env bash
# NIC steering for exchanged's AF_XDP variant (lab/exchanged/variants/xsk.conf; 07 §2.3).
# Each AF_XDP stage owns one queue: gw0's SoupBinTCP port, gw1's and the re-request port
# go to their queues by ntuple rules, and RSS keeps everything else on queue 0.
# usage: sudo lab/exchanged/xsk_steer.sh IF GW0_PORT:Q GW1_PORT:Q RR_PORT:Q
#   e.g. sudo lab/exchanged/xsk_steer.sh ens1f0np0 15000:1 15001:2 26479:3
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ $# -eq 4 ]] || { echo "usage: $0 IF GW0_PORT:Q GW1_PORT:Q RR_PORT:Q" >&2; exit 64; }
ifc=$1
ethtool -K "$ifc" ntuple on
ethtool -X "$ifc" equal 1                 # RSS: queue 0 only
for spec in "$2" "$3"; do
  ethtool -N "$ifc" flow-type tcp4 dst-port "${spec%%:*}" action "${spec##*:}"
done
ethtool -N "$ifc" flow-type udp4 dst-port "${4%%:*}" action "${4##*:}"
ethtool -n "$ifc"
