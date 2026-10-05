#!/usr/bin/env bash
# exchanged's AF_XDP variant (iv) end to end on a veth pair (07 §2.3, §5): the e2e suites
# of tests/integration/exchange with node.backend = xsk. Copy mode (veth has no zero-copy:
# [xsk] allow_copy, the dev/test override); function only, never latency.
#
# Namespace A runs exchanged: gw0, gw1 and md own AF_XDP sockets on queues 0, 1 and 2 of
# veth A (md_steer attached natively), the kernel keeps 10.89.0.1 and answers ARP, and the
# control, admin and GLIMPSE ports stay on kernel TCP. Namespace B runs the test process:
# SoupBinTCP clients over kernel TCP to 10.89.0.1, the feed subscriber on 10.89.0.2 (the
# node sends both lines there, to B's MAC). B's egress steers each AF_XDP port to its
# queue with tc skbedit queue_mapping, as ethtool ntuple rules do on the lab NIC
# (lab/exchanged/xsk_steer.sh): gw0 15000 -> 0, gw1 15001 -> 1, re-requests 26479 -> 2.
#
# usage: xsk_e2e.sh <test binary> [gtest args...]   (repeatable via ctest; label vm)
# Needs root and Linux, else exits 77.
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then echo "SKIP: not Linux"; exit 77; fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "SKIP: needs root (ip netns, veth, XDP, AF_XDP)"; exit 77; fi
for t in ip tc ethtool; do command -v $t >/dev/null || { echo "SKIP: $t missing"; exit 77; }; done
TEST=$1; shift

tag=$$
NS_A=llxea-$tag; NS_B=llxeb-$tag
VA=lxa$tag; VB=lxb$tag
MARK=$(mktemp)
cleanup() {
  ip netns pids "$NS_A" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  # Metrics segments the nodes made as root would block later unprivileged runs (a node
  # replaces a stale segment of its name, which it cannot do across users).
  find /dev/shm -maxdepth 1 -name 'lle-stats-*' -user root -newer "$MARK" -delete 2>/dev/null || true
  rm -f "$MARK"
}
trap cleanup EXIT
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add "$VA" numtxqueues 4 numrxqueues 4 type veth peer name "$VB" numtxqueues 4 numrxqueues 4
ip link set "$VA" netns "$NS_A"; ip link set "$VB" netns "$NS_B"
ip -n "$NS_A" addr add 10.89.0.1/24 dev "$VA"
ip -n "$NS_B" addr add 10.89.0.2/24 dev "$VB"
for ns in "$NS_A" "$NS_B"; do
  ip -n "$ns" link set lo up
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
done
ip -n "$NS_A" link set "$VA" up
ip -n "$NS_B" link set "$VB" up
# Complete checksums and MSS-sized frames toward the AF_XDP side (utcp verifies checksums).
ip netns exec "$NS_B" ethtool -K "$VB" tx off tso off gso off >/dev/null 2>&1 || true
# Steering: each AF_XDP stage's port to its queue.
ip netns exec "$NS_B" tc qdisc add dev "$VB" clsact
steer() {  # proto port queue
  ip netns exec "$NS_B" tc filter add dev "$VB" egress protocol ip flower ip_proto "$1" dst_port "$2" \
    action skbedit queue_mapping "$3"
}
steer tcp 15000 0
steer tcp 15001 1
steer udp 26479 2
MAC_B=$(ip -n "$NS_B" -o link show "$VB" | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p')
# Warm the neighbour entries both ways (the kernel answers ARP for the node's address).
ip netns exec "$NS_B" ping -c 1 -W 2 10.89.0.1 >/dev/null 2>&1 || true

echo "=== $(basename "$TEST") over AF_XDP (copy mode) on $VA: $*"
rc=0
ip netns exec "$NS_B" env LLE_E2E_BACKEND=xsk LLE_E2E_NETNS="$NS_A" LLE_E2E_HOST=10.89.0.1 \
  LLE_E2E_PEER_HOST=10.89.0.2 LLE_E2E_XSK_IF="$VA" LLE_E2E_XSK_NEXT_HOP="$MAC_B" "$TEST" "$@" || rc=$?
ip netns exec "$NS_B" tc -s filter show dev "$VB" egress | grep -E "skbedit|Sent" | head -12 || true
exit $rc
