#!/usr/bin/env bash
# utcp <-> Linux kernel TCP interop over a veth pair across two network namespaces
# (07 §2.4 Utcp.InteropLinuxPeer). utcp runs on an AF_PACKET raw socket in namespace U
# and owns 10.88.0.1 there (the kernel in U has no address, so it never answers for
# it); the kernel TCP echo peer runs in namespace K at 10.88.0.2. tc netem impairs both
# directions in the lossy cases. veth offloads are disabled so frames are real
# MSS-sized segments with complete checksums.
#
# usage: utcp_interop_test.sh <utcp_interop> <utcp_kernel_peer> [quick|full|soak SECONDS]
# UTCP_CASE=<substring> runs only the matching cases; UTCP_PCAP=<prefix> captures the
# peer side with tcpdump. Needs root and Linux, else exits
# 77 (ctest: skipped).
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then echo "SKIP: not Linux"; exit 77; fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "SKIP: needs root (ip netns, veth, tc)"; exit 77; fi
for t in ip tc ethtool; do command -v $t >/dev/null || { echo "SKIP: $t missing"; exit 77; }; done

UTCP=$1
PEER=$2
MODE=${3:-quick}
SOAK_S=${4:-600}

tag=$$
NS_U=lleu-$tag
NS_K=llek-$tag
VU=lleu$tag
VK=llek$tag
WORK=$(mktemp -d)
cleanup() {
  ip netns del "$NS_U" 2>/dev/null || true
  ip netns del "$NS_K" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

ip netns add "$NS_U"
ip netns add "$NS_K"
ip link add "$VU" type veth peer name "$VK"
ip link set "$VU" netns "$NS_U"
ip link set "$VK" netns "$NS_K"
ip -n "$NS_K" addr add 10.88.0.2/24 dev "$VK"
for ns in "$NS_U" "$NS_K"; do ip -n "$ns" link set lo up; done
ip netns exec "$NS_U" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
ip netns exec "$NS_K" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
ip -n "$NS_U" link set "$VU" up
ip -n "$NS_K" link set "$VK" up
ip netns exec "$NS_U" ethtool -K "$VU" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec "$NS_K" ethtool -K "$VK" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true

netem() {  # netem "<spec>" | netem ""  (both directions)
  ip netns exec "$NS_U" tc qdisc del dev "$VU" root 2>/dev/null || true
  ip netns exec "$NS_K" tc qdisc del dev "$VK" root 2>/dev/null || true
  if [[ -n "$1" ]]; then
    ip netns exec "$NS_U" tc qdisc add dev "$VU" root netem $1
    ip netns exec "$NS_K" tc qdisc add dev "$VK" root netem $1
  fi
}

failures=0
port=7000
run_case() {  # name "netem spec" "utcp args" "peer args"
  local name=$1 spec=$2 uargs=$3 pargs=$4
  if [[ -n "${UTCP_CASE:-}" && "$name" != *"$UTCP_CASE"* ]]; then return; fi
  port=$((port + 1))
  netem "$spec"
  echo "=== $name (netem: ${spec:-none})"
  local pargs2=${pargs//PORT/$port}
  local uargs2=${uargs//PORT/$port}
  local dump_pid=""
  if [[ -n "${UTCP_PCAP:-}" ]] && command -v tcpdump >/dev/null; then
    ip netns exec "$NS_K" tcpdump -i "$VK" -n -s 96 -w "$UTCP_PCAP.$port.pcap" >/dev/null 2>&1 &
    dump_pid=$!
    sleep 0.5
  fi
  # shellcheck disable=SC2086
  ip netns exec "$NS_K" "$PEER" $pargs2 >"$WORK/peer.log" 2>&1 &
  local ppid=$!
  sleep 0.2
  local urc=0
  # shellcheck disable=SC2086
  ip netns exec "$NS_U" "$UTCP" --if "$VU" --local-ip 10.88.0.1 $uargs2 >"$WORK/utcp.log" 2>&1 || urc=$?
  local prc=0
  if [[ $urc -ne 0 ]]; then
    # utcp failed: do not wait out the peer's timeout.
    sleep 1
    kill "$ppid" 2>/dev/null || true
  fi
  wait "$ppid" || prc=$?
  if [[ -n "$dump_pid" ]]; then kill "$dump_pid" 2>/dev/null || true; wait "$dump_pid" 2>/dev/null || true; fi
  cat "$WORK/utcp.log" "$WORK/peer.log"
  if [[ $urc -ne 0 || $prc -ne 0 ]]; then
    echo "--- FAIL: $name (utcp rc=$urc, peer rc=$prc)"
    failures=$((failures + 1))
  else
    echo "--- ok: $name"
  fi
}

MB=$((1024 * 1024))
# Reordering is kept light: utcp drops out-of-order segments (07 §2.4), so every
# reordered segment costs a retransmission. On the dedicated point-to-point link utcp
# targets there is no reordering; heavy netem reordering (e.g. 25%) turns into ~25%
# effective loss and Linux's non-SACK recovery backs off for tens of seconds.
LOSSY="loss 1% delay 1ms reorder 1% 25%"
HEAVY="loss 2% duplicate 1% delay 500us reorder 2% 25%"

case "$MODE" in
  quick|full)
    BULK=$((100 * MB))
    if [[ $MODE == quick ]]; then SMALL=$((20 * MB)); else SMALL=$BULK; fi
    run_case "client bulk 100MB, clean link, utcp closes" "" \
      "--peer-ip 10.88.0.2 --port PORT --bulk $BULK --close utcp" "--listen PORT"
    run_case "client small messages + ping-pong, lossy, utcp closes" "$LOSSY" \
      "--peer-ip 10.88.0.2 --port PORT --messages 50000 --max-msg 120 --pingpong 2000 --close utcp" "--listen PORT"
    run_case "client bulk 100MB, lossy, peer closes first" "$LOSSY" \
      "--peer-ip 10.88.0.2 --port PORT --bulk $BULK --close peer" "--listen PORT --close-after $BULK"
    run_case "server (kernel connects) bulk + messages, lossy, utcp closes" "$LOSSY" \
      "--server --port PORT --bulk $SMALL --messages 20000 --close utcp" "--connect 10.88.0.1:PORT"
    run_case "server bulk, heavy loss/dup/reorder, peer closes first" "$HEAVY" \
      "--server --port PORT --bulk $SMALL --close peer" "--connect 10.88.0.1:PORT --close-after $SMALL"
    run_case "client bulk, peer resets (RST) at the end" "$LOSSY" \
      "--peer-ip 10.88.0.2 --port PORT --bulk $((8 * MB)) --close peer-rst" "--listen PORT --close-after $((8 * MB)) --rst"
    ;;
  soak)
    run_case "soak ${SOAK_S}s: bulk + messages + ping-pong, lossy" "loss 0.5% delay 200us reorder 0.5% 25%" \
      "--peer-ip 10.88.0.2 --port PORT --duration-s $SOAK_S --bulk $((4 * MB)) --messages 5000 --pingpong 200 --close utcp" \
      "--listen PORT --timeout-s $((SOAK_S + 300))"
    ;;
  *) echo "unknown mode $MODE"; exit 2 ;;
esac

if [[ $failures -ne 0 ]]; then
  echo "utcp interop: $failures case(s) failed"
  exit 1
fi
echo "utcp interop: all cases passed"
