#!/usr/bin/env bash
# Cross-namespace functional test of every kernel-socket/io_uring backend (07 §5):
# two network namespaces joined by a veth pair; for each backend
#   1. UDP multicast feed  A → B (IP_ADD_MEMBERSHIP on B's veth, IP_MULTICAST_IF on A's),
#   2. UDP unicast echo    A ⇄ B,
#   3. TCP echo session    A (client) ⇄ B (server),
# plus the variant (ii) device setup (IRQ-suspend sub-variant) on the namespace's veth and
# the busy-poll unit tests as root (CAP_NET_ADMIN paths).
#
# veth gives SOFTWARE timestamps only; nothing here measures latency or claims hardware
# timestamps. Needs root and Linux: otherwise exits 77, which ctest reports as skipped.
#
# usage: veth_netns_test.sh <net_peer> [net_busypoll_test] [backends...]
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then echo "SKIP: not Linux"; exit 77; fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "SKIP: needs root (ip netns, veth)"; exit 77; fi
command -v ip >/dev/null || { echo "SKIP: iproute2 missing"; exit 77; }

PEER=$1; shift
BUSYPOLL_TEST=""
if [[ $# -gt 0 && -x "$1" ]]; then BUSYPOLL_TEST=$1; shift; fi
BACKENDS=("$@")
[[ ${#BACKENDS[@]} -gt 0 ]] || BACKENDS=(epoll busypoll uring uring-napi)

tag=$$
NS_A=lle-a-$tag
NS_B=lle-b-$tag
VA=llea$tag
VB=lleb$tag
WORK=$(mktemp -d)
cleanup() {
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add "$VA" type veth peer name "$VB"
ip link set "$VA" netns "$NS_A"
ip link set "$VB" netns "$NS_B"
ip -n "$NS_A" addr add 10.77.0.1/24 dev "$VA"
ip -n "$NS_B" addr add 10.77.0.2/24 dev "$VB"
for ns in "$NS_A" "$NS_B"; do ip -n "$ns" link set lo up; done
ip -n "$NS_A" link set "$VA" up
ip -n "$NS_B" link set "$VB" up
# Multicast leaves A through its veth.
ip -n "$NS_A" route add 224.0.0.0/4 dev "$VA"
# veth runs NAPI only with GRO on, and routes locally generated skbs through it only when
# they are GRO-eligible (veth_skb_is_eligible_for_gro): UDP needs rx-udp-gro-forwarding
# on the receiver, TCP needs TSO off on the sender. With that, sockets get a NAPI ID and
# the busy-poll variants really poll (asserted through BusyPollRxPackets).
NAPI_OK=0
if command -v ethtool >/dev/null &&
   ip netns exec "$NS_A" ethtool -K "$VA" gro on rx-udp-gro-forwarding on tso off >/dev/null 2>&1 &&
   ip netns exec "$NS_B" ethtool -K "$VB" gro on rx-udp-gro-forwarding on tso off >/dev/null 2>&1; then
  NAPI_OK=1
  ip netns exec "$NS_B" "$PEER" napi-list --ifname "$VB" || true
else
  echo "note: veth NAPI not configured (ethtool missing); busy-poll counters not asserted"
fi

# Waits (bounded) until a background peer has opened its ports.
wait_ready() {
  local f=$1 pid=$2
  for _ in $(seq 1 400); do
    [[ -f "$f" ]] && return 0
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.025
  done
  return 1
}

failures=0
run_case() {
  local name=$1; shift
  if "$@"; then echo "PASS $name"; else echo "FAIL $name"; failures=$((failures + 1)); fi
}

mcast_case() {
  local b=$1 rdy=$WORK/mcast-$1 expect=0
  if [[ $NAPI_OK -eq 1 && ( $b == busypoll || $b == uring-napi ) ]]; then expect=1; fi
  ip netns exec "$NS_B" "$PEER" mcast-sub --backend "$b" --group 239.77.0.1 --port 26400 --ifname "$VB" \
    --count 2000 --ready-file "$rdy" --expect-busy-poll "$expect" &
  local sub=$!
  wait_ready "$rdy" "$sub" || { wait "$sub" || true; return 1; }
  ip netns exec "$NS_A" "$PEER" mcast-pub --backend "$b" --group 239.77.0.1 --port 26400 --ifname "$VA" \
    --count 2000 --gap-us 20 || { kill "$sub" 2>/dev/null || true; return 1; }
  wait "$sub"
}

udp_echo_case() {
  local b=$1 rdy=$WORK/udp-$1
  ip netns exec "$NS_B" "$PEER" udp-echo --backend "$b" --bind 10.77.0.2:26401 --count 500 --ready-file "$rdy" &
  local srv=$!
  wait_ready "$rdy" "$srv" || { wait "$srv" || true; return 1; }
  ip netns exec "$NS_A" "$PEER" udp-ping --backend "$b" --peer 10.77.0.2:26401 --count 500 \
    || { kill "$srv" 2>/dev/null || true; return 1; }
  wait "$srv"
}

tcp_case() {
  local b=$1 rdy=$WORK/tcp-$1
  ip netns exec "$NS_B" "$PEER" tcp-echo-server --backend "$b" --bind 10.77.0.2:26402 --ready-file "$rdy" &
  local srv=$!
  wait_ready "$rdy" "$srv" || { wait "$srv" || true; return 1; }
  ip netns exec "$NS_A" "$PEER" tcp-echo-client --backend "$b" --peer 10.77.0.2:26402 --count 2000 \
    || { kill "$srv" 2>/dev/null || true; return 1; }
  wait "$srv"
}

for b in "${BACKENDS[@]}"; do
  rc=0
  ip netns exec "$NS_A" "$PEER" probe --backend "$b" >/dev/null 2>&1 || rc=$?
  if [[ $rc -eq 77 ]]; then echo "SKIP $b (not compiled in this build)"; continue; fi
  run_case "$b/mcast-feed" mcast_case "$b"
  run_case "$b/udp-echo" udp_echo_case "$b"
  run_case "$b/tcp-echo" tcp_case "$b"
done

# Variant (ii) device setup on B's veth (namespace-local, so the host is untouched):
# sysfs napi_defer_hard_irqs/gro_flush_timeout and the IRQ-suspend sub-variant's
# per-NAPI irq-suspend-timeout through netdev netlink napi-set, read back.
if [[ $NAPI_OK -eq 1 ]]; then
  run_case "busypoll/irq-suspend-device-config" ip netns exec "$NS_B" "$PEER" napi-config --ifname "$VB" --mode irq-suspend
fi

if [[ -n "$BUSYPOLL_TEST" ]]; then
  run_case "busypoll-unit-as-root" "$BUSYPOLL_TEST" --gtest_brief=1
fi

if [[ $failures -ne 0 ]]; then echo "$failures case(s) failed"; exit 1; fi
echo "all cases passed"
