#!/usr/bin/env bash
# AF_XDP functional suite on veth (07 §5; R3a XskSmoke.VethCopyMode). Two veth pairs
# join namespace A (AF_XDP side, kernel-owned 10.89.0.1 and 10.90.0.1) and namespace B
# (kernel peers 10.89.0.2 and 10.90.0.2: UDP echo on port 7, TCP echo for utcp). The
# md_steer program attaches natively to the veth ends in A; AF_XDP runs in copy mode
# (veth has no zero-copy). Then utcp over AF_XDP interoperates with kernel TCP in B,
# with and without tc netem on B's egress (AF_XDP copy-mode TX bypasses A's qdisc).
#
# usage: xsk_veth_test.sh <net_xsk_vm_test> <xsk_udp_echo> <xsk_interop> <kernel_peer> [quick|full]
# Needs root and Linux, else exits 77.
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then echo "SKIP: not Linux"; exit 77; fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "SKIP: needs root (ip netns, veth, XDP, AF_XDP)"; exit 77; fi
for t in ip tc ethtool; do command -v $t >/dev/null || { echo "SKIP: $t missing"; exit 77; }; done
VMTEST=$1; ECHO=$2; INTEROP=$3; PEER=$4; MODE=${5:-quick}

tag=$$
NS_A=llexa-$tag; NS_B=llexb-$tag
VA=llxa$tag; VB=llxb$tag; VC=llxc$tag; VD=llxd$tag
HUGE_OLD=$(cat /proc/sys/vm/nr_hugepages)
cleanup() {
  [[ -n "${ECHO_PID:-}" ]] && kill "$ECHO_PID" 2>/dev/null || true
  echo "$HUGE_OLD" > /proc/sys/vm/nr_hugepages 2>/dev/null || true
  [[ -n "${NSIM_ID:-}" ]] && echo "$NSIM_ID" > /sys/bus/netdevsim/del_device 2>/dev/null || true
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
}
trap cleanup EXIT
# 2 MiB hugepages for the UMEM (07 §2.3); best effort.
echo $((HUGE_OLD + 32)) > /proc/sys/vm/nr_hugepages 2>/dev/null || true
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add "$VA" type veth peer name "$VB"
ip link add "$VC" type veth peer name "$VD"
ip link set "$VA" netns "$NS_A"; ip link set "$VC" netns "$NS_A"
ip link set "$VB" netns "$NS_B"; ip link set "$VD" netns "$NS_B"
ip -n "$NS_A" addr add 10.89.0.1/24 dev "$VA"; ip -n "$NS_A" addr add 10.90.0.1/24 dev "$VC"
ip -n "$NS_B" addr add 10.89.0.2/24 dev "$VB"; ip -n "$NS_B" addr add 10.90.0.2/24 dev "$VD"
for ns in "$NS_A" "$NS_B"; do
  ip -n "$ns" link set lo up
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
done
for v in "$VA" "$VC"; do ip -n "$NS_A" link set "$v" up; done
for v in "$VB" "$VD"; do
  ip -n "$NS_B" link set "$v" up
  # Complete checksums and real MSS-sized frames toward the AF_XDP side.
  ip netns exec "$NS_B" ethtool -K "$v" tx off tso off gso off >/dev/null 2>&1 || true
done
# utcp's local ports are reserved from the kernel (07 §2.3).
ip netns exec "$NS_A" sysctl -qw net.ipv4.ip_local_reserved_ports=40000-40999
ip netns exec "$NS_B" "$ECHO" 10.89.0.2 7 10.90.0.2 7 &
ECHO_PID=$!
sleep 0.3

failures=0
echo "=== AF_XDP gtests (copy mode on veth)"
if ! ip netns exec "$NS_A" env LLE_XSK_IF="$VA" LLE_XSK_LOCAL_IP=10.89.0.1 LLE_XSK_PEER_IP=10.89.0.2 \
     LLE_XSK_IF2="$VC" LLE_XSK_LOCAL_IP2=10.90.0.1 LLE_XSK_PEER_IP2=10.90.0.2 "$VMTEST"; then
  failures=$((failures + 1))
fi

# NAPI control (napi-get / napi-set threaded=busy-poll) on a netdevsim device, whose
# queues are linked to NAPI instances (veth's are not).
if modprobe netdevsim 2>/dev/null && [[ -w /sys/bus/netdevsim/new_device ]]; then
  NSIM_ID=$((tag % 10000 + 100))
  if echo "$NSIM_ID 1 1" > /sys/bus/netdevsim/new_device 2>/dev/null; then
    sleep 0.3
    NSIM_IF=$(ls /sys/bus/netdevsim/devices/netdevsim$NSIM_ID/net/ 2>/dev/null | head -1)
    if [[ -n "$NSIM_IF" ]]; then
      ip link set "$NSIM_IF" up
      echo "=== NAPI control on netdevsim ($NSIM_IF)"
      if ! LLE_XSK_NAPI_IF="$NSIM_IF" "$VMTEST" --gtest_filter='XskNapi.*'; then failures=$((failures + 1)); fi
    fi
  fi
fi

port=7100
interop() {  # name "netem spec on B" "xsk_interop args" "peer args"
  local name=$1 spec=$2 xargs=$3 pargs=$4
  port=$((port + 1))
  ip netns exec "$NS_B" tc qdisc del dev "$VB" root 2>/dev/null || true
  [[ -n "$spec" ]] && ip netns exec "$NS_B" tc qdisc add dev "$VB" root netem $spec
  echo "=== utcp over AF_XDP: $name (netem on B egress: ${spec:-none})"
  ip netns exec "$NS_B" "$PEER" ${pargs//PORT/$port} > /tmp/xsk_peer.$tag.log 2>&1 &
  local ppid=$!
  sleep 0.2
  local rc=0
  ip netns exec "$NS_A" "$INTEROP" --if "$VA" --local-ip 10.89.0.1 ${xargs//PORT/$port} || rc=$?
  if [[ $rc -ne 0 ]]; then sleep 1; kill "$ppid" 2>/dev/null || true; fi
  local prc=0
  wait "$ppid" || prc=$?
  cat /tmp/xsk_peer.$tag.log; rm -f /tmp/xsk_peer.$tag.log
  if [[ $rc -ne 0 || $prc -ne 0 ]]; then echo "--- FAIL: $name"; failures=$((failures + 1)); else echo "--- ok: $name"; fi
}
MB=$((1024 * 1024))
BULK=$((100 * MB))
[[ $MODE == quick ]] || BULK=$((400 * MB))
interop "client bulk ${BULK}B + messages, clean" "" \
  "--peer-ip 10.89.0.2 --port PORT --bulk $BULK --messages 20000 --pingpong 1000 --close utcp" "--listen PORT"
interop "client bulk, lossy (B egress), peer closes first" "loss 1% delay 500us reorder 1% 25%" \
  "--peer-ip 10.89.0.2 --port PORT --bulk $((20 * MB)) --close peer" "--listen PORT --close-after $((20 * MB))"
interop "server (kernel connects), bulk + messages, lossy" "loss 1% delay 500us reorder 1% 25%" \
  "--server --port PORT --bulk $((20 * MB)) --messages 10000 --close utcp" "--connect 10.89.0.1:PORT"
ip netns exec "$NS_B" tc qdisc del dev "$VB" root 2>/dev/null || true

if [[ $failures -ne 0 ]]; then echo "xsk veth suite: $failures failure(s)"; exit 1; fi
echo "xsk veth suite: all passed"
