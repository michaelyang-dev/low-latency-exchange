#!/bin/bash
# Variant wiring on veth (07 §1, §5; WP N-13), root only (label vm): the variants the
# loopback test cannot run. Namespace A holds refclient, namespace B ttt_harness; one
# veth pair joins them (10.91.0.1 <-> 10.91.0.2); the feed is two multicast groups.
#   - busypoll and busypoll-irq-suspend (SO_PREFER_BUSY_POLL needs CAP_NET_ADMIN), with
#     --device-setup applying the 07 §1 device settings to the veth end;
#   - xsk: AF_XDP feed and utcp order entry over AF_XDP on veth, in copy mode through
#     the explicit --xsk-allow-copy override (veth has no zero-copy);
#   - xsk-threaded: refused cleanly on veth (its queues have no NAPI instance);
#   - the harness's AF_XDP feed (--feed xsk, copy mode) into an epoll refclient.
# Every run uses software timestamps or none (veth has no PHC), so every run must be
# marked invalid; the functional checks are the loop test's. The background feed runs at
# 20,000 msgs/s (LLE_TEST_FEED_RATE): a sanitizer build of refclient on a loaded VM cannot
# drain much more in copy mode before AF_XDP's fill ring runs dry (rx_fill_ring_empty).
# usage: xsk_variants_test.sh ITCH_SYNTH TTT_HARNESS REFCLIENT WORK_DIR
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then echo "SKIP: not Linux"; exit 77; fi
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then echo "SKIP: needs root (ip netns, veth, XDP, AF_XDP)"; exit 77; fi
for t in ip ethtool; do command -v $t >/dev/null || { echo "SKIP: $t missing"; exit 77; }; done
SYNTH=$1; HARNESS=$2; CLIENT=$3; W=$4
fail() { echo "FAIL: $*" >&2; exit 1; }
json_num() { sed -n "s/^ *\"$2\": \\([0-9-]*\\).*/\\1/p" "$1" | head -1; }
tag=$$
NS_A=llcla-$tag; NS_B=llclb-$tag; VA=lcva$tag; VB=lcvb$tag
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
}
trap cleanup EXIT
rm -rf "$W"; mkdir -p "$W"; chmod 777 "$W"
"$SYNTH" --out "$W/day.bin" --messages 150000 --symbols 50 --live 5000 --seed 13 > /dev/null
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add "$VA" type veth peer name "$VB"
ip link set "$VA" netns "$NS_A"; ip link set "$VB" netns "$NS_B"
ip -n "$NS_A" addr add 10.91.0.1/24 dev "$VA"; ip -n "$NS_B" addr add 10.91.0.2/24 dev "$VB"
for ns in "$NS_A" "$NS_B"; do
  ip -n "$ns" link set lo up
  ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
done
ip -n "$NS_A" link set "$VA" up; ip -n "$NS_B" link set "$VB" up
# Complete checksums and MSS-sized frames toward the AF_XDP side (as xsk_veth_test.sh).
ip netns exec "$NS_B" ethtool -K "$VB" tx off tso off gso off > /dev/null 2>&1 || true
ip netns exec "$NS_A" ethtool -K "$VA" tx off tso off gso off > /dev/null 2>&1 || true
ip -n "$NS_B" route add 239.0.0.0/8 dev "$VB"
ip -n "$NS_A" route add 239.0.0.0/8 dev "$VA"
ip netns exec "$NS_A" sysctl -qw net.ipv4.ip_local_reserved_ports=40000-40999

port=31000
# one NAME FEED "refclient variant args" [loopback] [harness args]: the harness in
# namespace B feeding the multicast groups over the veth, or (loopback) both programs in
# namespace A on lo.
one() {
  local name=$1 feed=$2 cargs=$3 lo=${4:-} hargs=${5:-}
  port=$((port + 100))
  local D="$W/$name"; mkdir -p "$D"
  local LA=239.1.1.1:$((port + 1)) LB=239.1.1.2:$((port + 2)) DESK=10.91.0.2:$((port + 30)) HNS=$NS_B
  local RR=10.91.0.2:$((port + 11))
  if [ -n "$lo" ]; then
    LA=127.0.0.1:$((port + 1)); LB=127.0.0.1:$((port + 2)); DESK=127.0.0.1:$((port + 30)); RR=127.0.0.1:$((port + 11)); HNS=$NS_A
  fi
  # shellcheck disable=SC2086
  # The re-request service recovers packets veth drops on both lines under load (the run
  # stays invalid: no hardware timestamps, and a re-request makes feed_gap_free false).
  ip netns exec "$NS_A" "$CLIENT" $cargs --line-a $LA --line-b $LB --rerequest-a $RR --rerequest-b $RR --request-timeout 200ms \
    --trade --symbol LLTRG --sell-at 10.00 \
    --primary $DESK --user U00099 --linger 1s --max-runtime 60s --stamp-log "$D/client.hwts" \
    --report "$D/client.json" > /dev/null 2> "$D/client.err" &
  local cpid=$!
  PIDS+=($cpid)
  sleep 1
  kill -0 $cpid 2>/dev/null || fail "$name: refclient exited: $(tail -3 "$D/client.err")"
  local fargs="--feed udp"
  [ "$feed" = xsk ] && fargs="--feed xsk --ifname $VB --xsk-allow-copy --source-ip 10.91.0.2"
  [ "$feed" = udp ] && [ -z "$lo" ] && fargs="--feed udp --ifname $VB"
  # shellcheck disable=SC2086
  ip netns exec "$HNS" "$HARNESS" run --file "$W/day.bin" --line-a $LA --line-b $LB --listen $DESK $fargs \
    --rerequest $RR $hargs --timestamps software --rate ${LLE_TEST_FEED_RATE:-20000} --trigger-rate 1000 --duration 3s --warmup 1s --min-triggers 100 \
    --start-delay 1500ms --linger 2s --seed 9 --out "$D" --run-name run-01 > /dev/null 2> "$D/harness.err" \
    || fail "$name: harness failed: $(tail -3 "$D/harness.err")"
  local i=0
  while [ ! -s "$D/client.json" ]; do sleep 0.2; i=$((i + 1)); [ $i -lt 400 ] || fail "$name: no client report"; done
  local H="$D/run-01.json" C="$D/client.json" T
  T=$(json_num "$H" triggers)
  grep -q '"feed_ended": true' "$C" || fail "$name: client feed did not end ($(tail -2 "$D/client.err"))"
  [ "$(json_num "$C" delivered)" = "$(json_num "$H" messages)" ] || fail "$name: delivered $(json_num "$C" delivered) of $(json_num "$H" messages)"
  [ "$(json_num "$C" strategy_orders)" = "$T" ] || fail "$name: $T triggers, $(json_num "$C" strategy_orders) orders"
  [ "$(json_num "$H" desk_orders)" = "$T" ] || fail "$name: desk got $(json_num "$H" desk_orders) of $T"
  [ "$(json_num "$H" orders_missing)" = 0 ] || fail "$name: measured triggers without an order"
  [ "$(json_num "$C" oe_acked)" = "$T" ] || fail "$name: acked $(json_num "$C" oe_acked) of $T"
  [ "$(json_num "$C" stamp_log_records)" = "$T" ] || fail "$name: stamp log"
  grep -q '"valid": false' "$H" || fail "$name: run without hardware stamps not invalid"
  grep -q '"run_valid": false' "$H" || fail "$name: run_valid without hardware stamps"
  echo "ok: $name: $T triggers ordered and acknowledged; run invalid ($(sed -n 's/^ *"invalid_reasons": "\(.*\)",/\1/p' "$H"))"
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  PIDS=()
}

one busypoll udp "--variant busypoll --ifname $VA --device-setup --timestamps software"
grep -q '"device_ok": true' "$W/busypoll/client.json" || fail "busypoll: device settings not verified: $(grep device_notes "$W/busypoll/client.json")"
# IRQ-suspend needs NAPI instances (per-NAPI irq-suspend-timeout): veth has none, so
# the variant is refused cleanly there; on a netdevsim device (NAPI per queue) the
# device settings are applied and verified while the loop runs over loopback.
if ip netns exec "$NS_A" "$CLIENT" --variant busypoll-irq-suspend --ifname "$VA" --device-setup \
     --line-a 127.0.0.1:39011 --line-b 127.0.0.1:39012 --max-runtime 1s > /dev/null 2> "$W/irqs-veth.err"; then
  fail "busypoll-irq-suspend ran on veth (no NAPI instances)"
fi
grep -q "list_napi" "$W/irqs-veth.err" || fail "busypoll-irq-suspend on veth: unexpected error: $(cat "$W/irqs-veth.err")"
echo "ok: busypoll-irq-suspend refused on veth: $(tail -1 "$W/irqs-veth.err")"
NSIM_ID=$((tag % 10000 + 200))
if modprobe netdevsim 2>/dev/null && echo "$NSIM_ID 1 1" > /sys/bus/netdevsim/new_device 2>/dev/null; then
  sleep 0.3
  NSIM_IF=$(ls /sys/bus/netdevsim/devices/netdevsim$NSIM_ID/net/ 2>/dev/null | head -1)
  ip link set "$NSIM_IF" netns "$NS_A"
  ip -n "$NS_A" link set "$NSIM_IF" up
  one busypoll-irq-suspend lo "--variant busypoll-irq-suspend --ifname $NSIM_IF --device-setup --timestamps software" lo
  C="$W/busypoll-irq-suspend/client.json"
  grep -q '"device_ok": true' "$C" || fail "irq-suspend: device settings not verified: $(grep device_notes "$C")"
  [ "$(json_num "$C" irq_suspend_timeout_ns)" = 20000000 ] || fail "irq-suspend: timeout $(json_num "$C" irq_suspend_timeout_ns)"
  echo "$NSIM_ID" > /sys/bus/netdevsim/del_device 2>/dev/null || true
else
  echo "note: netdevsim unavailable; busypoll-irq-suspend checked for refusal only"
fi
# Every 400th data packet withheld from both lines: re-requests over the AF_XDP request
# port (and their replies steered back to it) must recover each one.
one xsk udp "--variant xsk --ifname $VA --xsk-allow-copy --timestamps software" "" "--test-drop-every 400"
C="$W/xsk/client.json"
[ "$(json_num "$C" arb_requests_sent_a)" -gt 0 ] || fail "xsk: no re-request sent"
[ "$(json_num "$W/xsk/run-01.json" rerequest_replies)" -gt 0 ] || fail "xsk: no re-request served"
[ "$(json_num "$C" arb_rerequest_a_packets)" -gt 0 ] || fail "xsk: no re-request reply received over AF_XDP"
grep -q '"xsk_zero_copy": false' "$C" || fail "xsk: expected copy mode on veth"
[ "$(json_num "$C" xsk_udp_received)" -gt 0 ] || fail "xsk: no datagrams through AF_XDP"
[ "$(json_num "$C" steer_redirect_tcp)" -gt 0 ] || fail "xsk: no utcp frames steered to AF_XDP"
grep -q '"xsk_tx_stamps_aligned": true' "$C" || fail "xsk: TX stamp attribution misaligned"
[ "$(json_num "$C" tx_stamps_hw)" = 0 ] || fail "xsk: copy mode reported hardware TX stamps"
one harness-xsk-feed xsk "--variant epoll --ifname $VA --timestamps software"
grep -q '"feed": "xsk"' "$W/harness-xsk-feed/run-01.json" || fail "harness xsk feed not used"
grep -q '"feed_tx_stamps_aligned": true' "$W/harness-xsk-feed/run-01.json" || fail "harness xsk feed: stamps misaligned"
# (iv-t) on veth: refused with a clear message (no NAPI instance on a veth queue).
if ip netns exec "$NS_A" "$CLIENT" --variant xsk-threaded --ifname "$VA" --xsk-allow-copy --line-a 239.1.1.1:39001 \
     --line-b 239.1.1.2:39002 --max-runtime 1s > /dev/null 2> "$W/threaded.err"; then
  fail "xsk-threaded ran on veth"
fi
grep -q "(iv-t)" "$W/threaded.err" || fail "xsk-threaded: unexpected error: $(cat "$W/threaded.err")"
echo "ok: xsk-threaded refused on veth: $(tail -1 "$W/threaded.err")"
echo "PASS"
