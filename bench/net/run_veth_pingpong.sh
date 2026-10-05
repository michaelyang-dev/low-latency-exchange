#!/usr/bin/env bash
# Runs net_udp_pingpong for each kernel-socket/io_uring backend across a veth pair
# between two network namespaces (root, Linux). Functional comparison only: veth and a
# VM give software timing, never headline numbers (07 §2.5).
#
# usage: sudo run_veth_pingpong.sh <net_udp_pingpong> [rate] [count] [backends...]
#   The reflector is the system under test and runs each backend with its own wait
#   strategy; the sender is the instrument and stays the same for every run
#   (SENDER_BACKEND, default uring, spinning), so only the variant under test changes.
#   env: REFLECTOR_CPU (default 2), SENDER_CPU (default 4), SIZE (64), WARMUP (10% of count),
#        SENDER_BACKEND (uring), SENDER_WAIT (spin)
set -euo pipefail
[[ "$(uname -s)" == Linux ]] || { echo "Linux only"; exit 77; }
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "needs root"; exit 77; }

BIN=$1
RATE=${2:-10000}
COUNT=${3:-100000}
shift $(( $# < 3 ? $# : 3 ))
BACKENDS=("$@")
[[ ${#BACKENDS[@]} -gt 0 ]] || BACKENDS=(epoll busypoll uring uring-napi)
RCPU=${REFLECTOR_CPU:-2}
SCPU=${SENDER_CPU:-4}
SIZE=${SIZE:-64}
WARMUP=${WARMUP:-$((COUNT / 10))}
SB=${SENDER_BACKEND:-uring}
SW=${SENDER_WAIT:-spin}

tag=$$
NS_A=llebench-a-$tag
NS_B=llebench-b-$tag
VA=llba$tag
VB=llbb$tag
cleanup() {
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
}
trap cleanup EXIT
ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add "$VA" type veth peer name "$VB"
ip link set "$VA" netns "$NS_A"
ip link set "$VB" netns "$NS_B"
ip -n "$NS_A" addr add 10.78.0.1/24 dev "$VA"
ip -n "$NS_B" addr add 10.78.0.2/24 dev "$VB"
# Give veth a NAPI context for locally generated UDP (see tests/integration/net).
ip netns exec "$NS_A" ethtool -K "$VA" gro on rx-udp-gro-forwarding on tso off >/dev/null 2>&1 || true
ip netns exec "$NS_B" ethtool -K "$VB" gro on rx-udp-gro-forwarding on tso off >/dev/null 2>&1 || true
ip -n "$NS_A" link set "$VA" up
ip -n "$NS_B" link set "$VB" up

echo "# host: $(uname -r), $(nproc) CPUs; reflector (SUT) CPU $RCPU, sender ($SB/$SW) CPU $SCPU; rate=$RATE/s count=$COUNT size=$SIZE"
echo "# VM/veth, software timing (CLOCK_MONOTONIC): NOT headline numbers"
port=27000
for b in "${BACKENDS[@]}"; do
  port=$((port + 1))
  ip netns exec "$NS_B" taskset -c "$RCPU" "$BIN" --role reflector --backend "$b" --bind "10.78.0.2:$port" &
  refl=$!
  sleep 0.2
  echo "## SUT reflector: $b"
  ip netns exec "$NS_A" taskset -c "$SCPU" "$BIN" --role sender --backend "$SB" --wait "$SW" --bind 10.78.0.1:0 \
    --peer "10.78.0.2:$port" --rate "$RATE" --count "$COUNT" --warmup "$WARMUP" --size "$SIZE" \
    --label "SUT reflector=$b; VM/veth, software (CLOCK_MONOTONIC) timing, NOT headline" || true
  wait "$refl" || true
done
