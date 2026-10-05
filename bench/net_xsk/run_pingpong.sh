#!/usr/bin/env bash
# AF_XDP vs kernel UDP ping-pong on a veth pair between two namespaces, both ends polling
# (VM numbers; copy mode; never a headline). usage: run_pingpong.sh <xsk_pingpong> [count]
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "needs root"; exit 77; }
BIN=$1; COUNT=${2:-200000}
tag=$$; NA=llpa-$tag; NB=llpb-$tag; VA=llpa$tag; VB=llpb$tag
cleanup() { kill ${RPID:-} 2>/dev/null || true; ip netns del $NA 2>/dev/null || true; ip netns del $NB 2>/dev/null || true; }
trap cleanup EXIT
ip netns add $NA; ip netns add $NB
ip link add $VA type veth peer name $VB
ip link set $VA netns $NA; ip link set $VB netns $NB
ip -n $NA addr add 10.91.0.1/24 dev $VA; ip -n $NB addr add 10.91.0.2/24 dev $VB
for n in $NA $NB; do ip -n $n link set lo up; done
ip -n $NA link set $VA up; ip -n $NB link set $VB up
for m in "--kernel" "" "--busy-poll"; do
  ip netns exec $NB "$BIN" --reflect --if $VB --local-ip 10.91.0.2 --peer-ip 10.91.0.1 --port 9500 $m &
  RPID=$!
  sleep 0.5
  ip netns exec $NA "$BIN" --client --if $VA --local-ip 10.91.0.1 --peer-ip 10.91.0.2 --port 9500 --count $COUNT $m
  kill $RPID; wait $RPID 2>/dev/null || true; RPID=
  sleep 0.3
done
