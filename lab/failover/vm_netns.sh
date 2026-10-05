#!/usr/bin/env bash
# The VM dry run of the T25 trials (lab/failover/vm-dryrun.toml): hosts A and B as network
# namespaces lleA and lleB on one machine, host C as the root namespace.
#
#   lle-br (bridge, 10.77.0.254/24, host C) -- lleA eth0 10.77.0.1/24 (node A: gateways,
#                                              control, re-request, lines)
#                                           -- lleB eth0 10.77.0.2/24 (node B)
#   lleA ab0 10.78.0.1/24 <-> lleB ab0 10.78.0.2/24 (the A-B replication link)
#
# The lines are multicast (239.77.0.1, 239.77.0.2) over the bridge, which floods them (no
# snooping) to host C. F3 takes eth0 and ab0 of lleA down; F6 takes the A-B link down.
# Needs root.   usage: lab/failover/vm_netns.sh up|down|status
set -euo pipefail
cmd=${1:?up|down|status}
case "$cmd" in
  up)
    "$0" down > /dev/null 2>&1 || true
    ip link add lle-br type bridge
    ip link set lle-br type bridge mcast_snooping 0
    ip addr add 10.77.0.254/24 dev lle-br
    ip link set lle-br up
    i=1
    for n in A B; do
      ns=lle$n
      ip netns add "$ns"
      ip link add "lle$n-br" type veth peer name "lle$n-eth"
      ip link set "lle$n-br" master lle-br up
      ip link set "lle$n-eth" netns "$ns"
      ip -n "$ns" link set "lle$n-eth" name eth0
      ip -n "$ns" addr add "10.77.0.$i/24" dev eth0
      ip -n "$ns" link set eth0 up
      ip -n "$ns" link set lo up
      ip -n "$ns" route add 224.0.0.0/4 dev eth0
      i=$((i + 1))
    done
    ip link add lleab-a type veth peer name lleab-b
    ip link set lleab-a netns lleA
    ip link set lleab-b netns lleB
    ip -n lleA link set lleab-a name ab0
    ip -n lleB link set lleab-b name ab0
    ip -n lleA addr add 10.78.0.1/24 dev ab0
    ip -n lleB addr add 10.78.0.2/24 dev ab0
    ip -n lleA link set ab0 up
    ip -n lleB link set ab0 up
    echo "vm_netns: lleA 10.77.0.1 (ab0 10.78.0.1), lleB 10.77.0.2 (ab0 10.78.0.2), host C 10.77.0.254 on lle-br"
    ;;
  down)
    ip netns del lleA 2>/dev/null || true
    ip netns del lleB 2>/dev/null || true
    ip link del lle-br 2>/dev/null || true
    ;;
  status)
    ip -br addr show lle-br
    for ns in lleA lleB; do echo "== $ns"; ip -n "$ns" -br addr; done
    ;;
  *) echo "usage: $0 up|down|status" >&2; exit 64 ;;
esac
