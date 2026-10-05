#!/usr/bin/env bash
# Idempotent runtime tuning for a lab host (docs/plan/02 §5.4). Run as root.
# usage: sudo lab/tune.sh <iface> [<iface>...]
# Environment: ISOLATED (default 8-15), HOUSEKEEPING (default 0-7),
#              COALESCE (default "adaptive-rx off adaptive-tx off rx-usecs 0 tx-usecs 0")
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ $# -ge 1 ]] || { echo "usage: $0 <iface>..." >&2; exit 64; }
ISOLATED="${ISOLATED:-8-15}"
HOUSEKEEPING="${HOUSEKEEPING:-0-7}"
COALESCE="${COALESCE:-adaptive-rx off adaptive-tx off rx-usecs 0 tx-usecs 0}"

sysctl -q -w kernel.numa_balancing=0 kernel.timer_migration=0 vm.stat_interval=10
systemctl stop irqbalance 2>/dev/null || true
cpupower frequency-set -g performance >/dev/null
cpupower -c "$ISOLATED" idle-set -d 2 >/dev/null || true   # disable deep C-states on exchange cores

# Workqueues and default IRQ affinity to housekeeping CPUs.
mask=$(python3 - "$HOUSEKEEPING" <<'EOF'
import sys
m = 0
for part in sys.argv[1].split(','):
    a, _, b = part.partition('-')
    for c in range(int(a), int(b or a) + 1): m |= 1 << c
print(format(m, 'x'))
EOF
)
echo "$mask" > /sys/devices/virtual/workqueue/cpumask 2>/dev/null || true
for irq in /proc/irq/[0-9]*; do echo "$HOUSEKEEPING" > "$irq/smp_affinity_list" 2>/dev/null || true; done

for ifc in "$@"; do
  ethtool -C "$ifc" $COALESCE 2>/dev/null || true
  ethtool -K "$ifc" ntuple on 2>/dev/null || true
  # mlx5: keep CQE-based TX timestamps for every variant (ADR-013, docs/plan/07 §2.5).
  ethtool --set-priv-flags "$ifc" tx_port_ts off 2>/dev/null || true
  # Hardware timestamping on every packet in both directions.
  if ethtool --help 2>&1 | grep -q set-hwtimestamp-cfg; then
    ethtool --set-hwtimestamp-cfg "$ifc" tx on rx-filter all
  else
    hwstamp_ctl -i "$ifc" -t 1 -r 1 >/dev/null
  fi
  for q in /sys/class/net/"$ifc"/queues/rx-*; do echo 0 > "$q/rps_cpus" 2>/dev/null || true; done
done

mkdir -p /mnt/lle-huge
mountpoint -q /mnt/lle-huge || mount -t hugetlbfs -o pagesize=2M none /mnt/lle-huge
echo "tune: done (isolated=$ISOLATED housekeeping=$HOUSEKEEPING ifaces=$*)"
