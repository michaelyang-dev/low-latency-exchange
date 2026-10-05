#!/usr/bin/env bash
# The harness-side MAC/PHY + cable time c for TTT_cal and the ±250 ns consistency rule
# (METHODOLOGY §13): ttt_harness reflect on host C (port C.p0), ttt_harness calibrate here
# (port A.p0); c = (RTT_A - turnaround_C) / 2 per probe, median. Also records `ethtool -T`
# and the PHC index of both ports (§12). Run once per campaign (setup).
# usage: t18_calibrate.sh KEY=VALUE...   out build host_c client_build a_if c_if c_ip [port] [count] [rate]
set -euo pipefail
declare -A A
for kv in "$@"; do A[${kv%%=*}]=${kv#*=}; done
for k in out build host_c client_build a_if c_if c_ip; do
  [[ -n "${A[$k]:-}" ]] || { echo "t18_calibrate.sh: $k= is required" >&2; exit 64; }
done
port=${A[port]:-31990}; count=${A[count]:-100000}; rate=${A[rate]:-10000}
C=${A[host_c]}
mkdir -p "${A[out]}"
ethtool -T "${A[a_if]}" > "${A[out]}/ethtool-T-a.txt" 2>&1 || true
ssh "$C" "ethtool -T ${A[c_if]}" > "${A[out]}/ethtool-T-c.txt" 2>&1 || true
ssh "$C" "sudo nohup ${A[client_build]}/apps/ttt_harness/ttt_harness reflect --listen ${A[c_ip]}:$port \
  --ifname ${A[c_if]} --timestamps hardware --device-setup --max-runtime $(( count / rate + 60 ))s \
  > /tmp/lle-t18-reflect.json 2> /tmp/lle-t18-reflect.err < /dev/null &"
sleep 2
sudo "${A[build]}/apps/ttt_harness/ttt_harness" calibrate --peer "${A[c_ip]}:$port" --ifname "${A[a_if]}" \
  --timestamps hardware --device-setup --count "$count" --rate "$rate" --out "${A[out]}/calibration.json" > /dev/null || true
sudo chown "$(id -u):$(id -g)" "${A[out]}/calibration.json" 2>/dev/null || true
echo "t18_calibrate: $(grep -oE '"(valid|c_ns)": [^,]*' "${A[out]}/calibration.json" | tr '\n' ' ')"
