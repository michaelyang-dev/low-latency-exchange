#!/usr/bin/env bash
# One T32 arm run (METHODOLOGY §16): the T20 configuration at the T20 headline rate with
# nlog on (arm A) or off (arm B), on host A, loadgen v2 on host C. The per-message cost
# is the exchange's summed stage work time per inbound message over the measured window
# (work_ns_per_msg_x1000, from the metrics segment); tools/results/summarize.py computes
# the overhead (on - off) / off from the arms. ABBA order is the campaign's matrix order.
#
# usage: t32_rep.sh KEY=VALUE...   out slot build host_c client_build a_ip gw_port profile rate duration warmup
#                                  exch_conf_on exch_conf_off node threads cpus loadgen_variant c_if c_out nlog_glob
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
declare -A A
for kv in "$@"; do A[${kv%%=*}]=${kv#*=}; done
for k in out slot build host_c client_build a_ip gw_port profile rate duration warmup exch_conf_on exch_conf_off node c_out; do
  [[ -n "${A[$k]:-}" ]] || { echo "t32_rep.sh: $k= is required" >&2; exit 64; }
  [[ "${A[$k]}" == TBD_* ]] && { echo "t32_rep.sh: $k = ${A[$k]} (not pre-registered)" >&2; exit 3; }
done
slot=${A[slot]}
case "$slot" in A*) arm=on; conf=${A[exch_conf_on]} ;; B*) arm=off; conf=${A[exch_conf_off]} ;;
  *) echo "t32_rep.sh: slot must start with A (nlog on) or B (nlog off)" >&2; exit 64 ;; esac
name="t32-$slot"
"$here/t20_node.sh" start "$name" build="${A[build]}" exch_conf="$conf" node="${A[node]}" out="${A[out]}"
root="$(cd "$here/../.." && pwd)"
ssh "${A[host_c]}" "mkdir -p ${A[c_out]} && ${A[client_build]}/apps/loadgen/loadgen run --server ${A[a_ip]}:${A[gw_port]} \
  --profile $root/${A[profile]} --rate ${A[rate]} --duration ${A[duration]} --warmup ${A[warmup]} \
  --threads ${A[threads]:-1} ${A[cpus]:+--cpus ${A[cpus]}} --variant ${A[loadgen_variant]:-xsk} \
  ${A[c_if]:+--ifname ${A[c_if]}} --out ${A[c_out]} --run-name $name > /dev/null 2>&1 || true"
"$here/t20_node.sh" stop "$name" build="${A[build]}" node="${A[node]}" out="${A[out]}" host_c="${A[host_c]}" c_out="${A[c_out]}"
# Logger drops and the event census of the logging-on arm (plan 11 §3).
if [[ "$arm" == on && -n "${A[nlog_glob]:-}" ]]; then
  for f in ${A[nlog_glob]}; do "${A[build]}/apps/nlog_decode/nlog_decode" --stats "$f" > /dev/null 2>> "${A[out]}/$name.nlog-stats.txt" || true; done
fi
python3 - "${A[out]}/$name.json" "${A[out]}/run-01-$slot.json" "$arm" <<'PY'
import json, sys
src, dst, arm = sys.argv[1:4]
try:
    run = json.load(open(src))
except (OSError, json.JSONDecodeError):
    run = {"valid": False, "invalid_conditions": "no loadgen run"}
run["arm"] = arm
json.dump(run, open(dst, "w"), indent=2)
PY
