#!/usr/bin/env bash
# One T18/T16/T19 measurement (METHODOLOGY §12-§14): ttt_harness on this host (A, port
# A.p0), refclient on host C (port C.p0) over one variant, then the offline analysis with
# refclient's order-stamp log and the campaign's calibration. Run by lab/run_campaign.sh.
#
# usage: t18_rep.sh KEY=VALUE...
#   out rep cell build host_c client_build a_if c_if a_ip line_a line_b desk_port input
#   variant (an I/O variant, or "afxdp" = the value of afxdp_variant) afxdp_variant
#   coalescing_map ("variant:cell,...": driver-default | adaptive | rx-usecs-0)
#   rate trigger_rate duration warmup min_triggers seed_base symbol trigger_price
#   harness_cpu harness_rx_cpu client_cpu napi_cpu
# Writes OUT/harness-REP[-CELL].{json,triggers.bin,hdr}, OUT/client-REP[-CELL].{json,hwts}
# and OUT/run-REP[-CELL].json (the verdict tools/results reads).
set -euo pipefail
declare -A A
for kv in "$@"; do A[${kv%%=*}]=${kv#*=}; done
need() { for k in "$@"; do [[ -n "${A[$k]:-}" ]] || { echo "t18_rep.sh: $k= is required" >&2; exit 64; }; done; }
need out rep build host_c client_build a_if c_if a_ip line_a line_b desk_port input variant rate trigger_rate duration \
  warmup min_triggers seed_base symbol trigger_price harness_cpu harness_rx_cpu client_cpu
variant=${A[variant]}
[[ "$variant" == afxdp ]] && { need afxdp_variant; variant=${A[afxdp_variant]}; }
for v in "${A[variant]}" "$variant" "${A[afxdp_variant]:-}"; do
  [[ "$v" == TBD_* ]] && { echo "t18_rep.sh: $v (not pre-registered)" >&2; exit 3; }
done
suffix=${A[rep]}${A[cell]:+-${A[cell]}}
seed=$(( ${A[seed_base]} + 10#${A[rep]} ))
C=${A[host_c]}
CB=${A[client_build]}
remote="/tmp/lle-t18"
# Coalescing cell of this variant on the SUT's port (METHODOLOGY §14, fixed in §18).
coal=driver-default
IFS=',' read -ra pairs <<<"${A[coalescing_map]:-}"
for p in "${pairs[@]}"; do [[ "${p%%:*}" == "$variant" ]] && coal=${p#*:}; done
case "$coal" in
  driver-default) coal_args="" ;;
  adaptive) coal_args="adaptive-rx on adaptive-tx on" ;;
  rx-usecs-0) coal_args="adaptive-rx off adaptive-tx off rx-usecs 0 tx-usecs 0" ;;
  TBD_*) echo "t18_rep.sh: coalescing for $variant is $coal (not pre-registered)" >&2; exit 3 ;;
  *) echo "t18_rep.sh: unknown coalescing cell $coal" >&2; exit 64 ;;
esac
[[ -n "$coal_args" ]] && ssh "$C" "sudo ethtool -C ${A[c_if]} $coal_args" || true
xsk_args=""
case "$variant" in
  xsk) xsk_args="--xsk-queue 0" ;;
  xsk-threaded) xsk_args="--xsk-queue 0 --napi-cpu ${A[napi_cpu]:?napi_cpu= is required for xsk-threaded}" ;;
esac
runtime=$(( ${A[duration]%s} + 120 ))s
ssh "$C" "mkdir -p $remote && rm -f $remote/client-$suffix.*"
ssh "$C" "sudo nohup $CB/apps/refclient/refclient --variant $variant --ifname ${A[c_if]} --timestamps hardware \
  --device-setup --cpu ${A[client_cpu]} $xsk_args --line-a ${A[line_a]} --line-b ${A[line_b]} \
  --rerequest-a ${A[a_ip]}:$(( ${A[desk_port]} + 1 )) --rerequest-b ${A[a_ip]}:$(( ${A[desk_port]} + 1 )) --trade \
  --symbol ${A[symbol]} --sell-at ${A[trigger_price]} --primary ${A[a_ip]}:${A[desk_port]} --user U00099 \
  --linger 2s --max-runtime $runtime --stamp-log $remote/client-$suffix.hwts --report $remote/client-$suffix.json \
  > $remote/client-$suffix.out 2> $remote/client-$suffix.err < /dev/null &"
sleep 3  # refclient reserves its book and joins the groups before the feed starts
calib=()
[[ -s "${A[out]}/calibration.json" ]] && calib=(--calibration "${A[out]}/calibration.json")
sudo "${A[build]}/apps/ttt_harness/ttt_harness" run --file "${A[input]}" --line-a "${A[line_a]}" --line-b "${A[line_b]}" \
  --listen "${A[a_ip]}:${A[desk_port]}" --rerequest "${A[a_ip]}:$(( ${A[desk_port]} + 1 ))" --feed xsk --ifname "${A[a_if]}" --source-ip "${A[a_ip]}" --timestamps hardware \
  --device-setup --rate "${A[rate]}" --trigger-rate "${A[trigger_rate]}" --duration "${A[duration]}" --warmup "${A[warmup]}" \
  --min-triggers "${A[min_triggers]}" --seed "$seed" --symbol "${A[symbol]}" --trigger-price "${A[trigger_price]}" \
  --cpu "${A[harness_cpu]}" --rx-cpu "${A[harness_rx_cpu]}" "${calib[@]}" --out "${A[out]}" --run-name "harness-$suffix" \
  > /dev/null
for _ in $(seq 1 600); do
  ssh "$C" "test -s $remote/client-$suffix.json" && break
  sleep 1
done
scp -q "$C:$remote/client-$suffix.json" "$C:$remote/client-$suffix.hwts" "$C:$remote/client-$suffix.err" "${A[out]}/"
sudo chown "$(id -u):$(id -g)" "${A[out]}"/harness-"$suffix".* 2>/dev/null || true
"${A[build]}/apps/ttt_harness/ttt_harness" analyze --triggers "${A[out]}/harness-$suffix.triggers.bin" \
  --harness-report "${A[out]}/harness-$suffix.json" --client-log "${A[out]}/client-$suffix.hwts" \
  --client-report "${A[out]}/client-$suffix.json" "${calib[@]}" --warmup "${A[warmup]}" \
  --min-triggers "${A[min_triggers]}" --out "${A[out]}/run-$suffix.json" > /dev/null
echo "t18_rep: run-$suffix: $(grep -o '"valid": [a-z]*' "${A[out]}/run-$suffix.json" | head -1)"
