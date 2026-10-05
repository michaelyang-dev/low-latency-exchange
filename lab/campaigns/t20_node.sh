#!/usr/bin/env bash
# The exchange-host side of a T20/T32 run (METHODOLOGY §15, §16), on host A. Called by
# `loadgen search` (--before-run / --after-run) and by t32_rep.sh.
#
#   t20_node.sh start NAME KEY=VALUE...      build exch_conf node out [sampler_interval]
#     fresh node: stops a running exchanged, empties its data directory, starts it with
#     the campaign's configuration (solo, durable L3 journal, CPUs 8-15, nlog on), waits
#     for its metrics segment, snapshots /proc/interrupts and /proc/softirqs, starts the
#     metrics sampler and mpstat.
#   t20_node.sh stop NAME KEY=VALUE...       build node out host_c c_out [irq_match] [softirq_allow]
#     snapshots the interrupts again, records the pinning map, stops the sampler, mpstat
#     and the node, fetches loadgen's run files from host C, and merges the verdict:
#     loadgen check-backlog (condition 3), tools/results/irq_delta.py (CPUs 0-7) and
#     tools/results/merge_t20.py (the run's final "valid").
#   t20_node.sh capacity KEY=VALUE...        build host_c client_build a_ip port rate profile out [threads] [cpus]
#     the capacity self-test (07 §3): loadgen on C against the engine-free ack server here
#     must hold `rate` (>= 6M msgs/s) with generator lateness p99.9 <= 1 us.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cmd=${1:?start|stop|capacity}; shift
name=""
[[ "$cmd" != capacity ]] && { name=${1:?NAME}; shift; }
declare -A A
for kv in "$@"; do A[${kv%%=*}]=${kv#*=}; done
need() { for k in "$@"; do [[ -n "${A[$k]:-}" ]] || { echo "t20_node.sh: $k= is required" >&2; exit 64; }; done; }
out=${A[out]:-.}
mkdir -p "$out"
case "$cmd" in
  start)
    need build exch_conf node
    [[ "${A[exch_conf]}" == TBD_* ]] && { echo "t20_node.sh: exch_conf ${A[exch_conf]}" >&2; exit 3; }
    sudo pkill -INT -f "apps/exchanged/exchanged" 2>/dev/null || true
    sleep 1
    data=$(awk -F= '/^data_dir/{gsub(/[ \t]|#.*/,"",$2); print $2; exit}' "${A[exch_conf]}")
    [[ -n "$data" && "$data" != / ]] && sudo rm -rf "$data"
    sudo nohup "${A[build]}/apps/exchanged/exchanged" --config "${A[exch_conf]}" > "$out/$name.exchanged.out" \
      2> "$out/$name.exchanged.err" < /dev/null &
    for _ in $(seq 1 300); do [[ -e "/dev/shm/lle-stats-${A[node]}" ]] && break; sleep 0.1; done
    cat /proc/interrupts > "$out/$name.irq-before.txt"
    cat /proc/softirqs > "$out/$name.softirq-before.txt"
    nohup "${A[build]}/apps/loadgen/loadgen" sample-metrics --node "${A[node]}" --interval "${A[sampler_interval]:-250ms}" \
      --out "$out/$name.metrics.jsonl" > /dev/null 2>&1 < /dev/null &
    echo $! > "$out/$name.sampler.pid"
    nohup mpstat -P ALL 1 > "$out/$name.mpstat.txt" 2>&1 < /dev/null &
    echo $! > "$out/$name.mpstat.pid"
    sleep 1
    ;;
  stop)
    need build node host_c c_out
    cat /proc/interrupts > "$out/$name.irq-after.txt"
    cat /proc/softirqs > "$out/$name.softirq-after.txt"
    ps -eLo pid,tid,psr,comm | awk 'NR==1 || /exchanged|lle-/' > "$out/$name.pinning.txt" || true
    kill -INT "$(cat "$out/$name.sampler.pid")" 2>/dev/null || true
    kill "$(cat "$out/$name.mpstat.pid")" 2>/dev/null || true
    sleep 0.5
    sudo pkill -INT -f "apps/exchanged/exchanged" 2>/dev/null || true
    scp -q "${A[host_c]}:${A[c_out]}/$name.json" "${A[host_c]}:${A[c_out]}/$name.hdr" "$out/" || true
    if [[ -s "$out/$name.json" ]]; then
      "${A[build]}/apps/loadgen/loadgen" check-backlog --samples "$out/$name.metrics.jsonl" --run "$out/$name.json" \
        --out "$out/backlog-$name.json" > /dev/null || true
      python3 "$root/tools/results/irq_delta.py" "$out/$name.irq-before.txt" "$out/$name.irq-after.txt" \
        --softirq "$out/$name.softirq-before.txt" "$out/$name.softirq-after.txt" --cpus 0-7 \
        --match "${A[irq_match]:-mlx5|nvme}" --softirq-allow "${A[softirq_allow]:-0}" > "$out/irq-$name.json"
      python3 "$root/tools/results/merge_t20.py" "$out/$name.json" "$out/backlog-$name.json" "$out/irq-$name.json"
    fi
    ;;
  capacity)
    need build host_c client_build a_ip port rate profile
    nohup "${A[build]}/apps/loadgen/loadgen" serve --ack-only --listen "${A[a_ip]}:${A[port]}" --max-runtime 120s \
      > "$out/capacity-server.json" 2> "$out/capacity-server.err" < /dev/null &
    sleep 1
    ssh "${A[host_c]}" "${A[client_build]}/apps/loadgen/loadgen run --server ${A[a_ip]}:${A[port]} \
      --profile $root/${A[profile]} --rate ${A[rate]} --duration 20s --warmup 5s --threads ${A[threads]:-1} \
      ${A[cpus]:+--cpus ${A[cpus]}} --out /tmp --run-name lle-capacity > /dev/null 2>&1 || true; cat /tmp/lle-capacity.json" \
      > "$out/capacity.json"
    grep -q '"lateness_ok": true' "$out/capacity.json" && grep -q '"responses_valid": true' "$out/capacity.json" || {
      echo "t20_node.sh: the capacity self-test failed (loadgen must hold ${A[rate]} msgs/s with lateness p99.9 <= 1 us)" >&2
      exit 1
    }
    ;;
  *) echo "t20_node.sh: start|stop|capacity" >&2; exit 64 ;;
esac
