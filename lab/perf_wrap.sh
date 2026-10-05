#!/usr/bin/env bash
# Runs a command under `perf stat` with counters enabled only inside its timed
# region (04-order-book §5 "Counters"). The command must accept
# --perf-ctl-fd/--perf-ack-fd (lob_replay does) and write "enable"/"disable".
#
# usage: lab/perf_wrap.sh <perf.csv> <command> [args...]
# Events: $PERF_EVENTS (comma-separated), default below. Merge the CSV into the
# run JSON with tools/results/merge_perf.py.
set -euo pipefail
csv="${1:?perf csv path}"; shift
events="${PERF_EVENTS:-cycles,instructions,L1-dcache-load-misses,LLC-load-misses,dTLB-load-misses,branch-misses}"
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
mkfifo "$dir/ctl" "$dir/ack"
exec {ctl}<>"$dir/ctl" {ack}<>"$dir/ack"
perf stat -x, -o "$csv" -e "$events" -D -1 --control "fd:${ctl},${ack}" -- \
  "$@" --perf-ctl-fd "$ctl" --perf-ack-fd "$ack"
