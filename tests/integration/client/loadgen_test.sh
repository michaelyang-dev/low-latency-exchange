#!/bin/bash
# loadgen -> the loopback OUCH server (the real sequencer and engine behind
# SoupBinTCP): the pre-registered mix over 4 sessions; every message must get its
# expected response, none missing, no unexpected response.
# usage: loadgen_test.sh LOADGEN WORK_DIR PORT
source "$(dirname "$0")/common.sh"
LG=$1; W=$2; P=$3
rm -rf "$W"; mkdir -p "$W"
"$LG" serve --listen :$P --sessions 8 --symbols 2000 --max-runtime 60s > "$W/serve.json" 2> "$W/serve.err" &
PIDS+=($!)
wait_listening "$W/serve.err" 60
"$LG" --server :$P --sessions 4 --rate 20000 --duration 2s --seed 99 --out "$W" --run-name run-01 > /dev/null 2> "$W/run.err" \
  || fail "loadgen failed: $(cat "$W/run.err")"
J="$W/run-01.json"
[ -s "$W/run-01.hgrm" ] || fail "no histogram"
grep -q '"responses_valid": true' "$J" || fail "responses not valid"
[ "$(json_num "$J" missing)" = 0 ] || fail "missing responses"
[ "$(json_num "$J" unexpected)" = 0 ] || fail "unexpected responses"
[ "$(json_num "$J" acked)" = "$(json_num "$J" scheduled)" ] || fail "not every message acknowledged"
[ "$(json_num "$J" ioc_shares)" = "$(json_num "$J" ioc_shares_expected)" ] || fail "IOC fills differ from the model"
echo "PASS: $(json_num "$J" acked) messages acknowledged, p99 $(json_num "$J" p99_ns) ns (indicative)"
