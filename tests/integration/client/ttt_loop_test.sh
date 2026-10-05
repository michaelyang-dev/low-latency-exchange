#!/bin/bash
# T18 instrument loop on one host (METHODOLOGY §13; functional only, never a result):
# ttt_harness publishes a synthetic day with Poisson triggers on two loopback lines and
# takes orders on its kernel TCP desk; refclient runs the pre-registered strategy over
# each I/O variant given and writes its order-stamp log. Checks, per variant: every
# trigger produced exactly one order, every order was matched to its trigger by
# ClOrdID on both sides, the client delivered the whole stream, and the run is marked
# INVALID because no hardware timestamps exist here (software stamps on Linux, none on
# macOS); `analyze` then merges the client log and keeps the verdict.
# usage: ttt_loop_test.sh ITCH_SYNTH TTT_HARNESS REFCLIENT WORK_DIR PORT_BASE VARIANT...
# LLE_TTT_RATE (messages/s, default 100000) and LLE_TTT_WAIT (s, default 30) are lowered
# and raised for sanitizer builds, whose client cannot take the full rate over UDP.
source "$(dirname "$0")/common.sh"
SYNTH=$1; HARNESS=$2; CLIENT=$3; W=$4; P=$5; shift 5
RATE=${LLE_TTT_RATE:-100000}
WAIT=${LLE_TTT_WAIT:-30}
VARIANTS=("$@")
[ ${#VARIANTS[@]} -gt 0 ] || VARIANTS=(epoll)
rm -rf "$W"; mkdir -p "$W"
"$SYNTH" --out "$W/day.bin" --messages 200000 --symbols 50 --live 5000 --seed 11 > /dev/null
TS=off
[ "$(uname -s)" = Linux ] && TS=software
n=0
for V in "${VARIANTS[@]}"; do
  n=$((n + 1))
  B=$((P + 40 * n))
  D="$W/$V"; mkdir -p "$D"
  "$CLIENT" --variant "$V" --timestamps $TS --line-a :$((B+1)) --line-b :$((B+2)) \
    --rerequest-a :$((B+11)) --rerequest-b :$((B+11)) --request-timeout 200ms --trade --symbol LLTRG --sell-at 10.00 \
    --primary :$((B+30)) --user U00099 --linger 1s --max-runtime 60s --stamp-log "$D/client.hwts" \
    --report "$D/client.json" > /dev/null 2> "$D/client.err" &
  CPID=$!
  PIDS+=($CPID)
  sleep 0.5
  if ! kill -0 "$CPID" 2>/dev/null; then
    if grep -q "not compiled" "$D/client.err"; then
      echo "skip: $V (not compiled into this build)"
    elif grep -q "not permitted" "$D/client.err" && [ "$(id -u)" != 0 ]; then
      echo "skip: $V (needs CAP_NET_ADMIN: $(tail -1 "$D/client.err"))"
    else
      fail "$V: refclient exited: $(tail -2 "$D/client.err")"
    fi
    kill_all
    continue
  fi
  "$HARNESS" run --file "$W/day.bin" --line-a :$((B+1)) --line-b :$((B+2)) --listen :$((B+30)) \
    --rerequest :$((B+11)) --timestamps $TS --rate "$RATE" --trigger-rate 2000 --duration 3s --warmup 1s --min-triggers 100 \
    --start-delay 1s --linger 1500ms --seed 7 --out "$D" --run-name run-01 > /dev/null 2> "$D/harness.err" \
    || fail "$V: harness exited with an error: $(tail -2 "$D/harness.err")"
  wait_for "$D/client.json" "$WAIT"
  H="$D/run-01.json"; C="$D/client.json"
  grep -q '"feed_ended": true' "$C" || fail "$V: client feed did not end"
  [ "$(json_num "$C" delivered)" = "$(json_num "$H" messages)" ] || fail "$V: client delivered $(json_num "$C" delivered) of $(json_num "$H" messages)"
  T=$(json_num "$H" triggers)
  [ "$T" -gt 1000 ] || fail "$V: only $T triggers"
  [ "$(json_num "$C" strategy_orders)" = "$T" ] || fail "$V: $T triggers but $(json_num "$C" strategy_orders) orders"
  [ "$(json_num "$H" desk_orders)" = "$T" ] || fail "$V: desk saw $(json_num "$H" desk_orders) orders of $T"
  [ "$(json_num "$H" desk_orders_unknown_clordid)" = 0 ] || fail "$V: orders with an unknown ClOrdID"
  [ "$(json_num "$H" orders_missing)" = 0 ] || fail "$V: measured triggers without an order"
  [ "$(json_num "$H" orders_duplicate)" = 0 ] || fail "$V: duplicate orders"
  [ "$(json_num "$C" oe_acked)" = "$T" ] || fail "$V: acked $(json_num "$C" oe_acked) of $T"
  [ "$(json_num "$C" stamp_log_records)" = "$T" ] || fail "$V: stamp log has $(json_num "$C" stamp_log_records) records"
  [ "$(json_num "$C" stamp_log_untagged)" = 0 ] || fail "$V: orders without a TX attribution"
  grep -q '"feed_gap_free": true' "$C" || fail "$V: the client feed had gaps"
  grep -q '"valid": false' "$H" || fail "$V: a run without hardware timestamps was not marked invalid"
  grep -q '"run_valid": false' "$H" || fail "$V: run_valid without hardware timestamps"
  if [ "$TS" = software ]; then
    grep -q 'software timestamps present' "$H" || fail "$V: software timestamps not reported: $(grep invalid_reasons "$H")"
    [ "$(json_num "$H" raw_pairs_ok)" = 0 ] || fail "$V: software stamps produced TTT_raw pairs"
  fi
  "$HARNESS" analyze --triggers "$D/run-01.triggers.bin" --harness-report "$H" --client-log "$D/client.hwts" \
    --client-report "$C" --warmup 1s --min-triggers 100 --out "$D/analysis.json" > /dev/null || fail "$V: analyze failed"
  A="$D/analysis.json"
  [ "$(json_num "$A" client_measured)" = "$(json_num "$H" triggers_measured)" ] || fail "$V: client log matched $(json_num "$A" client_measured) of $(json_num "$H" triggers_measured) measured triggers"
  [ "$(json_num "$A" client_unknown)" = 0 ] || fail "$V: client records for unknown triggers"
  grep -q '"run_valid": false' "$A" || fail "$V: analyze marked a software-stamped run valid"
  echo "ok: $V: $T triggers, all ordered, matched and acknowledged; run marked invalid ($TS timestamps)"
  kill_all
done
echo "PASS: ${VARIANTS[*]}"
