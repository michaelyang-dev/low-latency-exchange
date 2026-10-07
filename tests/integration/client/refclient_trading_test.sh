#!/bin/bash
# refclient end to end: feed -> book -> T18 strategy -> OUCH over SoupBinTCP to the
# loopback OUCH server. Every trigger sends one IOC whose ClOrdID is the trigger's
# sequence; every order is acknowledged. The client's event log (11 §3, T32) holds the
# orders, their responses, the gap fills of the lossy lines and the first arrivals, and
# its metrics segment (read by lle-top) the first arrivals per line and the A/B skew.
# usage: refclient_trading_test.sh ITCH_SYNTH MOLD_REPLAY REFCLIENT LOADGEN WORK_DIR PORT_BASE NLOG_DECODE LLE_TOP
source "$(dirname "$0")/common.sh"
SYNTH=$1; REPLAY=$2; CLIENT=$3; LG=$4; W=$5; P=$6; DECODE=$7; TOP=$8
SEG="rc$P"
rm -rf "$W"; mkdir -p "$W"
"$SYNTH" --out "$W/day.bin" --messages 100000 --symbols 50 --live 5000 --seed 3 > /dev/null
"$LG" serve --listen :$((P+30)) --sessions 100 --symbols 0 --symbols-from "$W/day.bin" --max-runtime 60s \
  > "$W/serve.json" 2> "$W/serve.err" &
PIDS+=($!)
wait_listening "$W/serve.err" 60
"$CLIENT" --line-a :$((P+1)) --line-b :$((P+2)) --rerequest-a :$((P+11)) --rerequest-b :$((P+12)) \
  --trade --symbol SYN0001 --sell-at 199999 --max-orders 300 --primary :$((P+30)) --user U00099 \
  --linger 1s --max-runtime 60s --report "$W/client.json" --nlog "$W/client.nlog" --metrics "$SEG" > /dev/null 2> "$W/client.err" &
PIDS+=($!)
sleep 0.5
"$REPLAY" --file "$W/day.bin" --line-a :$((P+1)) --line-b :$((P+2)) --rerequest-a :$((P+11)) --rerequest-b :$((P+12)) \
  --seed 5 --loss-a 1% --loss-b 1% --rate 100000 --linger 1s > /dev/null 2> "$W/replay.err"
wait_for "$W/client.json" 30
J="$W/client.json"
grep -q '"feed_ended": true' "$J" || fail "feed did not end"
O=$(json_num "$J" strategy_orders)
[ "$O" -gt 0 ] || fail "no orders sent"
[ "$O" = "$(json_num "$J" oe_acked)" ] || fail "orders $O but acked $(json_num "$J" oe_acked)"
[ "$(json_num "$J" oe_pending)" = 0 ] || fail "pending orders left"
[ "$(json_num "$J" oe_logins)" = 1 ] || fail "login"
wait "${PIDS[1]}" || fail "the client exited non-zero"  # its log is complete once it exits
"$DECODE" "$W/client.nlog" > "$W/client.log" 2> "$W/decode.err" || fail "nlog_decode: $(cat "$W/decode.err")"
for e in "client order 'O' urn" "client response" "client first arrivals: line A" "client gap filled"; do
  grep -q "$e" "$W/client.log" || fail "the client log has no \"$e\""
done
SENT=$(grep -c "client order 'O' urn" "$W/client.log")
[ "$SENT" = "$O" ] || fail "the client log has $SENT orders, the report $O"
"$TOP" "$SEG" --once > "$W/top.txt" 2>&1 || fail "lle_top: $(cat "$W/top.txt")"
for c in first_arrivals_line_a first_arrivals_line_b orders_sent; do
  V=$(awk -v c="$c" '$1 == c {print $3}' "$W/top.txt")
  [ -n "$V" ] && [ "$V" -gt 0 ] || fail "metrics: $c is '${V}': $(cat "$W/top.txt")"
done
grep -q "ab_skew" "$W/top.txt" || fail "metrics: no ab_skew histogram"
echo "PASS: $O IOC orders sent and acknowledged, and logged"
