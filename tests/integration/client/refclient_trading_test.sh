#!/bin/bash
# refclient end to end: feed -> book -> T18 strategy -> OUCH over SoupBinTCP to the
# loopback OUCH server. Every trigger sends one IOC whose ClOrdID is the trigger's
# sequence; every order is acknowledged.
# usage: refclient_trading_test.sh ITCH_SYNTH MOLD_REPLAY REFCLIENT LOADGEN WORK_DIR PORT_BASE
source "$(dirname "$0")/common.sh"
SYNTH=$1; REPLAY=$2; CLIENT=$3; LG=$4; W=$5; P=$6
rm -rf "$W"; mkdir -p "$W"
"$SYNTH" --out "$W/day.bin" --messages 100000 --symbols 50 --live 5000 --seed 3 > /dev/null
"$LG" serve --listen :$((P+30)) --sessions 100 --symbols 0 --symbols-from "$W/day.bin" --max-runtime 60s \
  > "$W/serve.json" 2> "$W/serve.err" &
PIDS+=($!)
wait_listening "$W/serve.err" 60
"$CLIENT" --line-a :$((P+1)) --line-b :$((P+2)) --rerequest-a :$((P+11)) --rerequest-b :$((P+12)) \
  --trade --symbol SYN0001 --sell-at 199999 --max-orders 300 --primary :$((P+30)) --user U00099 \
  --linger 1s --max-runtime 60s --report "$W/client.json" > /dev/null 2> "$W/client.err" &
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
echo "PASS: $O IOC orders sent and acknowledged"
