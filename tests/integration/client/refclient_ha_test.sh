#!/bin/bash
# The HA client rule over two order-entry instances (10 §3 step 5): the test
# exchange (loadgen serve, the real engine) serves each session on a primary and
# a mirror port with one byte-identical stream (mirror-attach). refclient sends
# on the primary instance only; when the primary port dies mid-run (connections
# closed without End of Session, unread bytes lost), the mirror instance takes
# over, every pending order is re-sent there in its original order, orders the
# engine already had are dropped by the UserRefNum filter, and nothing is left
# unanswered. After 400 orders the primary stops reading for 300 ms and then dies,
# so orders are in flight (unanswered) at the takeover, whatever the machine's speed.
# usage: refclient_ha_test.sh ITCH_SYNTH MOLD_REPLAY REFCLIENT LOADGEN WORK_DIR PORT_BASE
source "$(dirname "$0")/common.sh"
SYNTH=$1; REPLAY=$2; CLIENT=$3; LG=$4; W=$5; P=$6
rm -rf "$W"; mkdir -p "$W"
"$SYNTH" --out "$W/day.bin" --messages 150000 --symbols 50 --live 5000 --seed 4 > /dev/null
"$LG" serve --listen :$((P+30)) --mirror :$((P+31)) --fail-primary-after-inbound 400 --stall-primary 300ms --sessions 100 --symbols 0 \
  --symbols-from "$W/day.bin" --max-runtime 30s > "$W/serve.json" 2> "$W/serve.err" &
SERVER=$!
PIDS+=($SERVER)
wait_listening "$W/serve.err" 60
"$CLIENT" --line-a :$((P+1)) --line-b :$((P+2)) --rerequest-a :$((P+11)) --rerequest-b :$((P+12)) \
  --trade --symbol SYN0001 --sell-at 199999 --primary :$((P+30)) --backup :$((P+31)) --user U00099 \
  --reconnect 0 --linger 1s --max-runtime 60s --report "$W/client.json" > /dev/null 2> "$W/client.err" &
PIDS+=($!)
sleep 0.5
"$REPLAY" --file "$W/day.bin" --line-a :$((P+1)) --line-b :$((P+2)) --rerequest-a :$((P+11)) --rerequest-b :$((P+12)) \
  --seed 6 --rate 50000 --linger 1s > /dev/null 2> "$W/replay.err"
wait_for "$W/client.json" 30
J="$W/client.json"
grep -q '"feed_ended": true' "$J" || fail "feed did not end"
O=$(json_num "$J" strategy_orders)
[ "$O" -gt 0 ] || fail "no orders"
[ "$(json_num "$J" oe_takeovers)" = 1 ] || fail "expected one takeover, got $(json_num "$J" oe_takeovers)"
[ "$(json_num "$J" oe_logins)" = 2 ] || fail "both instances should have logged in"
[ "$(json_num "$J" oe_duplicate_responses)" -gt 0 ] || fail "the mirror instance should repeat the stream"
[ "$(json_num "$J" oe_resent)" -gt 0 ] || fail "nothing was pending at the takeover"
[ "$(json_num "$J" oe_pending)" = 0 ] || fail "pending orders left after the takeover"
[ "$O" = "$(json_num "$J" oe_acked)" ] || fail "orders $O but acked $(json_num "$J" oe_acked)"
[ "$(json_num "$J" oe_sequence_jumps)" = 0 ] || fail "the two instances' streams diverged"
kill "$SERVER" 2>/dev/null || true
wait "$SERVER" 2>/dev/null || true
[ "$(json_num "$W/serve.json" primary_failures)" = 1 ] || fail "the primary port did not fail"
# Exactly once at the engine: every order applied once (lost bytes re-sent, any
# order seen twice ignored by the UserRefNum filter and audited).
A=$(json_num "$W/serve.json" audits); I=$(json_num "$W/serve.json" inbound)
[ $((I - A)) = "$O" ] || fail "engine applied $((I - A)) orders, client sent $O"
echo "PASS: $O orders, takeover with $(json_num "$J" oe_resent) re-sent, all acknowledged exactly once"
