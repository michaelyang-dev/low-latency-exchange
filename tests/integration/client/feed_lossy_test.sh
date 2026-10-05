#!/bin/bash
# mold_replay -> refclient over lossy dual lines on a synthetic day (03 §9, T10 on
# loopback): seeded independent loss, duplication and reordering per line, two
# total outages that force snapshot joins; the reconstructed book must equal a
# direct replay of the file at every checkpoint (book digest, stream hash, BBO
# digest before the first splice).
# usage: feed_lossy_test.sh ITCH_SYNTH MOLD_REPLAY REFCLIENT WORK_DIR PORT_BASE
source "$(dirname "$0")/common.sh"
SYNTH=$1; REPLAY=$2; CLIENT=$3; W=$4; P=$5
rm -rf "$W"; mkdir -p "$W"
"$SYNTH" --out "$W/day.bin" --messages 400000 --symbols 300 --live 30000 --seed 17 > /dev/null
"$CLIENT" --line-a :$((P+1)) --line-b :$((P+2)) --rerequest-a :$((P+11)) --rerequest-b :$((P+12)) \
  --glimpse :$((P+20)) --checkpoint-every 40000 --checkpoints-out "$W/client.ck" --bbo --snapshot-gap 5000 \
  --request-timeout 50ms --max-runtime 200s --report "$W/client.json" > /dev/null 2> "$W/client.err" &
PIDS+=($!)
sleep 0.5
"$REPLAY" --file "$W/day.bin" --line-a :$((P+1)) --line-b :$((P+2)) --rerequest-a :$((P+11)) --rerequest-b :$((P+12)) \
  --glimpse :$((P+20)) --seed 4242 --loss-a 3% --loss-b 5% --dup 0.5% --reorder 0.5% --rate 200000 \
  --outage 120000:20000 --outage 290000:15000 --linger 120s --report "$W/replay.json" > /dev/null 2> "$W/replay.err" &
# End of session repeats for the linger, so a slow client (sanitizers, a loaded
# machine) still learns the end once it has caught up; stopped when the client is done.
REPLAY_PID=$!
PIDS+=($REPLAY_PID)

wait_for "$W/client.json" 200
kill -INT "$REPLAY_PID" 2>/dev/null || true
wait "$REPLAY_PID" 2>/dev/null || true
grep -q '"feed_ended": true' "$W/client.json" || fail "the feed did not end: $(cat "$W/client.err")"
SPL=$(json_str "$W/client.json" splice_checkpoints)
[ -n "$SPL" ] || fail "no snapshot join happened"
"$CLIENT" --direct "$W/day.bin" --checkpoint-every 40000 --extra-checkpoints "$SPL" \
  --checkpoints-out "$W/direct.ck" > "$W/direct.json"
"$CLIENT" --compare "$W/client.ck" "$W/direct.ck" > "$W/compare.json" || fail "checkpoints differ: $(cat "$W/compare.json")"
# Two outages: two joins on a fast machine; on a slow one (sanitizers) the first
# join's spin can already cover the second outage.
[ "$(json_num "$W/client.json" snapshots_applied)" -ge 1 ] || fail "expected a snapshot join"
[ "$(json_num "$W/client.json" arb_requests_sent_a)" -gt 0 ] || fail "no re-requests"
[ "$(json_num "$W/replay.json" a_dropped)" -gt 0 ] && [ "$(json_num "$W/replay.json" b_dropped)" -gt 0 ] || fail "no loss injected"
echo "PASS: $(json_num "$W/compare.json" compared_books) checkpoints equal, $(json_num "$W/client.json" snapshots_applied) snapshot joins"
