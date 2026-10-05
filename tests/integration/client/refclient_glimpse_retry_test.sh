#!/bin/bash
# A refused snapshot connect is retried (refclient.h): a total outage early in the day
# forces a snapshot join while the GLIMPSE port still refuses connections (mold_replay
# --glimpse-delay); refclient must keep retrying every snapshot_retry, join once the
# port listens, and end with the direct replay's book at every checkpoint.
# usage: refclient_glimpse_retry_test.sh ITCH_SYNTH MOLD_REPLAY REFCLIENT WORK_DIR PORT_BASE
source "$(dirname "$0")/common.sh"
SYNTH=$1; REPLAY=$2; CLIENT=$3; W=$4; P=$5
rm -rf "$W"; mkdir -p "$W"
"$SYNTH" --out "$W/day.bin" --messages 300000 --symbols 100 --live 10000 --seed 23 > /dev/null
"$CLIENT" --line-a :$((P+1)) --line-b :$((P+2)) --rerequest-a :$((P+11)) --rerequest-b :$((P+12)) \
  --glimpse :$((P+20)) --checkpoint-every 30000 --checkpoints-out "$W/client.ck" --snapshot-gap 5000 \
  --request-timeout 50ms --max-runtime 120s --verbose --report "$W/client.json" > /dev/null 2> "$W/client.err" &
PIDS+=($!)
sleep 2  # refclient reserves its book and reorder buffer first
# The outage starts after 0.2 s of feed; the snapshot port opens after 2 s.
"$REPLAY" --file "$W/day.bin" --line-a :$((P+1)) --line-b :$((P+2)) --rerequest-a :$((P+11)) --rerequest-b :$((P+12)) \
  --glimpse :$((P+20)) --glimpse-delay 2s --seed 77 --rate 100000 --outage 20000:15000 --linger 60s \
  --report "$W/replay.json" > /dev/null 2> "$W/replay.err" &
REPLAY_PID=$!
PIDS+=($REPLAY_PID)
wait_for "$W/client.json" 120
kill -INT "$REPLAY_PID" 2>/dev/null || true
wait "$REPLAY_PID" 2>/dev/null || true
grep -q '"feed_ended": true' "$W/client.json" || fail "the feed did not end: $(tail -5 "$W/client.err")"
F=$(json_num "$W/client.json" snapshot_failures)
[ "$F" -ge 1 ] || fail "no refused snapshot connect was seen (failures $F)"
grep -q "connect refused" "$W/client.err" || fail "refusals not reported as such"
[ "$(json_num "$W/client.json" snapshots_applied)" -ge 1 ] || fail "the snapshot join never completed"
SPL=$(json_str "$W/client.json" splice_checkpoints)
[ -n "$SPL" ] || fail "no splice checkpoint"
"$CLIENT" --direct "$W/day.bin" --checkpoint-every 30000 --extra-checkpoints "$SPL" \
  --checkpoints-out "$W/direct.ck" > "$W/direct.json"
"$CLIENT" --compare "$W/client.ck" "$W/direct.ck" > "$W/compare.json" || fail "checkpoints differ: $(cat "$W/compare.json")"
echo "PASS: $F refused snapshot connects retried, join completed, $(json_num "$W/compare.json" compared_books) checkpoints equal"
