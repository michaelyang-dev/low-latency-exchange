#!/bin/bash
# T10 real-feed arbitration run (docs/verification/protocols.md, docs/design/clients.md):
# mold_replay replays a NASDAQ day as MoldUDP64 on two independently packetized and
# impaired lines; refclient arbitrates them (re-requests, GLIMPSE snapshot joins) and
# records book checkpoints; refclient --direct replays the file into the book at the
# same sequences; refclient --compare checks every checkpoint.
#
#   tools/clients/t10_run.sh OUTDIR FILE SEED LOSS_A LOSS_B RATE PORTBASE [extra mold_replay flags...]
#
# Run from the repository root. BIN (default build/client-rel/apps) holds the release
# binaries; REFCLIENT_ARGS adds refclient options (the T10 runs used
# --reorder-capacity 8388608). Exit status: refclient --compare's (0 = every checkpoint matched).
set -u
D=$1; FILE=$2; SEED=$3; LA=$4; LB=$5; RATE=$6; P=$7; shift 7
B=${BIN:-build/client-rel/apps}
mkdir -p "$D"
echo "start $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$D/status.txt"
echo "mold_replay --file $FILE --seed $SEED --loss-a $LA --loss-b $LB --dup 0.1% --reorder 0.1% --rate $RATE $*" > "$D/command.txt"
"$B/refclient/refclient" --line-a :$((P+1)) --line-b :$((P+2)) --rerequest-a :$((P+11)) --rerequest-b :$((P+12)) --glimpse :$((P+20)) \
  --checkpoint-every 10000000 --checkpoints-out "$D/client.ck" --bbo --verbose --request-timeout 20ms \
  --max-runtime 7200s ${REFCLIENT_ARGS:-} --report "$D/client.json" > /dev/null 2> "$D/client.err" &
CPID=$!
sleep 1
"$B/mold_replay/mold_replay" --file "$FILE" --line-a :$((P+1)) --line-b :$((P+2)) --rerequest-a :$((P+11)) --rerequest-b :$((P+12)) \
  --glimpse :$((P+20)) --seed "$SEED" --loss-a "$LA" --loss-b "$LB" --dup 0.1% --reorder 0.1% --rate "$RATE" \
  --linger 10s --ring-messages 16777216 --ring-bytes 1073741824 --report "$D/replay.json" "$@" > /dev/null 2> "$D/replay.err"
echo "replay exit $?" >> "$D/status.txt"
wait $CPID
echo "client exit $?" >> "$D/status.txt"
SPL=$(sed -n 's/.*"splice_checkpoints": "\(.*\)".*/\1/p' "$D/client.json")
"$B/refclient/refclient" --direct "$FILE" --checkpoint-every 10000000 --extra-checkpoints "$SPL" \
  --checkpoints-out "$D/direct.ck" --report "$D/direct.json" > /dev/null 2> "$D/direct.err"
echo "direct exit $?" >> "$D/status.txt"
"$B/refclient/refclient" --compare "$D/client.ck" "$D/direct.ck" --report "$D/compare.json" > /dev/null 2>&1
rc=$?
echo "compare exit $rc $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$D/status.txt"
exit $rc
