#!/bin/bash
# itch2ouch on a seeded synthetic day (the CI order-flow day): convert, read the
# script back (every record valid inbound OUCH, times non-decreasing), and run the
# divergence report through the real sequencer and engine.
# usage: itch2ouch_test.sh ITCH_SYNTH ITCH2OUCH WORK_DIR
source "$(dirname "$0")/common.sh"
SYNTH=$1; I2O=$2; W=$3
rm -rf "$W"; mkdir -p "$W"
"$SYNTH" --out "$W/day.bin" --messages 200000 --symbols 100 --live 10000 --seed 8 > /dev/null
"$I2O" convert --itch "$W/day.bin" --out "$W/day.ofs.gz" --sessions 4 --synthetic > "$W/convert.json"
R=$(json_num "$W/convert.json" records)
[ "$R" -gt 100000 ] || fail "too few records: $R"
"$I2O" dump "$W/day.ofs.gz" > "$W/dump.txt" || fail "script invalid: $(tail -1 "$W/dump.txt")"
grep -q "records $R " "$W/dump.txt" || fail "record count differs: $(tail -1 "$W/dump.txt")"
"$I2O" diverge --itch "$W/day.bin" --checkpoint-every 50000 --report "$W/div.json" > /dev/null
[ "$(json_num "$W/div.json" script_records)" = "$R" ] || fail "divergence run saw a different script"
[ "$(json_num "$W/div.json" unmapped_engine_orders)" = 0 ] || fail "engine orders could not be mapped"
grep -q '"checkpoints": \[' "$W/div.json" || fail "no book checkpoints"
echo "PASS: $R records; enter_ok $(json_num "$W/div.json" enter_ok), ioc_exact $(json_num "$W/div.json" ioc_exact)"
