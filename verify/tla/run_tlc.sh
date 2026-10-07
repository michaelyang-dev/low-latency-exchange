#!/usr/bin/env bash
# Runs the HotStandby safety model (must pass), every safety mutant (must
# fail), the liveness models (must pass) and the liveness mutants (must fail).
# usage: verify/tla/run_tlc.sh /path/to/tla2tools.jar [workers] [safety-config]
# The safety config defaults to the full model (HotStandby.cfg); push/PR CI
# passes HotStandbyCI.cfg (reduced bounds) and the nightly job the full model.
set -uo pipefail
jar="${1:?path to tla2tools.jar}"
workers="${2:-auto}"
safety_cfg="${3:-HotStandby.cfg}"
cd "$(dirname "$0")"
meta=$(mktemp -d)
trap 'rm -rf "$meta"' EXIT
# TLC 1.8 builds write trace-explorer specs next to the model by default; 2.19
# (release v1.7.4) has no such option and writes none.
spec_te=()
if java -cp "$jar" tlc2.TLC -help 2>&1 | grep -q noGenerateSpecTE; then spec_te=(-noGenerateSpecTE); fi
java -cp "$jar" tlc2.TLC -help 2>&1 | grep -m1 "TLC2 Version" || true
# TLC_JAVA_OPTS: extra JVM options (the nightly full model sizes the heap for its runner).
# No checkpoints: no run is resumed, and every 30 minutes one copies the state queue and
# the fingerprint set to disk beside the live ones (the nightly full model's TLC died
# with an unexpected exception at its first, 32 minutes in).
# shellcheck disable=SC2086
tlc() { java -XX:+UseParallelGC ${TLC_JAVA_OPTS:-} -cp "$jar" tlc2.TLC -workers "$workers" -deadlock -checkpoint 0 ${spec_te[@]+"${spec_te[@]}"} -metadir "$meta/$1" -config "$2" "${3:-HotStandby.tla}"; }

status=0
echo "== safety model $safety_cfg (expect: no error)"
if tlc safety "$safety_cfg" > "$meta/safety.log" 2>&1 && ! grep -q "Error:" "$meta/safety.log"; then
  grep -E "distinct states found|depth of the complete state graph" "$meta/safety.log" | tail -2
else
  echo "FAIL: safety model reported an error"; tail -40 "$meta/safety.log"; status=1
fi

for cfg in mutants/*.cfg; do
  name=$(basename "$cfg" .cfg)
  tlc "m-$name" "$cfg" > "$meta/$name.log" 2>&1
  if grep -q "is violated" "$meta/$name.log"; then
    echo "== mutant $name: counterexample found ($(grep -m1 'is violated' "$meta/$name.log"))"
  else
    echo "FAIL: mutant $name produced no counterexample"; status=1
  fi
done
for cfg in HotStandbyLive*.cfg; do
  name=$(basename "$cfg" .cfg)
  if tlc "$name" "$cfg" HotStandbyLive.tla > "$meta/$name.log" 2>&1 && grep -q "No error has been found" "$meta/$name.log"; then
    echo "== liveness $name: no error ($(grep -E 'distinct states found' "$meta/$name.log" | tail -1))"
  else
    echo "FAIL: liveness model $name reported an error"; tail -40 "$meta/$name.log"; status=1
  fi
done

for cfg in mutants/live/*.cfg; do
  name=$(basename "$cfg" .cfg)
  tlc "lm-$name" "$cfg" HotStandbyLive.tla > "$meta/lm-$name.log" 2>&1
  if grep -qE "is violated|were violated" "$meta/lm-$name.log"; then
    echo "== liveness mutant $name: counterexample found ($(grep -m1 -E 'is violated|were violated' "$meta/lm-$name.log"))"
  else
    echo "FAIL: liveness mutant $name produced no counterexample"; status=1
  fi
done
exit $status
