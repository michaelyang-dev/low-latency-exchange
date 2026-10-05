# Shared helpers of the client integration tests (sourced). Arguments of every
# test: BIN_DIR (the build's apps directory layout is resolved by CMake into the
# variables below) and WORK (a fresh scratch directory).
set -euo pipefail
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT
# Stops every background process started so far (between phases of one test).
kill_all() {
  for p in "${PIDS[@]:-}"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  PIDS=()
  return 0
}
fail() { echo "FAIL: $*" >&2; exit 1; }
# json_num FILE KEY -> the number after "KEY":
json_num() { sed -n "s/^ *\"$2\": \\([0-9-]*\\).*/\\1/p" "$1" | head -1; }
json_str() { sed -n "s/^ *\"$2\": \"\\(.*\\)\".*/\\1/p" "$1" | head -1; }
# wait_for FILE SECONDS: until FILE exists and is non-empty.
wait_for() {
  local f=$1 t=$2 i=0
  while [ ! -s "$f" ]; do
    sleep 0.2; i=$((i + 1))
    if [ $i -gt $((t * 5)) ]; then fail "timed out waiting for $f"; fi
  done
  return 0
}
# wait_listening ERRFILE SECONDS: until `loadgen serve` reports it is listening.
wait_listening() {
  local f=$1 t=$2 i=0
  until grep -q listening "$f" 2>/dev/null; do
    sleep 0.2; i=$((i + 1))
    if [ $i -gt $((t * 5)) ]; then fail "server did not start: $(cat "$f" 2>/dev/null)"; fi
  done
  return 0
}
