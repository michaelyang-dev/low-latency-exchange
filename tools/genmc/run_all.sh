#!/usr/bin/env bash
# Runs every GenMC harness in verify/genmc/ under RC11 and IMM (08-concurrency-runtime
# §7) and prints one row per (case, model): outcome, explored / blocked executions and
# wall time. Exits non-zero if any outcome differs from its expectation (positive
# harnesses must report no errors; the Vyukov stalled-producer harnesses must fail).
#
#   tools/genmc/run_all.sh                     # full suite, rc11 + imm
#   tools/genmc/run_all.sh --quick             # skip the long pre-registered SCQ 2x2 bound
#   tools/genmc/run_all.sh --only scq          # cases whose name matches a regex
#   tools/genmc/run_all.sh --models rc11       # one model
#   tools/genmc/run_all.sh --src /tmp/mut/src  # alternate source tree (mutate_orders.py)
#
# Environment: GENMC (default: genmc on PATH), GENMC_TIMEOUT seconds per run (default
# 86400, the plan's 24 h bound), GENMC_NTHREADS (default 1; parallel exploration for the
# large SCQ cases), OUT (log directory, default build/genmc).
# Every invocation has the documented shape: genmc -<model> [opts] -- -std=c++20 -I src <file>
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GENMC="${GENMC:-genmc}"
TIMEOUT="${GENMC_TIMEOUT:-86400}"
NTHREADS="${GENMC_NTHREADS:-1}"
OUT="${OUT:-$ROOT/build/genmc}"
SRC="$ROOT/src"
MODELS="rc11 imm"
ONLY=""
QUICK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) QUICK=1 ;;
    --only) ONLY="$2"; shift ;;
    --models) MODELS="$2"; shift ;;
    --src) SRC="$2"; shift ;;
    --out) OUT="$2"; shift ;;
    -h | --help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
mkdir -p "$OUT"
V="$ROOT/verify/genmc"

# name | harness | compiler flags | genmc flags | expectation (pass|fail|liveness|lin) | long?
CASES=(
  "spsc_ring_cap1|spsc_ring.cpp|-DCAP=1 -DK=4||pass|"
  "spsc_ring_cap2|spsc_ring.cpp|-DCAP=2 -DK=4||pass|"
  "spsc_ring_cap4|spsc_ring.cpp|-DCAP=4 -DK=4||pass|"
  "spsc_ring_drain_cap2|spsc_ring.cpp|-DCAP=2 -DK=4 -DUSE_DRAIN||pass|"
  "spsc_ring_claim_commit_cap1|spsc_ring_claim_commit.cpp|-DCAP=1 -DK=3||pass|"
  "spsc_ring_claim_commit_cap2|spsc_ring_claim_commit.cpp|-DCAP=2 -DK=3||pass|"
  "spsc_byte_ring_wrap|spsc_byte_ring_wrap.cpp|||pass|"
  "spsc_byte_ring_wrap_drain|spsc_byte_ring_wrap.cpp|-DUSE_DRAIN||pass|"
  "broadcast_ring_2c|broadcast_ring_2c.cpp|-DRECORDS=3||pass|"
  "broadcast_ring_2c_4rec|broadcast_ring_2c.cpp|-DRECORDS=4||pass|"
  "broadcast_ring_2c_drain|broadcast_ring_2c.cpp|-DRECORDS=4 -DUSE_DRAIN||pass|"
  "mpsc_scq_2p1x1c|mpsc_scq_2p1c.cpp|-DPRODUCERS=2 -DPUSHES=1||pass|"
  "mpsc_scq_3p1c_1pop|mpsc_scq_3p1c.cpp|-DPOPS=1|NTHREADS|pass|long"
  "mpsc_scq_2p2x1c_1pop|mpsc_scq_2p1c.cpp|-DPOPS=1|NTHREADS|pass|long"
  "mpsc_scq_2p2x1c_2pops|mpsc_scq_2p1c.cpp|-DPOPS=2|NTHREADS|pass|long"
  "mpsc_scq_3p1c|mpsc_scq_3p1c.cpp||NTHREADS|pass|long"
  "mpsc_scq_sym_3p1x_3pops|mpsc_scq_sym.cpp|-DPRODUCERS=3 -DPUSHES=1 -DPOPS=3|NTHREADS|pass|long"
  "mpsc_scq_sym_2p2x_4pops|mpsc_scq_sym.cpp|-DPRODUCERS=2 -DPUSHES=2 -DPOPS=4|NTHREADS|pass|long"
  "mpsc_scq_2p1c|mpsc_scq_2p1c.cpp||NTHREADS|pass|long"
  "mpsc_scq_lin_2x1|mpsc_scq_lin.cpp|-DENQ=2|--disable-mm-detector --disable-warn-on-unfreed-memory|lin|"
  "mpsc_stalled_producer_scq|mpsc_stalled_producer.cpp|||pass|"
  "mpsc_stalled_producer_scq_ordered|mpsc_stalled_producer.cpp|-DLLE_ORDERED||pass|"
  "mpsc_scq_sc_2p1x1c|mpsc_scq_2p1c.cpp|-DLLE_SCQ_SINGLE_CONSUMER -DPRODUCERS=2 -DPUSHES=1||pass|"
  "mpsc_scq_sc_1p2x1c|mpsc_scq_2p1c.cpp|-DLLE_SCQ_SINGLE_CONSUMER -DPRODUCERS=1 -DPUSHES=2||pass|"
  "mpsc_scq_sc_lin_2x1|mpsc_scq_lin.cpp|-DLLE_SCQ_SINGLE_CONSUMER -DENQ=2|--disable-mm-detector --disable-warn-on-unfreed-memory|lin|"
  "mpsc_stalled_producer_scq_sc|mpsc_stalled_producer.cpp|-DLLE_SCQ_SINGLE_CONSUMER||pass|"
  "mpsc_scq_sc_3p1c_1pop|mpsc_scq_3p1c.cpp|-DLLE_SCQ_SINGLE_CONSUMER -DPOPS=1|NTHREADS|pass|long"
  "mpsc_stalled_producer_vyukov|mpsc_stalled_producer.cpp|-DLLE_STALLED_VYUKOV||fail|"
  "mpsc_stalled_producer_vyukov_liveness|mpsc_stalled_producer.cpp|-DLLE_STALLED_VYUKOV -DLLE_SPIN_CONSUMER|-check-liveness|liveness|"
)

run_genmc() {  # $1 = log file, rest = genmc args; enforces the timeout
  local log="$1"
  shift
  local start end
  start=$(perl -MTime::HiRes=time -e 'printf "%.2f", time')
  perl -e 'alarm shift; exec @ARGV' "$TIMEOUT" "$GENMC" "$@" >"$log" 2>&1
  local rc=$?
  end=$(perl -MTime::HiRes=time -e 'printf "%.2f", time')
  echo "# exit=$rc elapsed=$(echo "$end - $start" | bc)s" >>"$log"
  return $rc
}

field() { sed -n "s/.*$1 \([0-9][0-9.]*\).*/\1/p" "$2" | tail -1; }

summary="$OUT/summary.tsv"
printf "case\tmodel\texpected\toutcome\tverdict\texplored\tblocked\twall_s\n" >"$summary"
printf "%-40s %-5s %-9s %-10s %-7s %10s %10s %9s\n" case model expected outcome verdict explored blocked wall_s
failures=0
for entry in "${CASES[@]}"; do
  IFS='|' read -r name file cflags gflags expect long <<<"$entry"
  if [ -n "$ONLY" ] && ! [[ "$name" =~ $ONLY ]]; then continue; fi
  if [ "$QUICK" = 1 ] && [ "$long" = long ]; then continue; fi
  gflags="${gflags//NTHREADS/--nthreads=$NTHREADS}"
  for model in $MODELS; do
    log="$OUT/$name.$model.log"
    if [ "$expect" = lin ]; then
      # Relinche: collect the spec from the sequential reference, then check SCQ.
      spec="$OUT/$name.spec.in"
      rm -f "$spec"
      run_genmc "$OUT/$name.$model.spec.log" "-$model" --disable-estimation $gflags --collect-lin-spec="$spec" \
        -- -std=c++20 -I "$SRC" $cflags -DLLE_LIN_REFERENCE "$V/$file"
      run_genmc "$log" "-$model" --disable-estimation $gflags --check-lin-spec="$spec" \
        -- -std=c++20 -I "$SRC" $cflags "$V/$file"
    else
      run_genmc "$log" "-$model" --disable-estimation $gflags -- -std=c++20 -I "$SRC" $cflags "$V/$file"
    fi
    rc=$?
    if grep -q "No errors were detected" "$log"; then
      outcome=pass
    elif grep -q "Non-terminating spinloop" "$log"; then
      outcome=liveness
    elif grep -qE "Verification unsuccesful|Error detected|Safety violation" "$log"; then
      outcome=fail
    elif [ "$rc" -ge 128 ]; then
      outcome=timeout
    else
      outcome=error
    fi
    want="$expect"
    [ "$want" = lin ] && want=pass
    verdict=OK
    if [ "$outcome" != "$want" ]; then
      verdict=UNEXPECTED
      failures=$((failures + 1))
    fi
    explored=$(field "complete executions explored:" "$log")
    blocked=$(field "blocked executions seen:" "$log")
    wall=$(field "Total wall-clock time:" "$log")
    printf "%-40s %-5s %-9s %-10s %-7s %10s %10s %9s\n" "$name" "$model" "$expect" "$outcome" "$verdict" \
      "${explored:-0}" "${blocked:-0}" "${wall:--}"
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$name" "$model" "$expect" "$outcome" "$verdict" \
      "${explored:-0}" "${blocked:-0}" "${wall:--}" >>"$summary"
  done
done
echo "logs: $OUT  summary: $summary"
[ "$failures" -eq 0 ] || echo "$failures unexpected outcome(s)" >&2
exit $((failures > 0))
