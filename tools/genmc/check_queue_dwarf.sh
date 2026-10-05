#!/usr/bin/env bash
# T28 production-path check (08-concurrency-runtime §11): lists the lle::conc queue
# types instantiated in a binary from its DWARF type information (which survives LTO
# and inlining, unlike a link map), and fails unless the exchanged production queues
# are the verified ones:
#   required:  MpscScqRing<InboundMsg, 4096, false>, MpscScqRing<SessionEventMsg, 1024, false>,
#              MpscScqRing<AdminMsg, 256, false>, SpscRing<StateHashMsg, 256>,
#              BroadcastRing<2> (L2 journal ring), BroadcastRing<4> (egress ring), SpscByteRing
#   forbidden: VyukovMpscRing (baseline only), MpscScqRing<..., true> (ADR-031, not adopted)
#
# usage: tools/genmc/check_queue_dwarf.sh <binary built with -g>
# Linux: needs llvm-dwarfdump (llvm-dwarfdump-21 is tried too). macOS: dsymutil + dwarfdump.
set -euo pipefail
bin="${1:?usage: $0 <binary>}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

dump() {
  if command -v llvm-dwarfdump >/dev/null 2>&1; then llvm-dwarfdump --debug-info "$1"
  elif command -v llvm-dwarfdump-21 >/dev/null 2>&1; then llvm-dwarfdump-21 --debug-info "$1"
  else dwarfdump --debug-info "$1"; fi
}
if [[ "$(uname -s)" == Darwin ]]; then
  dsymutil "$bin" -o "$tmp/bin.dSYM" >/dev/null 2>&1
  dump "$tmp/bin.dSYM" >"$tmp/info.txt"
else
  dump "$bin" >"$tmp/info.txt"
fi

# Type names of class/struct DIEs in lle::conc (DW_AT_name follows DW_TAG_*_type).
grep -E 'DW_AT_name' "$tmp/info.txt" | sed -E 's/.*DW_AT_name[^"]*"([^"]*)".*/\1/' |
  grep -E '^(MpscScqRing|SpscRing|SpscByteRing|BroadcastRing|VyukovMpscRing|ScqIndexRing)(<|$)' |
  perl -pe 's/(\d+)(?:UL|ul|U|u|L|l)\b/$1/g' | sort -u >"$tmp/types.txt"

echo "lle::conc queue types instantiated in $bin:"
sed 's/^/  /' "$tmp/types.txt"

status=0
need() {
  if ! grep -qE "$1" "$tmp/types.txt"; then
    echo "MISSING: $2" >&2
    status=1
  fi
}
need '^MpscScqRing<lle::seq::BasicInboundMsg<168>, 4096, false>$' "OUCH queue MpscScqRing<InboundMsg, 4096> (general SCQ)"
need '^MpscScqRing<lle::seq::SessionEventMsg, 1024, false>$' "session-event queue MpscScqRing<SessionEventMsg, 1024>"
need '^MpscScqRing<lle::seq::(Basic)?AdminMsg(<[0-9]+>)?, 256, false>$' "admin queue MpscScqRing<AdminMsg, 256>"
need '^SpscRing<lle::exch::StateHashMsg, 256>$' "state-hash SpscRing<StateHashMsg, 256>"
need '^BroadcastRing<2>$' "L2 journal ring BroadcastRing<2>"
need '^BroadcastRing<4>$' "egress ring BroadcastRing<4>"
need '^SpscByteRing$' "SpscByteRing (nlog rings, split-mode tee)"
if grep -qE '^VyukovMpscRing' "$tmp/types.txt"; then
  echo "FORBIDDEN: VyukovMpscRing is a baseline, never on the production path" >&2
  status=1
fi
if grep -qE '^MpscScqRing<.*, true>$' "$tmp/types.txt"; then
  echo "FORBIDDEN: the single-consumer SCQ specialization is not adopted (ADR-031)" >&2
  status=1
fi
[[ $status -eq 0 ]] && echo "queue instantiation check: OK"
exit $status
