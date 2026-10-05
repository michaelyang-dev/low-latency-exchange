#!/usr/bin/env bash
# Determinism purity audit for simulator builds (docs/plan/09 §2).
# Fails if any object/library built for the simulator references wall-clock,
# randomness, threading or yield symbols, or contains inline timer reads or
# spin-wait hints.
#
# usage: tools/ci/check_sim_purity.sh <archive-or-object>...
set -euo pipefail
[[ $# -gt 0 ]] || { echo "usage: $0 <lib.a|obj.o>..." >&2; exit 64; }

c_syms='^_?(clock_gettime|gettimeofday|time|clock|mach_absolute_time|pthread_create|rand|random|arc4random|arc4random_buf|getentropy|getrandom|sched_yield)$'
# Real waiting: the runtime's out-of-line yield (concurrent/wait.cpp) and the standard
# library's yield helpers. Sim-built cores must never block, spin or yield.
cxx_syms='(chrono.*(system_clock|steady_clock|high_resolution_clock).*now|random_device|std::__1::thread|std::thread|lle::conc::detail::yield_thread|this_thread::yield|__libcpp_thread_yield|__gthread_yield)'
status=0

for f in "$@"; do
  undef=$(nm -u "$f" 2>/dev/null | awk '{print $NF}' | sort -u || true)
  bad_c=$(echo "$undef" | grep -E "$c_syms" || true)
  bad_cxx=$(echo "$undef" | c++filt 2>/dev/null | grep -E "$cxx_syms" || true)
  # Inline timer reads and spin-wait hints (conc::cpu_relax: x86 pause, arm64 isb /
  # yield / wfe) leave no symbol: scan the disassembly's mnemonic column.
  bad_insn=$(objdump -d "$f" 2>/dev/null | grep -E -i '\brdtscp?\b|cntvct|[[:space:]](pause|isb|wfe|yield)([[:space:]]|$)' || true)
  if [[ -n "$bad_c$bad_cxx$bad_insn" ]]; then
    echo "PURITY VIOLATION in $f" >&2
    [[ -n "$bad_c" ]] && echo "  C symbols:   $(echo $bad_c)" >&2
    [[ -n "$bad_cxx" ]] && echo "  C++ symbols: $(echo "$bad_cxx" | head -5)" >&2
    [[ -n "$bad_insn" ]] && echo "  instructions: $(echo "$bad_insn" | head -3)" >&2
    status=1
  fi
done
[[ $status -eq 0 ]] && echo "sim purity: OK ($# file(s))"
exit $status
