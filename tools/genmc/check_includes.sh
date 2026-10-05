#!/usr/bin/env bash
# Enforces the include allowlist for src/concurrent/*.h (08-concurrency-runtime §7):
# GenMC compiles these production headers directly, and its runtime provides only a
# minimal C++ library, so they may include nothing but <atomic>, <cstddef>, <cstdint>,
# <type_traits>, common/cache.h and other src/concurrent headers.
set -euo pipefail
dir="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/src/concurrent}"
status=0
for h in "$dir"/*.h; do
  while IFS= read -r line; do
    inc="$(sed -E 's/^[[:space:]]*#[[:space:]]*include[[:space:]]*([<"][^>"]*[>"]).*/\1/' <<<"$line")"
    case "$inc" in
      "<atomic>" | "<cstddef>" | "<cstdint>" | "<type_traits>" | '"common/cache.h"' | '"concurrent/'*'.h"') ;;
      *)
        echo "$(basename "$h"): include not allowed in GenMC-checked header: $inc" >&2
        status=1
        ;;
    esac
  done < <(grep -E '^[[:space:]]*#[[:space:]]*include' "$h")
done
# common/cache.h must itself stay allowlist-clean.
cache="$(dirname "$dir")/common/cache.h"
if [ -f "$cache" ] && grep -E '^[[:space:]]*#[[:space:]]*include' "$cache" | grep -vqE '<cstddef>'; then
  echo "common/cache.h includes more than <cstddef>; GenMC harnesses may break" >&2
  status=1
fi
# No standalone fences (TSan does not model them, 08 §3).
if grep -nE 'atomic_thread_fence|atomic_signal_fence' "$dir"/*.h >&2; then
  echo "standalone fences are not allowed in src/concurrent" >&2
  status=1
fi
[ "$status" -eq 0 ] && echo "include allowlist OK ($(ls "$dir"/*.h | wc -l | tr -d ' ') headers)"
exit "$status"
