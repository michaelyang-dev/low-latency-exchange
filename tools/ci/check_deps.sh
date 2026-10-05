#!/usr/bin/env bash
# T01 dependency audit: only the infrastructure libraries approved by ADR-002
# may appear as build dependencies. Adding one requires an ADR.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
allowed_fetch='^(googletest|benchmark|hdrhistogram)$'
# Python3 is only ever found as the Interpreter component, to run tool self-tests and
# reference decoders from ctest; it is never linked.
allowed_find='^(ZLIB|Threads|PkgConfig|GTest|benchmark|Python3)$'
status=0

while IFS= read -r name; do
  [[ "$name" =~ $allowed_fetch ]] || { echo "unapproved FetchContent dependency: $name" >&2; status=1; }
done < <(grep -rhoE 'FetchContent_Declare\(\s*[A-Za-z0-9_]+' --include=CMakeLists.txt --include='*.cmake' "$root/cmake" "$root/src" "$root/apps" "$root/tests" "$root/bench" "$root/fuzz" "$root/sim" 2>/dev/null | sed -E 's/.*\(\s*//' | sort -u)

while IFS= read -r name; do
  [[ "$name" =~ $allowed_find ]] || { echo "unapproved find_package: $name" >&2; status=1; }
done < <(grep -rhoE 'find_package\(\s*[A-Za-z0-9_]+' --include=CMakeLists.txt --include='*.cmake' "$root/src" "$root/apps" "$root/tests" "$root/bench" "$root/fuzz" "$root/sim" 2>/dev/null | grep -v 'find_package(Java' | sed -E 's/.*\(\s*//' | sort -u)
# Java: test-only, for the nassau interop test (plan 02 §3: "Test-only: nassau (JDK),
# tshark"). It is never linked, and allowed nowhere else.
if grep -rlE 'find_package\(\s*Java' --include=CMakeLists.txt --include='*.cmake' "$root/cmake" "$root/src" "$root/apps" "$root/tests" "$root/bench" "$root/fuzz" "$root/sim" 2>/dev/null | grep -v '/tests/integration/nassau/CMakeLists.txt$'; then
  echo "find_package(Java) is allowed only in tests/integration/nassau (test-only interop)" >&2; status=1
fi

# Linux system libraries are allowed only for the I/O backends: liburing, libbpf and
# libxdp under src/net/, and liburing for the journal's io_uring device (06 §3).
if grep -rlE 'pkg_check_modules|find_library' --include=CMakeLists.txt "$root/src" 2>/dev/null | grep -v '/src/net/' | grep -v '/src/journal/' ; then
  echo "system library lookups are only allowed under src/net/ (and liburing in src/journal/)" >&2; status=1
fi
if grep -hoE 'pkg_check_modules\([A-Z_]+ [A-Z_ ]*[a-z][a-z0-9_]*' "$root/src/journal/CMakeLists.txt" 2>/dev/null | grep -vqE 'liburing$'; then
  echo "src/journal may only look up liburing" >&2; status=1
fi
# Python3 must only be the interpreter.
if grep -rhE 'find_package\(\s*Python3' --include=CMakeLists.txt "$root/src" "$root/apps" "$root/tests" "$root/fuzz" "$root/sim" 2>/dev/null | grep -vq 'COMPONENTS Interpreter'; then
  echo "find_package(Python3) is allowed only with COMPONENTS Interpreter" >&2; status=1
fi
[[ $status -eq 0 ]] && echo "dependency audit: OK"
exit $status
