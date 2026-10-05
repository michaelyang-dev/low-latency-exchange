#!/usr/bin/env bash
# Prints the CMake cache flags that build against an MSan libc++ (see build_msan_libcxx.sh).
# usage: cmake --preset msan $(tools/ci/msan_flags.sh <prefix>)
set -euo pipefail
p="${1:?msan libc++ prefix}"
triple_inc=$(ls -d "$p"/include/*-linux-gnu/c++/v1 2>/dev/null | head -1 || true)
# Instrument everything, third-party test code (GoogleTest) included.
cxx="-fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -nostdinc++ -isystem $p/include/c++/v1${triple_inc:+ -isystem $triple_inc}"
ld="-fsanitize=memory -stdlib=libc++ -L$p/lib -Wl,-rpath,$p/lib -lc++abi"
lib=$(ls -d "$p"/lib/*-linux-gnu 2>/dev/null | head -1 || true)
[[ -n "$lib" ]] && ld="$ld -L$lib -Wl,-rpath,$lib"
printf '%s\n' "-DCMAKE_CXX_FLAGS=$cxx" "-DCMAKE_EXE_LINKER_FLAGS=$ld" "-DZLIB_ROOT=$p" "-DZLIB_USE_STATIC_LIBS=ON"
