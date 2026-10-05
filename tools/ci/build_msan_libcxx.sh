#!/usr/bin/env bash
# Builds an MSan-instrumented libc++/libc++abi and zlib. MemorySanitizer reports
# false positives for memory written by uninstrumented code (the standard
# library; zlib in the ITCH gzip reader), so everything linked must be instrumented.
# usage: tools/ci/build_msan_libcxx.sh <install-prefix> [llvm-tag] [clang-suffix]
#   e.g. tools/ci/build_msan_libcxx.sh $HOME/msan-libcxx llvmorg-21.1.8 -21
# Then build with tools/ci/msan_flags.sh <install-prefix> (prints CMake flags).
set -euo pipefail
prefix="${1:?install prefix}"
tag="${2:-llvmorg-21.1.8}"
sfx="${3:--21}"
work="$(mktemp -d "${TMPDIR:-/tmp}/msan-libcxx.XXXXXX")"
on_exit() {
  rc=$?
  if [[ $rc -ne 0 ]]; then
    for f in "$work/configure.log" "$work/build.log"; do [[ -f "$f" ]] && { echo "== $f"; tail -30 "$f"; }; done
  fi
  rm -rf "$work"
}
trap on_exit EXIT
git clone --quiet --depth 1 --branch "$tag" --filter=blob:none --sparse https://github.com/llvm/llvm-project.git "$work/src"
git -C "$work/src" sparse-checkout set runtimes libcxx libcxxabi libunwind libc cmake llvm/cmake llvm/utils/llvm-lit third-party
cmake -G Ninja -S "$work/src/runtimes" -B "$work/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="clang$sfx" -DCMAKE_CXX_COMPILER="clang++$sfx" \
  -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" \
  -DLLVM_USE_SANITIZER=MemoryWithOrigins \
  -DLIBCXX_INCLUDE_TESTS=OFF -DLIBCXXABI_INCLUDE_TESTS=OFF -DLIBUNWIND_INCLUDE_TESTS=OFF \
  -DLIBCXX_INCLUDE_BENCHMARKS=OFF \
  -DCMAKE_INSTALL_PREFIX="$prefix" > "$work/configure.log" 2>&1
ninja -C "$work/build" install-cxx install-cxxabi install-unwind > "$work/build.log" 2>&1
git clone --quiet --depth 1 --branch v1.3.1 https://github.com/madler/zlib.git "$work/zlib"
cmake -G Ninja -S "$work/zlib" -B "$work/zlib-build" -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="clang$sfx" -DCMAKE_C_FLAGS="-fsanitize=memory -fsanitize-memory-track-origins=2" \
  -DCMAKE_INSTALL_PREFIX="$prefix" > "$work/zlib.log" 2>&1
ninja -C "$work/zlib-build" install >> "$work/zlib.log" 2>&1
echo "MSan libc++ and zlib installed in $prefix"
