#!/usr/bin/env bash
# Builds arm B of a compiler-side LOB experiment (T13; docs/plan/04 §7: X01, X02, X03,
# X18, X19, X24): lob_replay from the bench preset with one change, in OUT, plus
# OUT/arm.json (the arm, its flags, the compiler, the training file's SHA-256). Arm A is
# the bench preset as committed (cmake --preset bench; lob_replay in build/bench).
# tools/perf/abba.py then runs the two binaries.
#
#   tools/perf/build_arm.sh ARM OUT [--train ITCH_FILE]
#
# ARM:
#   o2            X01's other arm: -O2 instead of the bench preset's -O3
#   march-v3      X02: -march=x86-64-v3          march-native  X02: -march=native
#   thinlto       X03: ThinLTO (clang)
#   pgo           X18: instrumented build, trained on --train (a day other than the one
#                 measured: 10302019 for 01302019), then built with the profile (clang)
#   bolt          X19: built with relocations, instrumented by llvm-bolt, trained on
#                 --train, then reordered (ext-tsp blocks, cdsort functions, hot/cold
#                 split; Linux)
#   gcc           X24: gcc instead of clang (CC/CXX, default gcc-15/g++-15)
# Environment: CC and CXX for the arms other than gcc (default clang-21/clang++-21),
# LLVM_PROFDATA (default llvm-profdata-21, then llvm-profdata), LLVM_BOLT (default
# llvm-bolt-21, then llvm-bolt).
set -euo pipefail
usage() { sed -n '2,25p' "$0" >&2; exit 2; }
[[ $# -ge 2 ]] || usage
arm=$1
out=$(mkdir -p "$2" && cd "$2" && pwd)
shift 2
train=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --train) train=$2; shift 2 ;;
    *) usage ;;
  esac
done
src=$(cd "$(dirname "$0")/../.." && pwd)
cc=${CC:-clang-21}
cxx=${CXX:-clang++-21}
find_tool() { for t in "$@"; do command -v "$t" > /dev/null 2>&1 && { echo "$t"; return; }; done; echo "none of: $*" >&2; exit 1; }
need_train() {
  [[ -n $train && -f $train ]] || { echo "build_arm.sh: $arm needs --train ITCH_FILE (another day than the one measured)" >&2; exit 2; }
}
# A bench-preset build of lob_replay in $1 with extra CMake arguments.
build() {
  local dir=$1
  shift
  CC=$cc CXX=$cxx cmake --preset bench -S "$src" -B "$dir" -G Ninja "$@" > "$dir.cfg.log" 2>&1 ||
    { cat "$dir.cfg.log" >&2; exit 1; }
  cmake --build "$dir" --target lob_replay -j > "$dir.build.log" 2>&1 || { tail -40 "$dir.build.log" >&2; exit 1; }
}
train_run() {  # one training replay of $train with the binary $1
  "$1" --file "$train" --variant opt --mode throughput --runs 1 > "$out/train.log" 2>&1 ||
    { tail -20 "$out/train.log" >&2; exit 1; }
}
bench_flags="-g -fno-omit-frame-pointer -DNDEBUG"
flags=""
bin="$out/build/apps/lob_replay/lob_replay"
case $arm in
  o2)
    flags="-O2 $bench_flags"
    build "$out/build" "-DCMAKE_CXX_FLAGS_RELEASE=$flags" ;;
  march-v3 | march-native)
    flags="-march=${arm#march-}"
    [[ $arm == march-v3 ]] && flags="-march=x86-64-v3"
    build "$out/build" "-DCMAKE_CXX_FLAGS=$flags" ;;
  thinlto)
    flags="-flto=thin"
    build "$out/build" "-DCMAKE_CXX_FLAGS=$flags" "-DCMAKE_EXE_LINKER_FLAGS=$flags" ;;
  pgo)
    need_train
    profdata=${LLVM_PROFDATA:-$(find_tool llvm-profdata-21 llvm-profdata)}
    rm -rf "$out/profraw"
    build "$out/instr" "-DCMAKE_CXX_FLAGS=-fprofile-generate=$out/profraw" \
      "-DCMAKE_EXE_LINKER_FLAGS=-fprofile-generate=$out/profraw"
    train_run "$out/instr/apps/lob_replay/lob_replay"
    "$profdata" merge -o "$out/train.profdata" "$out"/profraw/*.profraw
    flags="-fprofile-use=$out/train.profdata -Wno-profile-instr-unprofiled -Wno-profile-instr-out-of-date"
    build "$out/build" "-DCMAKE_CXX_FLAGS=$flags" ;;
  bolt)
    need_train
    bolt=${LLVM_BOLT:-$(find_tool llvm-bolt-21 llvm-bolt)}
    build "$out/build" "-DCMAKE_EXE_LINKER_FLAGS=-Wl,--emit-relocs"
    base="$out/build/apps/lob_replay/lob_replay"
    "$bolt" "$base" -instrument -instrumentation-file="$out/train.fdata" -o "$base.instr" > "$out/bolt-instr.log" 2>&1
    train_run "$base.instr"
    "$bolt" "$base" -data="$out/train.fdata" -o "$base.bolt" -reorder-blocks=ext-tsp -reorder-functions=cdsort \
      -split-functions -split-all-cold -dyno-stats > "$out/bolt.log" 2>&1
    flags="llvm-bolt -reorder-blocks=ext-tsp -reorder-functions=cdsort -split-functions -split-all-cold"
    bin="$base.bolt" ;;
  gcc)
    cc=${CC:-gcc-15}
    cxx=${CXX:-g++-15}
    [[ $cc == clang* ]] && cc=gcc-15
    [[ $cxx == clang* ]] && cxx=g++-15
    build "$out/build" ;;
  *) usage ;;
esac
train_sha=""
[[ -n $train ]] && train_sha=$( (sha256sum "$train" 2>/dev/null || shasum -a 256 "$train") | cut -d' ' -f1)
cat > "$out/arm.json" << EOF
{
  "arm": "$arm",
  "binary": "$bin",
  "flags": "$flags",
  "compiler": "$("$cxx" --version | head -1)",
  "source": "$(git -C "$src" rev-parse HEAD 2>/dev/null || echo unknown)",
  "dirty": $( [[ -n $(git -C "$src" status --porcelain 2>/dev/null) ]] && echo true || echo false),
  "train_file": "$( [[ -n $train ]] && basename "$train")",
  "train_sha256": "$train_sha"
}
EOF
echo "$bin"
