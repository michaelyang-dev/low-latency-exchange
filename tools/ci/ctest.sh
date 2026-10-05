#!/usr/bin/env bash
# Runs ctest with the given arguments. When tests fail, they are also reported as GitHub
# Actions error annotations (every name, and the end of each failed test's output), so
# they can be read without the job log (ctest_annotate.py).
set -u
ctest "$@"
rc=$?
if [ "$rc" -ne 0 ]; then
  dir=.
  prev=""
  for a in "$@"; do
    [ "$prev" = "--test-dir" ] && dir="$a"
    prev="$a"
  done
  python3 "$(dirname "$0")/ctest_annotate.py" "$dir" || true
fi
exit "$rc"
