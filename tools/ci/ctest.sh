#!/usr/bin/env bash
# Runs ctest with the given arguments. When tests fail, each one is also reported as a
# GitHub Actions error annotation, so the names can be read without the job log.
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
  failed="$dir/Testing/Temporary/LastTestsFailed.log"
  if [ -f "$failed" ]; then
    while IFS= read -r line; do echo "::error::ctest failed: ${line#*:}"; done < "$failed"
  fi
fi
exit "$rc"
