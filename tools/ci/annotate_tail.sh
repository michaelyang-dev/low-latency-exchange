#!/usr/bin/env bash
# usage: tools/ci/annotate_tail.sh TITLE FILE [LINES] [AFTER]
# Emits a failed step's log as one GitHub error annotation: the lines around the first
# errors when it has any ("error:", "Error:", "FAIL"; AFTER lines after each, default 3),
# else its last LINES (default 40). Annotations are readable through the API where job
# logs are not.
set -u
title=$1
f=$2
n=${3:-40}
after=${4:-3}
if [ ! -f "$f" ]; then
  echo "::error title=$title::$f missing"
  exit 0
fi
if grep -qE "error:|Error:|FAIL" "$f"; then
  body=$(grep -m "$n" -E -B2 -A"$after" "error:|Error:|FAIL" "$f")
else
  body=$(tail -n "$n" "$f")
fi
body=$(printf '%s' "$body" | head -c 30000)
body=${body//'%'/'%25'}
body=${body//$'\r'/'%0D'}
body=${body//$'\n'/'%0A'}
echo "::error title=$title::$body"
