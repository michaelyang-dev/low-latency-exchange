#!/usr/bin/env bash
# Download NASDAQ TotalView-ITCH 5.0 BinaryFILE days from emi.nasdaq.com with
# parallel HTTP range requests, verify SHA-256, and record them in
# data/itch/MANIFEST.txt (docs/plan/02 §6). The data is never committed.
#
# usage: tools/itch_fetch.sh <file-name> [expected-sha256]
#   e.g. tools/itch_fetch.sh 01302019.NASDAQ_ITCH50.gz 8c97b5b13bc451c012c2466fb7e258da134dab29aa47b67fe7b0088c78e870be
set -euo pipefail

name="${1:?file name required (e.g. 01302019.NASDAQ_ITCH50.gz)}"
expected="${2:-}"
base="https://emi.nasdaq.com/ITCH/Nasdaq%20ITCH"
dest_dir="$(cd "$(dirname "$0")/.." && pwd)/data/itch"
parts=16
mkdir -p "$dest_dir"
dest="$dest_dir/$name"

if [[ -f "$dest" && -n "$expected" ]]; then
  have=$(shasum -a 256 "$dest" | cut -d' ' -f1)
  if [[ "$have" == "$expected" ]]; then echo "already present and verified: $dest"; exit 0; fi
fi

size=$(curl -sSIL "$base/$name" | awk 'tolower($1)=="content-length:"{print $2}' | tr -d '\r' | tail -1)
[[ -n "$size" ]] || { echo "could not determine size of $name" >&2; exit 1; }
echo "fetching $name ($size bytes) in $parts parts"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
chunk=$(( (size + parts - 1) / parts ))
pids=()
for ((i = 0; i < parts; i++)); do
  start=$(( i * chunk )); end=$(( start + chunk - 1 ))
  (( end >= size )) && end=$(( size - 1 ))
  (( start > end )) && break
  curl -sSf --retry 5 -r "$start-$end" -o "$tmp/part.$(printf %03d $i)" "$base/$name" &
  pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done
cat "$tmp"/part.* > "$dest.partial"
mv "$dest.partial" "$dest"

have=$(shasum -a 256 "$dest" | cut -d' ' -f1)
if [[ -n "$expected" && "$have" != "$expected" ]]; then
  echo "SHA-256 mismatch: expected $expected got $have" >&2; exit 2
fi
gzip -t "$dest" 2>/dev/null || { echo "gzip integrity check failed" >&2; exit 3; }
grep -q " $name\$" "$dest_dir/MANIFEST.txt" 2>/dev/null || echo "$have  $name" >> "$dest_dir/MANIFEST.txt"
echo "ok: $dest  sha256=$have"
