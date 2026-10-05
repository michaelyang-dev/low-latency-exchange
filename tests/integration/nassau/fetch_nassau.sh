#!/usr/bin/env bash
# Downloads the pinned nassau jars (test-only interop, plan 03 §5) from Maven Central
# into DIR and verifies their SHA-256. Then configure with -DLLE_NASSAU_DIR=DIR.
#
#   tests/integration/nassau/fetch_nassau.sh DIR
set -euo pipefail
dir=${1:?usage: fetch_nassau.sh DIR}
mkdir -p "$dir"
base=https://repo1.maven.org/maven2
while read -r path sha; do
  f="$dir/$(basename "$path")"
  [ -f "$f" ] || curl -sSfL -o "$f" "$base/$path"
  echo "$sha  $f" | shasum -a 256 -c - >/dev/null || { echo "checksum mismatch: $f" >&2; exit 1; }
done <<'PINS'
com/paritytrading/nassau/nassau-core/1.0.0/nassau-core-1.0.0.jar 56055ec00a894891f92defaf27837e12d5bba32469b4e062ae06bbc34e592dfa
com/paritytrading/foundation/foundation/1.0.0/foundation-1.0.0.jar 7d955f331a27c7f03e1c1bb1ce7019c67de16130f0829b118aa6b4d02956aa82
org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar d919d904486c037f8d193412da0c92e22a9fa24230b9d67a57855c5c31c7e94e
PINS
echo "nassau jars verified in $dir"
