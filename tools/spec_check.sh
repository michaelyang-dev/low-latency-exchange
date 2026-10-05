#!/usr/bin/env bash
# Re-downloads every pinned specification and compares SHA-256 with docs/protocols/SPEC_VERSIONS.md.
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
status=0
grep -E '^\| [^|]+ \| [^|]+ \| https?://' "$root/docs/protocols/SPEC_VERSIONS.md" | while IFS='|' read -r _ name rev url sha _; do
  url=$(echo "$url" | xargs); want=$(echo "$sha" | tr -d '` ' ); name=$(echo "$name" | xargs)
  [[ "$want" =~ ^[0-9a-f]{64}$ ]] || { echo "skip (no pinned hash): $name"; continue; }
  if curl -sSLf -o "$tmp/f" "$url"; then
    have=$(shasum -a 256 "$tmp/f" | cut -d' ' -f1)
    [[ "$have" == "$want" ]] && echo "ok:      $name" || { echo "CHANGED: $name ($have)"; status=1; }
  else
    echo "UNREACHABLE: $name"; status=1
  fi
done
exit $status
