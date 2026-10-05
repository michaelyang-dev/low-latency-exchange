#!/usr/bin/env python3
"""Sums queue stress items per (platform, sanitizer, queue) at the current source tree
(T28: >= 1e10 items per production queue under TSan on linux-x86_64 and darwin-arm64).

    sum_items.py [--ledger verify/stress/runs.jsonl] [--all-trees]

Exit status 0 when every production queue has reached the threshold on both required
platforms under TSan, 2 otherwise.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/evidence"))
from build_evidence import tree_hash  # noqa: E402

TREE_DIRS = ["src/concurrent", "tests/unit/concurrent"]
PRODUCTION_QUEUES = ["SpscRing", "SpscByteRing", "BroadcastRing", "MpscScqRing"]
REQUIRED_PLATFORMS = ["linux-x86_64", "darwin-arm64"]
THRESHOLD = 10**10


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ledger", default=str(ROOT / "verify/stress/runs.jsonl"))
    ap.add_argument("--all-trees", action="store_true")
    a = ap.parse_args()
    tree = tree_hash(TREE_DIRS)
    sums: dict[tuple[str, str, str], int] = {}
    fails = 0
    p = Path(a.ledger)
    for line in (p.read_text().splitlines() if p.exists() else []):
        if not line.strip():
            continue
        r = json.loads(line)
        if not a.all_trees and r.get("tree") != tree:
            continue
        if r.get("result") != "PASS":
            fails += 1
            continue
        k = (r["platform"], r["sanitizer"], r["queue"])
        sums[k] = sums.get(k, 0) + int(r["items"])
    print(f"tree {tree}{' (all trees)' if a.all_trees else ''}; failed tests recorded: {fails}")
    for k in sorted(sums):
        print(f"  {k[0]:<16} {k[1]:<5} {k[2]:<30} {sums[k]:>18,}")
    met = fails == 0 and all(sums.get((pl, "tsan", q), 0) >= THRESHOLD for pl in REQUIRED_PLATFORMS for q in PRODUCTION_QUEUES)
    for pl in REQUIRED_PLATFORMS:
        for q in PRODUCTION_QUEUES:
            n = sums.get((pl, "tsan", q), 0)
            print(f"  T28 {pl} tsan {q}: {n:,} / {THRESHOLD:,} ({100 * n / THRESHOLD:.2f}%)")
    print("T28 stress threshold:", "MET" if met else "not met")
    return 0 if met else 2


if __name__ == "__main__":
    sys.exit(main())
