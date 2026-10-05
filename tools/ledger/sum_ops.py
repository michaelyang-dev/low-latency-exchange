#!/usr/bin/env python3
"""Sum differential-fuzzing operations in fuzz/ledger/runs.jsonl (docs/plan/04 §8, 05 §9).

Reports totals per (harness, build, variant) and per source tree hash, so the
T14 acceptance ("≥2B release ops per book on the release tree") can be checked:
  sum_ops.py [--ledger fuzz/ledger/runs.jsonl] [--tree <hash>] [--harness lobdiff|enginediff]

Real-file replay harnesses (itch_replay_diff) are listed separately and never
count toward the random-fuzzing total (04 §8 "Honest counting").
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

REPLAY_HARNESSES = {"itch_replay_diff"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", default=str(Path(__file__).resolve().parents[2] / "fuzz/ledger/runs.jsonl"))
    ap.add_argument("--tree", help="only count records with this source tree hash")
    ap.add_argument("--harness", help="only count this harness")
    a = ap.parse_args()
    by_key: dict[tuple, list[int]] = collections.defaultdict(lambda: [0, 0, 0])
    by_tree: dict[str, int] = collections.Counter()
    for line in Path(a.ledger).read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if a.tree and r.get("tree") != a.tree:
            continue
        if a.harness and r.get("harness") != a.harness:
            continue
        k = (r.get("harness", "?"), r.get("build", "?"), r.get("variant", "?"))
        by_key[k][0] += int(r.get("ops", 0))
        by_key[k][1] += int(r.get("divergences", 0))
        by_key[k][2] += 1
        by_tree[f'{r.get("harness","?")}@{r.get("tree","?")}'] += int(r.get("ops", 0))
    print(f"{'harness':<12} {'build':<12} {'variant':<16} {'ops':>16} {'divergences':>12} {'records':>8}")
    total = replay = 0
    for (h, b, v), (ops, div, n) in sorted(by_key.items()):
        print(f"{h:<12} {b:<12} {v:<16} {ops:>16,} {div:>12} {n:>8}")
        if h in REPLAY_HARNESSES:
            replay += ops
        else:
            total += ops
    print(f"{'fuzzing total':<42} {total:>16,}")
    print(f"{'real-file replay (not counted)':<42} {replay:>16,}")
    print("\nper source tree:")
    for k, ops in sorted(by_tree.items()):
        print(f"  {k}: {ops:,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
