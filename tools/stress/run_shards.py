#!/usr/bin/env python3
"""Runs the queue stress binary repeatedly and accumulates items moved per queue in a
ledger (T28: >= 1e10 checksummed items per production queue under TSan, on Linux x86-64
and macOS arm64; docs/plan/08 §8, docs/verification/queues-stress.md).

    run_shards.py --bin BUILD/tests/unit/concurrent/concurrent_stress_long_test --sanitizer tsan
                  [--runs N] [--time-budget SECONDS] [--seed-offset-start K]
                  [--ledger verify/stress/runs.jsonl] [--platform NAME] [--filter GTEST_FILTER]

Each run sets LLE_STRESS_SEED_OFFSET (a different pause sequence per run) and reads the
per-test properties `queue` and `items` from --gtest_output=json. Every passed test
appends one record: harness, test, queue, items, seed offset, sanitizer, platform, the
source tree hash of src/concurrent and tests/unit/concurrent (tools/evidence/build_evidence.py
tree_hash), git SHA and dirty flag, date and wall time. A failed test is a finding: it
is recorded with "result": "FAIL" and the script stops with exit status 1.

The script refuses to run when a source in the hashed directories is newer than the
binary, so a stale build cannot certify the current tree.
"""
from __future__ import annotations

import argparse
import json
import os
import platform as plat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/evidence"))
from build_evidence import tree_hash  # noqa: E402

TREE_DIRS = ["src/concurrent", "tests/unit/concurrent"]


def git(*args: str) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True, stderr=subprocess.DEVNULL).strip()
    except subprocess.CalledProcessError:
        return ""


def default_platform() -> str:
    m = plat.machine().lower()
    m = {"amd64": "x86_64", "aarch64": "arm64"}.get(m, m)
    return f"{plat.system().lower()}-{m}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--sanitizer", required=True, choices=["tsan", "none"])
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--time-budget", type=float, default=0, help="stop starting new runs after this many seconds")
    ap.add_argument("--seed-offset-start", type=int, default=None)
    ap.add_argument("--ledger", default=str(ROOT / "verify/stress/runs.jsonl"))
    ap.add_argument("--platform", default=default_platform())
    ap.add_argument("--filter", default="")
    a = ap.parse_args()

    binary = Path(a.bin).resolve()
    bin_mtime = binary.stat().st_mtime
    newer = [p for d in TREE_DIRS for p in (ROOT / d).rglob("*") if p.is_file() and p.stat().st_mtime > bin_mtime]
    if newer:
        print(f"refusing: {len(newer)} hashed source(s) newer than the binary, e.g. {newer[0]}", file=sys.stderr)
        return 2
    tree = tree_hash(TREE_DIRS)
    sha, dirty = git("rev-parse", "HEAD"), bool(git("status", "--porcelain", "--", *TREE_DIRS))
    offset = a.seed_offset_start if a.seed_offset_start is not None else int.from_bytes(os.urandom(4), "little")
    start = time.monotonic()
    ledger = Path(a.ledger)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    totals: dict[str, int] = {}
    for run in range(a.runs):
        if a.time_budget and time.monotonic() - start > a.time_budget:
            print(f"time budget reached after {run} run(s)")
            break
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out.json"
            cmd = [str(binary), f"--gtest_output=json:{out}"] + ([f"--gtest_filter={a.filter}"] if a.filter else [])
            t0 = time.monotonic()
            r = subprocess.run(cmd, env={**os.environ, "LLE_STRESS_SEED_OFFSET": str(offset)},
                               capture_output=True, text=True)
            wall = time.monotonic() - t0
            if not out.exists():
                print(r.stdout[-2000:] + r.stderr[-2000:], file=sys.stderr)
                print(f"run {run}: no gtest JSON (exit {r.returncode})", file=sys.stderr)
                return 1
            report = json.loads(out.read_text())
        date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        failed = False
        with ledger.open("a") as f:
            for suite in report.get("testsuites", []):
                for t in suite.get("testsuite", []):
                    if t.get("status") != "RUN" or "queue" not in t:
                        continue
                    ok = "failures" not in t
                    failed |= not ok
                    rec = {"harness": "concurrent_stress", "test": f"{suite['name']}.{t['name']}", "queue": t["queue"],
                           "items": int(t["items"]) if ok else 0, "result": "PASS" if ok else "FAIL",
                           "seed_offset": offset, "sanitizer": a.sanitizer, "platform": a.platform, "tree": tree,
                           "sha": sha, "dirty": dirty, "date": date, "wall_s": round(wall, 1)}
                    f.write(json.dumps(rec, separators=(",", ":")) + "\n")
                    if ok:
                        totals[t["queue"]] = totals.get(t["queue"], 0) + int(t["items"])
        print(f"run {run}: seed offset {offset}, {wall:.0f} s, {'FAILED' if failed else 'passed'}", flush=True)
        if failed:
            print(r.stdout[-4000:], file=sys.stderr)
            return 1
        offset += 1
    for q, n in sorted(totals.items()):
        print(f"{q}: +{n:,} items")
    return 0


if __name__ == "__main__":
    sys.exit(main())
