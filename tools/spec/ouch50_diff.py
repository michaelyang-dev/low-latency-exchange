#!/usr/bin/env python3
"""Differential test: C++ OUCH 5.0 codec vs. the independent Python decoder.

Runs `ouch50_diffgen` (built from fuzz/ouch50) in J shards with distinct seeds,
pipes each into tools/spec/ouch50_ref_decoder.py, and reports the total number
of messages checked and disagreements (pass criterion: 0; 03-protocols s9).

  ouch50_diff.py --gen build/<dir>/.../ouch50_diffgen --count 10000000 --jobs 12
"""
from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
REF = HERE / "ouch50_ref_decoder.py"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gen", required=True, help="path to the ouch50_diffgen binary")
    ap.add_argument("--count", type=int, default=1_000_000, help="total messages across all shards")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--seed", type=int, default=1, help="base seed; shard i uses seed + i")
    ap.add_argument("--max-report", type=int, default=10)
    args = ap.parse_args()

    jobs = max(1, min(args.jobs, args.count))
    per = [args.count // jobs + (1 if i < args.count % jobs else 0) for i in range(jobs)]
    t0 = time.monotonic()
    procs = []
    for i, n in enumerate(per):
        gen = subprocess.Popen([args.gen, "--seed", str(args.seed + i), "--count", str(n)], stdout=subprocess.PIPE)
        chk = subprocess.Popen([sys.executable, str(REF), "check", "--max-report", str(args.max_report)],
                               stdin=gen.stdout, stdout=subprocess.PIPE, text=True)
        gen.stdout.close()  # the checker owns the read end
        procs.append((gen, chk))
    total = bad = 0
    failed = False
    for gen, chk in procs:
        out, _ = chk.communicate()
        gen.wait()
        if gen.returncode != 0:
            print(f"generator exited with {gen.returncode}", file=sys.stderr)
            failed = True
        line = out.strip().splitlines()[-1] if out.strip() else ""
        try:
            fields = dict(kv.split("=") for kv in line.split())
            total += int(fields["checked"])
            bad += int(fields["disagreements"])
        except (ValueError, KeyError):
            print(f"unexpected checker output: {out!r}", file=sys.stderr)
            failed = True
    elapsed = time.monotonic() - t0
    print(f"ouch50 differential test: messages={total} disagreements={bad} shards={jobs} "
          f"seed={args.seed} elapsed={elapsed:.1f}s")
    if total != args.count:
        print(f"expected {args.count} messages, checked {total}", file=sys.stderr)
        failed = True
    return 1 if (failed or bad) else 0


if __name__ == "__main__":
    sys.exit(main())
