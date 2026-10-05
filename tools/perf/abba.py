#!/usr/bin/env python3
"""ABBA experiment runner and keep/revert decision (docs/perf/METHODOLOGY.md §7, target T13).

Runs two arms (A = current best, B = the experiment) as fresh processes in ABBA
order (A B B A A B B A ...) for R repetitions per arm, then decides:

  keep  iff  (1) the upper bound of the 95% bootstrap CI of the B/A ratio of the
                 primary metric (default ns_per_msg_mean) is below 0.99;
             (2) B's sampled median (default net_p50_ns), if present, does not regress:
                 its 95% CI ratio upper bound must not exceed 1.0 by more than the
                 noise band (--median-tolerance, default 0.0, i.e. lower bound of
                 the ratio CI must be <= 1.0);
             (3) every run of both arms is valid and reports the same digests
                 (bbo_digest, books_digest);
             (4) the counters explain the effect: this is a judgement, recorded in
                 the experiment's EXP-NN.md, not decided here.

Each arm command is a shell template. It must write the run JSON to {json}
(lob_replay: `--out {dir} --run-name {name}`). Placeholders: {dir}, {name}, {json}.

    tools/perf/abba.py --out results/2026-10-02-exp-03-abc123 --reps 15 \\
        --a 'build-a/apps/lob_replay/lob_replay --file F --variant opt --cpu 11 --huge 1g --warmup 1 --strict-faults --out {dir} --run-name {name}' \\
        --b 'build-b/apps/lob_replay/lob_replay ... --out {dir} --run-name {name}'

Writes {out}/abba.json (all statistics and the decision) and prints a summary.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import subprocess
import sys
from pathlib import Path

RESAMPLES = 10_000
SEED = 20260930


def order(reps: int) -> list[str]:
    seq: list[str] = []
    pattern = ["a", "b", "b", "a"]
    while len(seq) < 2 * reps:
        seq += pattern
    return seq[: 2 * reps]


def ratio_ci(a: list[float], b: list[float]) -> tuple[float, float, float]:
    """Median(B)/median(A) with a 95% percentile-bootstrap CI over runs (arms resampled independently)."""
    point = statistics.median(b) / statistics.median(a)
    rng = random.Random(SEED)
    rs = []
    for _ in range(RESAMPLES):
        ra = statistics.median([a[rng.randrange(len(a))] for _ in a])
        rb = statistics.median([b[rng.randrange(len(b))] for _ in b])
        rs.append(rb / ra)
    rs.sort()
    return point, rs[int(0.025 * RESAMPLES)], rs[min(RESAMPLES - 1, int(0.975 * RESAMPLES))]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--reps", type=int, default=15)
    ap.add_argument("--a", required=True, help="arm A (current best) command template")
    ap.add_argument("--b", required=True, help="arm B (experiment) command template")
    ap.add_argument("--metric", default="ns_per_msg_mean", help="lower is better")
    ap.add_argument("--sampled-metric", default="net_p50_ns", help="must not regress (if present)")
    ap.add_argument("--keep-threshold", type=float, default=0.99)
    ap.add_argument("--analyze-only", action="store_true", help="reuse existing run JSONs in --out")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    runs: dict[str, list[dict]] = {"a": [], "b": []}
    counters = {"a": 0, "b": 0}
    for arm in order(args.reps):
        counters[arm] += 1
        name = f"{arm}-{counters[arm]:02d}"
        jpath = out / f"{name}.json"
        if not args.analyze_only:
            cmd = getattr(args, arm).format(dir=str(out), name=name, json=str(jpath))
            print(f"[{name}] {cmd}", flush=True)
            r = subprocess.run(["bash", "-c", cmd])
            if r.returncode not in (0, 3):  # 3 = lob_replay ran but marked the run invalid
                print(f"arm {arm} run {name} failed with exit {r.returncode}", file=sys.stderr)
                return 2
        runs[arm].append(json.loads(jpath.read_text()))

    def values(arm: str, key: str) -> list[float]:
        return [float(r[key]) for r in runs[arm] if key in r]

    invalid = [f'{r.get("variant")}:{i}' for arm in "ab" for i, r in enumerate(runs[arm]) if not r.get("valid", True)]
    digests = {(r.get("bbo_digest"), r.get("books_digest")) for arm in "ab" for r in runs[arm]}
    point, lo, hi = ratio_ci(values("a", args.metric), values("b", args.metric))
    result: dict = {
        "reps": args.reps,
        "metric": args.metric,
        "ratio": point,
        "ratio_ci95": [lo, hi],
        "a_median": statistics.median(values("a", args.metric)),
        "b_median": statistics.median(values("b", args.metric)),
        "invalid_runs": invalid,
        "digests_identical": len(digests) == 1,
    }
    checks = {
        "ci_upper_below_threshold": hi < args.keep_threshold,
        "all_runs_valid": not invalid,
        "digests_identical": len(digests) == 1,
    }
    sa, sb = values("a", args.sampled_metric), values("b", args.sampled_metric)
    if sa and sb:
        sp, slo, shi = ratio_ci(sa, sb)
        result["sampled_ratio"] = sp
        result["sampled_ratio_ci95"] = [slo, shi]
        checks["sampled_median_not_regressed"] = slo <= 1.0
    result["checks"] = checks
    result["decision"] = "keep" if all(checks.values()) else "revert"
    result["note"] = "Rule 4 (counters explain the effect) is judged in EXP-NN.md."
    (out / "abba.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
