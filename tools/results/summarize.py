#!/usr/bin/env python3
"""Summarize a benchmark campaign folder into summary.json (docs/plan/12 §5, §7).

Input:  results/<campaign>/campaign.toml and run-*.json files. Each run file is a
        flat JSON object of numeric metrics (e.g. {"msgs_per_s": ..., "p50_ns": ...}).
Output: results/<campaign>/summary.json with, per metric, the median across runs
        and a 95% percentile-bootstrap confidence interval over runs (10,000
        resamples, fixed seed), plus the git tree hashes of the campaign's
        declared source dependencies (freshness rule, docs/plan/12 §7).

Uncertainty is computed at the run level only: per-sample data within one run is
autocorrelated, so within-run intervals would be meaninglessly tight.

Multi-cell campaigns (a [matrix] in campaign.toml) name their runs run-NN-<cell>.json;
each cell is summarized on its own under "cells". Targets with a derived headline get a
"derived" block (METHODOLOGY v2):
  t18  median across runs of the per-run TTT_raw p50 and p99 against pass_p50_ns/pass_p99_ns
  t19  ratio of the cells' medians of ratio_metric with a 95% BCa bootstrap CI over runs
  t20  the highest valid rate of the search (search.json) against pass_rate
  t32  logger overhead (on - off) / off of the per-message work time, arms A (on) / B (off)
"""
from __future__ import annotations

import json
import random
import re
import statistics
import subprocess
import sys
import tomllib
from pathlib import Path

RESAMPLES = 10_000
SEED = 20260930


def bootstrap_ci(values: list[float], stat=statistics.median, level: float = 0.95) -> tuple[float, float]:
    if len(values) < 2:
        return (values[0], values[0]) if values else (float("nan"), float("nan"))
    rng = random.Random(SEED)
    n = len(values)
    stats = sorted(stat([values[rng.randrange(n)] for _ in range(n)]) for _ in range(RESAMPLES))
    lo = stats[int((1 - level) / 2 * RESAMPLES)]
    hi = stats[min(RESAMPLES - 1, int((1 + level) / 2 * RESAMPLES))]
    return lo, hi


def tree_hashes(repo: Path, paths: list[str]) -> dict[str, str]:
    out = {}
    for p in paths:
        try:
            out[p] = subprocess.check_output(["git", "-C", str(repo), "rev-parse", f"HEAD:{p}"], text=True,
                                             stderr=subprocess.DEVNULL).strip()
        except subprocess.CalledProcessError:
            out[p] = "unknown"
    return out


RUN = re.compile(r"^run-(\d+)(?:-(.+))?\.json$")


def metric_stats(runs: list[dict]) -> dict[str, dict]:
    metrics: dict[str, dict] = {}
    keys = sorted({k for r in runs for k, v in r.items() if isinstance(v, (int, float)) and not isinstance(v, bool)})
    for k in keys:
        vals = [float(r[k]) for r in runs if k in r and isinstance(r[k], (int, float)) and not isinstance(r[k], bool)]
        if not vals:
            continue
        lo, hi = bootstrap_ci(vals)
        metrics[k] = {"median": statistics.median(vals), "mean": statistics.fmean(vals), "min": min(vals),
                      "max": max(vals), "ci95": [lo, hi], "runs": len(vals)}
    return metrics


def load_cells(campaign_dir: Path) -> dict[str | None, dict]:
    """cell -> {"valid": [run dicts], "excluded": n}"""
    cells: dict[str | None, dict] = {}
    for f in sorted(campaign_dir.glob("run-*.json")):
        m = RUN.match(f.name)
        if not m:
            continue
        data = json.loads(f.read_text())
        c = cells.setdefault(m.group(2), {"valid": [], "excluded": 0})
        if data.get("valid", True):
            c["valid"].append(data)
        else:
            c["excluded"] += 1
    return cells


def bca_ratio_ci(x: list[float], y: list[float], level: float = 0.95) -> tuple[float, float]:
    """95% BCa bootstrap CI of median(x) / median(y), resampling runs within each cell."""
    theta = statistics.median(x) / statistics.median(y)
    if len(x) < 2 or len(y) < 2:
        return theta, theta
    rng = random.Random(SEED)
    boots = []
    for _ in range(RESAMPLES):
        bx = [x[rng.randrange(len(x))] for _ in x]
        by = [y[rng.randrange(len(y))] for _ in y]
        boots.append(statistics.median(bx) / statistics.median(by))
    boots.sort()
    nd = statistics.NormalDist()
    below = sum(1 for b in boots if b < theta)
    p = min(max(below / RESAMPLES, 1.0 / RESAMPLES), 1.0 - 1.0 / RESAMPLES)
    z0 = nd.inv_cdf(p)
    jack = [statistics.median(x[:i] + x[i + 1:]) / statistics.median(y) for i in range(len(x))]
    jack += [statistics.median(x) / statistics.median(y[:i] + y[i + 1:]) for i in range(len(y))]
    jm = statistics.fmean(jack)
    num = sum((jm - j) ** 3 for j in jack)
    den = 6.0 * (sum((jm - j) ** 2 for j in jack) ** 1.5)
    a = num / den if den else 0.0

    def quantile(alpha: float) -> float:
        z = nd.inv_cdf(alpha)
        adj = nd.cdf(z0 + (z0 + z) / (1.0 - a * (z0 + z)))
        return boots[min(RESAMPLES - 1, max(0, int(adj * RESAMPLES)))]

    return quantile((1 - level) / 2), quantile((1 + level) / 2)


def derived(target: str, cfg: dict, cells: dict, campaign_dir: Path) -> dict:
    out: dict = {}
    if target == "t18":
        runs = cells.get(None, {"valid": []})["valid"]
        p50 = [float(r["ttt_raw_p50_ns"]) for r in runs if "ttt_raw_p50_ns" in r]
        p99 = [float(r["ttt_raw_p99_ns"]) for r in runs if "ttt_raw_p99_ns" in r]
        if p50 and p99:
            out = {"median_p50_ns": statistics.median(p50), "median_p99_ns": statistics.median(p99), "runs": len(p50),
                   "pass_p50_ns": cfg.get("pass_p50_ns"), "pass_p99_ns": cfg.get("pass_p99_ns")}
            out["pass"] = (out["median_p50_ns"] <= float(cfg.get("pass_p50_ns", 0)) and
                           out["median_p99_ns"] <= float(cfg.get("pass_p99_ns", 0)))
    elif target == "t19":
        num, den, metric = cfg.get("ratio_numerator"), cfg.get("ratio_denominator"), cfg.get("ratio_metric")
        x = [float(r[metric]) for r in cells.get(num, {"valid": []})["valid"] if metric in r]
        y = [float(r[metric]) for r in cells.get(den, {"valid": []})["valid"] if metric in r]
        if x and y and statistics.median(y) > 0:
            ratio = statistics.median(x) / statistics.median(y)
            lo, hi = bca_ratio_ci(x, y)
            out = {"ratio": ratio, "ci95_bca": [lo, hi], "runs": [len(x), len(y)], "metric": metric,
                   "pass_ratio": cfg.get("pass_ratio"), "pass": ratio >= float(cfg.get("pass_ratio", 0))}
    elif target == "t20":
        sp = campaign_dir / "search.json"
        if sp.exists():
            s = json.loads(sp.read_text())
            rate = int(s.get("highest_valid_rate", 0))
            out = {"highest_valid_rate": rate, "points": s.get("points", []), "pass_rate": cfg.get("pass_rate"),
                   "pass": rate >= int(cfg.get("pass_rate", 0)) and rate > 0}
            per_rate: dict[str, list] = {}
            for f in sorted(campaign_dir.glob("rate-*-run-*.json")):
                d = json.loads(f.read_text())
                per_rate.setdefault(f.name.split("-run-")[0], []).append(
                    {"run": f.stem, "valid": d.get("valid", False), "invalid_conditions": d.get("invalid_conditions", "")})
            out["runs"] = per_rate
    elif target == "t32":
        on, off = [], []
        for cell, c in cells.items():
            for r in c["valid"]:
                v = r.get("work_ns_per_msg_x1000")
                if v is None:
                    continue
                arm = r.get("arm") or ("on" if (cell or "").startswith("A") else "off")
                (on if arm == "on" else off).append(float(v) / 1000.0)
        if on and off:
            m_on, m_off = statistics.fmean(on), statistics.fmean(off)
            pct = (m_on - m_off) / m_off * 100.0
            out = {"work_ns_per_msg_on": m_on, "work_ns_per_msg_off": m_off, "overhead_pct": pct,
                   "runs": [len(on), len(off)], "pass_overhead_pct": cfg.get("pass_overhead_pct"),
                   "pass_overhead": pct <= float(cfg.get("pass_overhead_pct", 0)),
                   "logger_drops": "see *.nlog-stats.txt (0 required in every logging-on run)"}
    return out


def summarize(campaign_dir: Path) -> dict:
    cfg_path = campaign_dir / "campaign.toml"
    cfg = tomllib.loads(cfg_path.read_text()) if cfg_path.exists() else {}
    cells = load_cells(campaign_dir)
    plain = cells.get(None, {"valid": [], "excluded": 0})
    repo = Path(__file__).resolve().parents[2]
    out = {
        "campaign": campaign_dir.name,
        "target": cfg.get("target", "unknown"),
        "methodology": cfg.get("methodology", "unknown"),
        "pilot": "pilot_overrides" in cfg,
        "runs_valid": sum(len(c["valid"]) for c in cells.values()),
        "runs_excluded": sum(c["excluded"] for c in cells.values()),
        "metrics": metric_stats(plain["valid"]),
        "source_tree_hashes": tree_hashes(repo, cfg.get("sources", [])),
    }
    named = {k: v for k, v in cells.items() if k is not None}
    if named:
        out["cells"] = {k: {"runs_valid": len(v["valid"]), "runs_excluded": v["excluded"],
                            "metrics": metric_stats(v["valid"])} for k, v in sorted(named.items())}
    d = derived(str(cfg.get("target", "")), cfg, cells, campaign_dir)
    if d:
        out["derived"] = d
    failures = campaign_dir / "failures.txt"
    if failures.exists():
        out["failed_commands"] = [l for l in failures.read_text().splitlines() if l.strip()]
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: summarize.py results/<campaign>", file=sys.stderr)
        return 64
    d = Path(sys.argv[1])
    summary = summarize(d)
    (d / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(f"summary: {d / 'summary.json'} ({summary['runs_valid']} valid runs, {summary['runs_excluded']} excluded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
