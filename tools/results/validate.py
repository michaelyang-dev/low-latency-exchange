#!/usr/bin/env python3
"""Validate campaign folders against the result-artifact contract (docs/plan/12 §7)."""
from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

NAME = re.compile(r"^\d{4}-\d{2}-\d{2}-[a-z0-9_.-]+-[0-9a-f]{7,40}$")
REQUIRED_CAMPAIGN = ("target", "profile", "preset", "repetitions", "commands", "methodology", "sources")


def validate(d: Path) -> list[str]:
    errs = []
    if not NAME.match(d.name):
        errs.append(f"{d.name}: folder name must be <yyyy-mm-dd>-<target>-<short-sha>")
    cfg = d / "campaign.toml"
    if not cfg.exists():
        errs.append(f"{d.name}: missing campaign.toml")
    else:
        c = tomllib.loads(cfg.read_text())
        errs += [f"{d.name}: campaign.toml lacks '{k}'" for k in REQUIRED_CAMPAIGN if k not in c]
    env = d / "env.json"
    if not env.exists():
        errs.append(f"{d.name}: missing env.json (lab/verify_env.sh)")
    elif not json.loads(env.read_text()).get("ok", False):
        errs.append(f"{d.name}: env.json reports a configuration mismatch")
    runs = list(d.glob("run-*.json"))
    # T20 searches name their runs by rate (rate-<R>-run-NN.json) next to search.json.
    runs += list(d.glob("rate-*-run-*.json"))
    if not runs:
        errs.append(f"{d.name}: no run-*.json files")
    for r in runs:
        try:
            json.loads(r.read_text())
        except json.JSONDecodeError as e:
            errs.append(f"{r}: invalid JSON ({e})")
    if not (d / "summary.json").exists():
        errs.append(f"{d.name}: missing summary.json (tools/results/summarize.py)")
    return errs


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[2] / "results"
    dirs = [p for p in sorted(root.iterdir()) if p.is_dir()] if root.exists() else []
    errs = [e for d in dirs for e in validate(d)]
    for e in errs:
        print(e, file=sys.stderr)
    print(f"validated {len(dirs)} campaign(s): {'OK' if not errs else f'{len(errs)} problem(s)'}")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
