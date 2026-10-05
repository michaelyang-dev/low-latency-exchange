#!/usr/bin/env python3
"""Merge `perf stat -x,` counters into a lob_replay run JSON (04-order-book §5).

usage: merge_perf.py <run-NN.json> <perf.csv>

Adds, for every counted event, `perf_<event>` (the raw count) and
`perf_<event>_per_msg` (count / records). Events perf could not count
("<not counted>", "<not supported>") are recorded as strings, so they never
enter the statistics.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    run_path, csv_path = Path(sys.argv[1]), Path(sys.argv[2])
    run = json.loads(run_path.read_text())
    records = float(run.get("records", 0)) or 1.0
    for line in csv_path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        cols = line.split(",")
        if len(cols) < 3:
            continue
        value, event = cols[0], cols[2]
        key = "perf_" + re.sub(r"[^A-Za-z0-9]+", "_", event).strip("_").lower()
        try:
            v = float(value)
        except ValueError:
            run[key] = value
            continue
        run[key] = v
        run[key + "_per_msg"] = v / records
    run_path.write_text(json.dumps(run, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
