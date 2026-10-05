#!/usr/bin/env python3
"""Merge a T20 run's verdict (METHODOLOGY §15; plan 12 §4, §7).

usage: merge_t20.py RUN.json BACKLOG.json IRQ.json

RUN.json is `loadgen run`'s output (responses_valid, lateness_ok, slo_evaluated,
slo_ok, ...). BACKLOG.json comes from `loadgen check-backlog` (validity condition 3 from
the exchange's metrics segment), IRQ.json from tools/results/irq_delta.py (interrupt
and softirq accounting on CPUs 0-7). The run file is rewritten in place with their
fields merged and
    valid = responses_valid and lateness_ok and backlog_ok and slo_ok and irq_clean
(every condition evaluated). A missing input leaves its condition false: a run is
never valid by default.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def load(p: str) -> dict:
    try:
        return json.loads(Path(p).read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    run_path = Path(sys.argv[1])
    run = load(sys.argv[1])
    if not run:
        print(f"cannot read {run_path}", file=sys.stderr)
        return 1
    backlog = load(sys.argv[2])
    irq = load(sys.argv[3])
    for k, v in backlog.items():
        run[k] = v
    for k in ("irq_matched_delta", "softirq_delta", "softirq_net_rx_delta", "softirq_net_tx_delta",
              "softirq_block_delta", "irq_clean"):
        if k in irq:
            run[k] = irq[k]
    conditions = {
        "responses_valid": bool(run.get("responses_valid", False)),
        "lateness_ok": bool(run.get("lateness_ok", False)),
        "backlog_ok": bool(backlog.get("backlog_evaluated", False) and backlog.get("backlog_ok", False)),
        "slo_ok": bool(run.get("slo_evaluated", False) and run.get("slo_ok", False)),
        "irq_clean": bool(irq.get("irq_clean", False)),
    }
    run["valid"] = all(conditions.values())
    run["invalid_conditions"] = ",".join(k for k, ok in conditions.items() if not ok)
    run_path.write_text(json.dumps(run, indent=2) + "\n")
    print(f"{run_path.name}: valid={run['valid']} {run['invalid_conditions']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
