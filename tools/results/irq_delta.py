#!/usr/bin/env python3
"""Interrupt and softirq accounting of a T20 window (METHODOLOGY §15, plan 12 §4).

usage: irq_delta.py IRQ_BEFORE IRQ_AFTER [--softirq BEFORE AFTER] [--cpus 0-7]
                    [--match REGEX] [--softirq-allow N]

Reads two snapshots of /proc/interrupts (and optionally /proc/softirqs) and prints a
JSON object: per CPU set, the delta of every interrupt line whose description matches
--match (the exchange's NIC queues and NVMe by default: "mlx5|nvme"), the NET_RX, NET_TX
and BLOCK softirq deltas, and `irq_clean`: no matched interrupt on the CPUs and at most
--softirq-allow of those softirqs (default 0). Any exchange-attributable interrupt or
softirq on CPUs 0-7 invalidates a T20 run; the counts are published either way.
"""
from __future__ import annotations

import argparse
import json
import re
import sys


def cpu_set(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    return out


def parse_interrupts(text: str) -> tuple[list[int], dict[str, tuple[list[int], str]]]:
    lines = text.splitlines()
    cpus = [int(c[3:]) for c in lines[0].split() if c.startswith("CPU")]
    rows: dict[str, tuple[list[int], str]] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        fields = rest.split()
        counts: list[int] = []
        for f in fields[: len(cpus)]:
            if not f.isdigit():
                break
            counts.append(int(f))
        desc = " ".join(fields[len(counts):])
        rows[key.strip()] = (counts, desc)
    return cpus, rows


def parse_softirqs(text: str) -> tuple[list[int], dict[str, list[int]]]:
    lines = text.splitlines()
    cpus = [int(c[3:]) for c in lines[0].split() if c.startswith("CPU")]
    rows = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        rows[key.strip()] = [int(x) for x in rest.split()]
    return cpus, rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("--softirq", nargs=2, metavar=("BEFORE", "AFTER"))
    ap.add_argument("--cpus", default="0-7")
    ap.add_argument("--match", default="mlx5|nvme")
    ap.add_argument("--softirq-allow", type=int, default=0)
    a = ap.parse_args()
    want = cpu_set(a.cpus)
    rx = re.compile(a.match)
    cpus_b, before = parse_interrupts(open(a.before).read())
    cpus_a, after = parse_interrupts(open(a.after).read())
    if cpus_a != cpus_b:
        print("CPU columns differ between the snapshots", file=sys.stderr)
        return 2
    idx = [cpus_a.index(c) for c in want if c in cpus_a]
    matched = {}
    total = 0
    for key, (counts, desc) in after.items():
        if not rx.search(desc) or key not in before:
            continue
        b = before[key][0]
        d = sum(counts[i] - b[i] for i in idx if i < len(counts) and i < len(b))
        if d:
            matched[f"{key} {desc}"] = d
        total += d
    out = {"cpus": a.cpus, "match": a.match, "irq_matched_delta": total, "irq_lines": matched}
    soft_total = 0
    if a.softirq:
        sc_b, sb = parse_softirqs(open(a.softirq[0]).read())
        sc_a, sa = parse_softirqs(open(a.softirq[1]).read())
        sidx = [sc_a.index(c) for c in want if c in sc_a]
        for name in ("NET_RX", "NET_TX", "BLOCK"):
            if name in sa and name in sb:
                d = sum(sa[name][i] - sb[name][i] for i in sidx)
                out[f"softirq_{name.lower()}_delta"] = d
                soft_total += d
    out["softirq_delta"] = soft_total
    out["irq_clean"] = total == 0 and soft_total <= a.softirq_allow
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
