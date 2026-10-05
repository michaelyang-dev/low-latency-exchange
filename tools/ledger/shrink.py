#!/usr/bin/env python3
"""Shrink a failing exsim seed to a minimal reproduction (docs/plan/09 §10).

    python3 tools/ledger/shrink.py --exsim build/sim/sim/exsim --seed 0x1c [--out min_trace.txt]
                                   [--strict] [-- <extra exsim args, e.g. --mode=swarm --canary>]

Pipeline (each step keeps the failure "the same": same oracle ID, or with
--strict the same oracle and message hash):
  1. binary-search the step count (--ticks-max);
  2. ablate one fault class at a time (--disable=...); the split PRNG streams
     keep everything else identical, so a class that is not needed can go;
  3. ddmin over the recorded discrete fault events (crashes, pauses,
     partitions, clock steps) replayed with --replay;
  4. re-minimize the step count for the reduced configuration.
The result is written as a replayable min_trace file: a comment header with
the exact exsim invocation, followed by the remaining fault events (exsim
ignores '#' lines, so the file itself is the --replay input).
"""
from __future__ import annotations

import argparse
import math
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ledger  # noqa: E402

CLASSES = ("buggify", "clock", "pause", "partition", "crash", "disk", "net")


@dataclass(frozen=True)
class Outcome:
    failed: bool
    oracle: str | None
    signature: str | None
    world: str | None
    events: int
    msg_hash: str | None


class Runner:
    def __init__(self, exsim: str, seed: int, base_args: list[str], timeout: int, verbose: bool):
        self.exsim, self.seed, self.base, self.timeout, self.verbose = exsim, seed, base_args, timeout, verbose
        self.runs = 0
        self.cache: dict[tuple, Outcome] = {}

    def run(self, disable: tuple[str, ...] = (), ticks: int | None = None, replay: str | None = None,
            record: str | None = None) -> Outcome:
        key = (disable, ticks, replay)
        if record is None and key in self.cache:
            return self.cache[key]
        args = [self.exsim, f"--seed=0x{self.seed:016x}", *self.base, "--quiet"]
        if disable:
            args.append("--disable=" + ",".join(disable))
        if ticks is not None:
            args.append(f"--ticks-max={ticks}")
        if replay is not None:
            args.append(f"--replay={replay}")
        if record is not None:
            args.append(f"--record-faults={record}")
        self.runs += 1
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=self.timeout)
            out, code = p.stdout, p.returncode
        except subprocess.TimeoutExpired:
            out, code = "", 124
        sig = world = None
        events = 0
        for line in out.splitlines():
            if line.startswith("signature="):
                kv = dict(x.split("=", 1) for x in line.split() if "=" in x)
                sig, world = kv.get("signature"), kv.get("world")
            elif line.startswith("events="):
                events = int(line.split()[0].split("=", 1)[1])
        parsed = ledger.parse_signature(sig) if sig else None
        if code not in (0, 1) and sig is None:
            # Crash (LLE_ASSERT abort) or timeout: a failure without an oracle signature.
            parsed = {"oracle": "ABORT" if code != 124 else "TIMEOUT", "event_index": 0, "msg_hash": "0x" + "0" * 16}
        o = Outcome(code != 0 and code != 2, parsed["oracle"] if parsed else None, sig, world, events,
                    parsed["msg_hash"] if parsed else None)
        if self.verbose:
            print(f"  [{self.runs}] {shlex.join(args[1:])} -> {o.signature or ('FAIL' if o.failed else 'PASS')}",
                  file=sys.stderr)
        if record is None:
            self.cache[key] = o
        return o


def ddmin(items: list[str], test) -> list[str]:
    """Zeller's ddmin: a 1-minimal subset of items for which test() holds."""
    if test([]):
        return []
    n = 2
    while len(items) >= 2:
        chunk = math.ceil(len(items) / n)
        subsets = [items[i:i + chunk] for i in range(0, len(items), chunk)]
        reduced = False
        for s in subsets:
            if test(s):
                items, n, reduced = s, 2, True
                break
        if not reduced:
            for i in range(len(subsets)):
                comp = [x for j, s in enumerate(subsets) if j != i for x in s]
                if test(comp):
                    items, n, reduced = comp, max(n - 1, 2), True
                    break
        if not reduced:
            if n >= len(items):
                break
            n = min(len(items), 2 * n)
    return items


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exsim", required=True)
    ap.add_argument("--seed", required=True, help="decimal or 0x hex")
    ap.add_argument("--out", help="min_trace output path (default: stdout only)")
    ap.add_argument("--strict", action="store_true", help="also require the same message hash")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("extra", nargs="*", help="extra exsim arguments (after --)")
    a = ap.parse_args()
    seed = ledger.parse_seed(a.seed)
    if seed is None:
        ap.error("bad --seed")
    extra = [x for x in a.extra if not x.startswith(("--disable=", "--ticks-max=", "--replay=", "--record-faults="))]
    user_disable = tuple(x.split("=", 1)[1] for x in a.extra if x.startswith("--disable=") and x != "--disable=-")
    disable: tuple[str, ...] = tuple(c for d in user_disable for c in d.split(",") if c)

    r = Runner(a.exsim, seed, extra, a.timeout, a.verbose)
    base = r.run(disable)
    if not base.failed:
        print(f"shrink: seed 0x{seed:016x} does not fail with {shlex.join(extra)}", file=sys.stderr)
        return 2
    if base.world and not any(x.startswith("--world=") for x in extra):
        extra.append(f"--world={base.world}")
        r = Runner(a.exsim, seed, extra, a.timeout, a.verbose)
        base = r.run(disable)
    target_oracle, target_hash = base.oracle, base.msg_hash
    print(f"shrink: seed=0x{seed:016x} fails: {base.signature} (world {base.world}, {base.events} events)")

    def same(o: Outcome) -> bool:
        return o.failed and o.oracle == target_oracle and (not a.strict or o.msg_hash == target_hash)

    def min_ticks(dis: tuple[str, ...], replay: str | None, upper: int) -> int | None:
        if upper <= 0 or not same(r.run(dis, upper, replay)):
            return None  # e.g. liveness failures need the whole run
        lo, hi = 1, upper
        while lo < hi:
            mid = (lo + hi) // 2
            if same(r.run(dis, mid, replay)):
                hi = mid
            else:
                lo = mid + 1
        return lo

    # 1. Step count.
    ticks = min_ticks(disable, None, base.events)
    print(f"shrink: step 1 (ticks): {base.events} -> {ticks if ticks is not None else 'not truncatable'}")

    # 2. Fault-class ablation (uncapped: removing a class can move the failure).
    for cls in CLASSES:
        if cls in disable:
            continue
        cand = tuple(sorted({*disable, cls}))
        if same(r.run(cand)):
            disable = cand
    print(f"shrink: step 2 (ablation): disabled = {','.join(disable) or '-'}")

    # 3. ddmin over the discrete fault schedule.
    with tempfile.TemporaryDirectory(prefix="shrink_") as td:
        rec = Path(td) / "schedule.txt"
        r.run(disable, record=str(rec))
        lines = [ln for ln in rec.read_text().splitlines() if ln.strip() and not ln.startswith("#")]
        counter = [0]

        def write(subset: list[str]) -> str:
            counter[0] += 1
            p = Path(td) / f"replay_{counter[0]}.txt"
            p.write_text("".join(x + "\n" for x in subset))
            return str(p)

        def test(subset: list[str]) -> bool:
            return same(r.run(disable, None, write(subset)))

        if not test(lines):
            print("shrink: step 3 (ddmin): recorded schedule does not replay to the same failure; keeping all",
                  file=sys.stderr)
            minimal = lines
        else:
            minimal = ddmin(lines, test)
        print(f"shrink: step 3 (ddmin): fault events {len(lines)} -> {len(minimal)}")

        # 4. Final step count with the minimal schedule.
        final_replay = write(minimal)
        final = r.run(disable, None, final_replay)
        ticks = min_ticks(disable, final_replay, final.events)
        final = r.run(disable, ticks, final_replay)
        print(f"shrink: step 4 (ticks): {ticks if ticks is not None else 'not truncatable'}")

    args = [*extra]
    if disable:
        args.append("--disable=" + ",".join(disable))
    if ticks is not None:
        args.append(f"--ticks-max={ticks}")
    header = [
        "# exsim minimal trace (tools/ledger/shrink.py)",
        f"# seed=0x{seed:016x}",
        f"# args={shlex.join(args)}",
        f"# oracle={target_oracle}",
        f"# signature={final.signature}",
        f"# original_signature={base.signature}",
        f"# replay: exsim --seed=0x{seed:016x} {shlex.join(args)} --replay=<this file>",
        "# fault events: <world> <at_ns> <kind> <node> <a> <b> <dur_ns>",
    ]
    text = "\n".join(header) + "\n" + "".join(x + "\n" for x in minimal)
    if a.out:
        Path(a.out).write_text(text)
    print(f"shrink: {r.runs} exsim runs; minimal: {shlex.join(args)} with {len(minimal)} fault events")
    print("ledger snippet:")
    print(f"  exsim_args: [{', '.join(repr(x) for x in args)}]".replace("'", '"'))
    print(f"  min_trace: {a.out or '<stdout>'}")
    if not a.out:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
