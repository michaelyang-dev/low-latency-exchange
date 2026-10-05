#!/usr/bin/env python3
"""Memory-order mutation testing for the GenMC suite (08-concurrency-runtime §7).

For every std::memory_order_* argument in the queue headers, build a copy of the
source tree in which that one argument is weakened (one step, or every weaker order
with --all-weaker), re-run the GenMC harnesses that exercise the header, and record
whether some harness now fails ("killed": the order is necessary and the checks have
teeth) or all still pass ("survived": the weaker order is either safe -- to be justified
in verify/genmc/ORDERINGS.md -- or the bounded harnesses are too small to see it).

The repository is never modified: mutants live in a temporary directory and are passed
to tools/genmc/run_all.sh with --src.

    tools/genmc/mutate_orders.py                      # all headers, rc11
    tools/genmc/mutate_orders.py --headers spsc_ring.h --models "rc11 imm"
    tools/genmc/mutate_orders.py --report verify/genmc/MUTATION.md

Environment: GENMC (path to genmc), GENMC_TIMEOUT (per-run seconds, default here 900).
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN_ALL = ROOT / "tools" / "genmc" / "run_all.sh"

# Harness cases (names from run_all.sh) that exercise each header. The long
# pre-registered SCQ 2x2 bound is left out to keep a mutant run in seconds/minutes.
CASES = {
    "spsc_ring.h": r"^spsc_ring_",
    "spsc_byte_ring.h": r"^spsc_byte_ring_",
    "broadcast_ring.h": r"^broadcast_ring_",
    # The larger pre-registered SCQ bounds take minutes to hours per run; mutants use the
    # small configurations (a survivor here is weaker evidence; see ORDERINGS.md).
    "mpsc_scq.h": r"^(mpsc_scq_2p1x1c|mpsc_scq_lin_2x1|mpsc_stalled_producer_scq|mpsc_scq_sc_2p1x1c|mpsc_scq_sc_1p2x1c|mpsc_scq_sc_lin_2x1|mpsc_stalled_producer_scq_sc)$",
}

ORDER_RE = re.compile(r"std::memory_order_(seq_cst|acq_rel|acquire|release|relaxed|consume)")
RMW_RE = re.compile(r"\.(fetch_add|fetch_sub|fetch_or|fetch_and|fetch_xor|exchange|compare_exchange_strong|compare_exchange_weak)\s*\(")
LOAD_RE = re.compile(r"\.load\s*\(")
STORE_RE = re.compile(r"\.store\s*\(")

# One-step weakenings per operation kind; --all-weaker uses the transitive closure.
STEP = {
    "load": {"seq_cst": ["acquire"], "acquire": ["relaxed"]},
    "store": {"seq_cst": ["release"], "release": ["relaxed"]},
    "rmw": {"seq_cst": ["acq_rel"], "acq_rel": ["acquire", "release"], "acquire": ["relaxed"], "release": ["relaxed"]},
}


def weaker(kind: str, order: str, all_weaker: bool) -> list[str]:
    direct = STEP[kind].get(order, [])
    if not all_weaker:
        return direct
    out: list[str] = []
    todo = list(direct)
    while todo:
        o = todo.pop(0)
        if o not in out:
            out.append(o)
            todo.extend(STEP[kind].get(o, []))
    return out


@dataclass
class Site:
    header: str
    line: int
    col: int
    order: str
    kind: str
    text: str


def find_sites(header: Path) -> list[Site]:
    sites: list[Site] = []
    lines = header.read_text().splitlines()
    for i, line in enumerate(lines):
        code = line.split("//", 1)[0]
        for m in ORDER_RE.finditer(code):
            # Classify by the nearest atomic call on this line before the order argument.
            prefix = code[: m.start()]
            calls = [(mm.start(), k) for k, rx in (("rmw", RMW_RE), ("load", LOAD_RE), ("store", STORE_RE)) for mm in rx.finditer(prefix)]
            if not calls:
                continue  # e.g. an order passed through a variable; not a call site
            kind = max(calls)[1]
            sites.append(Site(header.name, i + 1, m.start(), m.group(1), kind, line.strip()))
    return sites


def mutate(src_root: Path, site: Site, new_order: str) -> None:
    path = src_root / "concurrent" / site.header
    lines = path.read_text().splitlines(keepends=True)
    line = lines[site.line - 1]
    old = f"std::memory_order_{site.order}"
    assert line[site.col : site.col + len(old)] == old, (site, line)
    lines[site.line - 1] = line[: site.col] + f"std::memory_order_{new_order}" + line[site.col + len(old) :]
    path.write_text("".join(lines))


def run_cases(src_root: Path, pattern: str, models: str, out: Path) -> tuple[str, list[str]]:
    env = dict(os.environ)
    env.setdefault("GENMC_TIMEOUT", "900")
    env["OUT"] = str(out)
    proc = subprocess.run(
        [str(RUN_ALL), "--quick", "--only", pattern, "--models", models, "--src", str(src_root)],
        capture_output=True, text=True, env=env)
    failed = []
    outcomes = set()
    summary = out / "summary.tsv"
    if summary.exists():
        for row in summary.read_text().splitlines()[1:]:
            cols = row.split("\t")
            if len(cols) >= 5 and cols[4] != "OK":
                failed.append(f"{cols[0]}/{cols[1]}:{cols[3]}")
                outcomes.add(cols[3])
    # Only a reported violation kills a mutant; a timeout or a GenMC crash proves nothing.
    if outcomes & {"fail", "liveness"} or (outcomes == {"pass"}):
        return "killed", failed
    if "timeout" in outcomes:
        return "timeout", failed
    if failed:
        return "error", failed
    if proc.returncode != 0:
        return "error", [proc.stdout[-400:] + proc.stderr[-400:]]
    return "survived", []


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--headers", nargs="*", default=sorted(CASES), help="headers in src/concurrent to mutate")
    ap.add_argument("--models", default="rc11", help='GenMC models, e.g. "rc11 imm"')
    ap.add_argument("--all-weaker", action="store_true", help="try every weaker order, not just one step")
    ap.add_argument("--report", type=Path, help="write a Markdown report here")
    ap.add_argument("--keep", action="store_true", help="keep mutant trees and logs")
    args = ap.parse_args()

    work = Path(tempfile.mkdtemp(prefix="lle-mutate-"))
    rows = []
    started = time.time()
    try:
        # Baseline: the unmutated tree must pass, or mutation results mean nothing.
        base_src = work / "base" / "src"
        shutil.copytree(ROOT / "src" / "concurrent", base_src / "concurrent")
        shutil.copytree(ROOT / "src" / "common", base_src / "common")
        for header in args.headers:
            status, detail = run_cases(base_src, CASES[header], args.models, work / "base" / header)
            if status != "survived":
                print(f"baseline for {header} does not pass: {detail}", file=sys.stderr)
                return 2
        n = 0
        for header in args.headers:
            for site in find_sites(ROOT / "src" / "concurrent" / header):
                for new_order in weaker(site.kind, site.order, args.all_weaker):
                    n += 1
                    mdir = work / f"m{n:03d}"
                    src = mdir / "src"
                    shutil.copytree(base_src, src)
                    mutate(src, site, new_order)
                    t0 = time.time()
                    status, detail = run_cases(src, CASES[header], args.models, mdir / "out")
                    dt = time.time() - t0
                    rows.append((header, site, new_order, status, detail, dt))
                    print(f"[{n:3d}] {header}:{site.line} {site.kind:5s} {site.order:>7s} -> {new_order:<7s} "
                          f"{status:8s} {dt:6.1f}s  {' '.join(detail)[:120]}", flush=True)
                    if not args.keep:
                        shutil.rmtree(mdir, ignore_errors=True)
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"mutants kept in {work}")

    killed = sum(1 for r in rows if r[3] == "killed")
    survived = [r for r in rows if r[3] == "survived"]
    print(f"\n{len(rows)} mutants: {killed} killed, {len(survived)} survived, "
          f"{len(rows) - killed - len(survived)} other; {time.time() - started:.0f}s")
    if args.report:
        with args.report.open("w") as f:
            f.write("# Memory-order mutation report\n\n")
            f.write(f"Generated by `tools/genmc/mutate_orders.py` (models: {args.models}; "
                    f"{'all weaker orders' if args.all_weaker else 'one-step weakening'}). "
                    "A mutant is *killed* when at least one harness that passes on the unmutated tree "
                    "reports an error; *survived* means every harness still passes within the bounds.\n\n")
            f.write(f"Totals: {len(rows)} mutants, {killed} killed, {len(survived)} survived.\n\n")
            f.write("| Header | Line | Op | Order | Weakened to | Result | Failing harness(es) | Time |\n")
            f.write("|---|---|---|---|---|---|---|---|\n")
            for header, site, new_order, status, detail, dt in rows:
                det = ", ".join(detail).replace("|", "/")[:160]
                f.write(f"| {header} | {site.line} | {site.kind} | {site.order} | {new_order} | {status} | {det} | {dt:.1f}s |\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
