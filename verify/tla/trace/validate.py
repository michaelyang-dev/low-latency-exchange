#!/usr/bin/env python3
"""Validates exsim_ha protocol traces against HotStandby with TLC (R-08).

usage: validate.py --jar tla2tools.jar TRACE.ndjson... [--keep DIR] [--workers N]

For each trace: convert it (ndjson_to_tla.py), run TLC on HotStandbyTraceRun (which
extends verify/tla/HotStandbyTrace.tla) and report PASS when every event was matched
(TLC reports the invariant NotDone violated at the end of the trace) or FAIL with the
first event no specification step could match. Exit status 1 if any trace failed.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TLA_DIR = HERE.parent


def validate(jar: str, trace: Path, workdir: Path, workers: str) -> tuple[bool, str]:
    workdir.mkdir(parents=True, exist_ok=True)
    for f in ("HotStandby.tla", "HotStandbyTrace.tla"):
        shutil.copy(TLA_DIR / f, workdir / f)
    conv = subprocess.run([sys.executable, str(HERE / "ndjson_to_tla.py"), str(trace), str(workdir)],
                          capture_output=True, text=True)
    if conv.returncode != 0:
        return False, "conversion failed: " + (conv.stderr.strip() or conv.stdout.strip())
    stats = conv.stdout.strip()
    cmd = ["java", "-XX:+UseParallelGC", "-Xss16m", "-cp", jar, "tlc2.TLC", "-workers", workers, "-metadir",
           str(workdir / "meta"), "-config", "HotStandbyTraceRun.cfg", "HotStandbyTraceRun.tla"]
    r = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True)
    out = r.stdout + r.stderr
    (workdir / "tlc.log").write_text(out)
    if "Invariant NotDone is violated" in out:
        gen = re.findall(r"(\d+) states generated, (\d+) distinct", out)
        return True, f"{stats} matched ({gen[-1][1] + ' distinct states' if gen else ''})"
    # A mismatch: the last state of the error trace (deadlock) or the failing invariant.
    m = re.findall(r"/\\ l = (\d+)", out)
    why = "no error trace"
    if "Invariant" in out and "is violated" in out:
        why = re.search(r"Invariant \w+ is violated", out).group(0)
    elif "Deadlock reached" in out:
        why = "no specification step matches"
    elif "Error" in out:
        why = next((ln for ln in out.splitlines() if "Error" in ln), "TLC error")
    at = int(m[-1]) if m else 0
    return False, f"{stats} FAILED at event {at}: {why} (see {workdir / 'tlc.log'})"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--jar", required=True)
    ap.add_argument("--keep", help="keep the TLC work directories here")
    ap.add_argument("--workers", default="1")
    ap.add_argument("traces", nargs="+")
    a = ap.parse_args()
    base = Path(a.keep) if a.keep else Path(tempfile.mkdtemp(prefix="hstrace-"))
    failed = 0
    for t in a.traces:
        p = Path(t)
        ok, msg = validate(a.jar, p, base / p.stem, a.workers)
        print(f"{'PASS' if ok else 'FAIL'} {p.name}: {msg}", flush=True)
        failed += 0 if ok else 1
    print(f"traces={len(a.traces)} failed={failed}")
    if not a.keep and failed == 0:
        shutil.rmtree(base, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
