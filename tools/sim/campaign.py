#!/usr/bin/env python3
"""Run an exsim swarm campaign across N processes (docs/plan/09 §10, R4b §4).

    python3 tools/sim/campaign.py --exsim build/sim/sim/exsim --seeds 10000 [--jobs 16]
        [--seed-base commit|random|<u64|0xhex>] [--batch 50] [--mode swarm] [--disable net,...]
        [--world all] [--canary] [--check-determinism] [--timeout 600]
        [--ledger-dir sim/ledger] [--campaign-id ID] [--require-probes] [--budget-minutes M]

Seeds base..base+N-1 are split into batches (one `exsim --seeds=K` process
each) and run on --jobs workers. Practice from TigerBeetle's CFO:
  - a timeout or crash (LLE_ASSERT abort) counts as a failure;
  - failing seeds are kept per commit SHA in <ledger-dir>/failing_seeds.json,
    one per failure signature class (oracle), preferring the seed that failed
    after the fewest events (faster to debug and shrink);
  - every campaign appends one JSON line to <ledger-dir>/campaigns.jsonl with
    the seed counts, so the amount of simulation done is accounted for;
  - --seed-base commit derives the base from HEAD's hash, so PR runs are
    "random" yet reproducible from the commit alone.
Fault counters and probe hits are summed across the ensemble; must-hit probes
that were never hit are listed (and fail the run with --require-probes).
Exit status: 0 all passed, 1 any failure or determinism mismatch, 3 probes missing.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import datetime as dt
import hashlib
import json
import os
import platform
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SEED_RE = re.compile(r"^seed=0x(?P<seed>[0-9a-f]{16}) result=(?P<result>\w+) events=(?P<events>\d+) "
                     r"trace_hash=0x(?P<hash>[0-9a-f]{16})(?P<rest>.*)$")
PROBE_RE = re.compile(r"^probe (?P<name>\S+) hits=(?P<hits>\d+) status=(?P<status>\w+)(?P<rare> rare)?$")
ASSERT_RE = re.compile(r"LLE_ASSERT failed: (?P<expr>.*)\n\s+at (?P<loc>\S+)")


def git_sha() -> tuple[str, bool]:
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True,
                             check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=REPO,
                               capture_output=True, text=True).stdout.strip() != ""
        return sha, dirty
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown", True


def fold_hex(h: str) -> int:
    """Same folding as exsim's --seed for long hex strings (16 digits at a time)."""
    def mix64(z: int) -> int:
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        return z ^ (z >> 31)
    acc = 0
    for i in range(0, len(h), 16):
        chunk = int(h[i:i + 16], 16)
        acc = chunk if i == 0 and len(h) >= 16 else mix64(acc ^ chunk)
    return acc if len(h) > 16 else int(h, 16)


def parse_base(s: str, sha: str) -> int:
    if s == "commit":
        return fold_hex(sha) if re.fullmatch(r"[0-9a-f]{40}", sha) else 1
    if s == "random":
        return secrets.randbits(63)
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def run_batch(exsim: str, start: int, count: int, args: list[str], timeout: int) -> dict:
    """Runs seeds [start, start+count); restarts after a crash so every seed gets a verdict."""
    out = {"seeds": [], "faults": collections.Counter(), "probes": {}, "wall": 0.0}
    seed, remaining = start, count
    while remaining > 0:
        cmd = [exsim, f"--seed=0x{seed:016x}", f"--seeds={remaining}", *args]
        t0 = time.monotonic()
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            stdout, stderr, code = p.stdout, p.stderr, p.returncode
        except subprocess.TimeoutExpired as e:
            stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            stderr, code = "timeout", 124
        out["wall"] += time.monotonic() - t0
        done = 0
        for line in stdout.splitlines():
            m = SEED_RE.match(line)
            if m:
                rest = dict(kv.split("=", 1) for kv in m["rest"].split() if "=" in kv)
                out["seeds"].append({
                    "seed": int(m["seed"], 16), "result": m["result"], "events": int(m["events"]),
                    "trace_hash": m["hash"], "signature": rest.get("signature"),
                    "determinism": rest.get("determinism"), "world": rest.get("world"),
                })
                done += 1
                continue
            if line.startswith("faults "):
                for kv in line.split()[1:]:
                    k, v = kv.split("=", 1)
                    out["faults"][k] += int(v)
                continue
            pm = PROBE_RE.match(line)
            if pm:
                prev = out["probes"].get(pm["name"], {"hits": 0})
                out["probes"][pm["name"]] = {"hits": prev["hits"] + int(pm["hits"]), "status": pm["status"],
                                             "rare": bool(pm["rare"])}
        seed += done
        remaining -= done
        if code in (0, 1, 2) and remaining == 0:
            break
        if remaining > 0 and code not in (0, 1, 2):
            # The seed in flight crashed or timed out: record it and continue after it.
            am = ASSERT_RE.search(stderr)
            if code == 124:
                sig = "TIMEOUT"
            elif am:
                sig = "ASSERT:" + am["loc"] + ":0x" + hashlib.sha256(am["expr"].encode()).hexdigest()[:16]
            else:
                sig = f"ABORT:exit{code}"
            out["seeds"].append({"seed": seed, "result": "FAIL", "events": -1, "trace_hash": None,
                                 "signature": sig, "determinism": None, "world": None})
            seed += 1
            remaining -= 1
        elif remaining > 0:
            break  # exited normally but printed fewer seeds: should not happen
    # Exact accounting: every requested seed gets a verdict.
    seen = {s["seed"] for s in out["seeds"]}
    for s in range(start, start + count):
        if s not in seen:
            out["seeds"].append({"seed": s, "result": "FAIL", "events": -1, "trace_hash": None,
                                 "signature": "LOST:no verdict", "determinism": None, "world": None})
    return out


def signature_class(sig: str | None) -> str:
    if not sig:
        return "UNKNOWN"
    return sig.split(":", 1)[0]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--exsim", required=True)
    ap.add_argument("--seeds", type=int, required=True)
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--seed-base", default="random", help="commit | random | <u64|0xhex>")
    ap.add_argument("--batch", type=int, default=50, help="seeds per exsim process")
    ap.add_argument("--mode", default="swarm")
    ap.add_argument("--disable", default="")
    ap.add_argument("--world", default="all")
    ap.add_argument("--canary", action="store_true")
    ap.add_argument("--check-determinism", action="store_true")
    ap.add_argument("--timeout", type=int, default=1800, help="seconds per exsim process")
    ap.add_argument("--ledger-dir", default=str(REPO / "sim" / "ledger"))
    ap.add_argument("--campaign-id")
    ap.add_argument("--require-probes", action="store_true")
    ap.add_argument("--budget-minutes", type=float, default=0.0,
                    help="start no batch after this many minutes (0: no budget); the record says how many seeds ran")
    a = ap.parse_args()

    sha, dirty = git_sha()
    base = parse_base(a.seed_base, sha)
    cid = a.campaign_id or f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{sha[:8]}-{base:x}"
    args = [f"--mode={a.mode}", f"--world={a.world}"]
    if a.disable:
        args.append(f"--disable={a.disable}")
    if a.canary:
        args.append("--canary")
    if a.check_determinism:
        args.append("--check-determinism")

    t0 = time.monotonic()
    batches = [(base + i, min(a.batch, a.seeds - i)) for i in range(0, a.seeds, a.batch)]
    seeds: list[dict] = []
    faults: collections.Counter = collections.Counter()
    probes: dict[str, dict] = {}
    # A batch that would start after the budget is not run (None): a campaign fits its CI
    # job's time limit however heavy the worlds have become, and says how far it got.
    deadline = t0 + a.budget_minutes * 60 if a.budget_minutes > 0 else None

    def guarded(s: int, n: int) -> dict | None:
        if deadline is not None and time.monotonic() >= deadline:
            return None
        return run_batch(a.exsim, s, n, args, a.timeout)

    skipped = 0
    early_failures = 0
    with cf.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as pool:
        futs = [pool.submit(guarded, s, n) for s, n in batches]
        for f in cf.as_completed(futs):
            r = f.result()
            if r is None:
                skipped += 1
                continue
            seeds += r["seeds"]
            # A failure is reported when its batch ends, not only in the summary: a long
            # campaign's first failure can be triaged while it runs on (the first 100).
            for s in r["seeds"]:
                if s["result"] != "PASS":
                    early_failures += 1
                    if early_failures <= 100:
                        print(f"  failed: 0x{s['seed']:016x} {s.get('world')} {s['signature']}", flush=True)
            faults.update(r["faults"])
            for name, p in r["probes"].items():
                prev = probes.get(name, {"hits": 0, "status": p["status"], "rare": p["rare"]})
                prev["hits"] += p["hits"]
                if p["status"] != "OK" and prev.get("status") != "OK":
                    prev["status"] = p["status"]
                if p["hits"] > 0 and p["status"] in ("MISSING", "OK"):
                    prev["status"] = "OK"
                probes[name] = prev
    wall = time.monotonic() - t0
    seeds.sort(key=lambda s: s["seed"])
    failures = [s for s in seeds if s["result"] != "PASS"]
    mismatches = [s for s in seeds if s.get("determinism") == "MISMATCH"]
    missing = sorted(n for n, p in probes.items() if p["status"] == "MISSING" and p["hits"] == 0 and not p["rare"])

    ledger_dir = Path(a.ledger_dir)
    ledger_dir.mkdir(parents=True, exist_ok=True)
    # Keep failing seeds per SHA: one per signature class, the fastest failure wins.
    fpath = ledger_dir / "failing_seeds.json"
    keep = json.loads(fpath.read_text()) if fpath.exists() else {}
    per_sha = keep.setdefault(sha, {})
    for s in failures:
        cls = signature_class(s["signature"])
        cur = per_sha.get(cls)
        ev = s["events"] if s["events"] >= 0 else 1 << 62
        if cur is None or ev < (cur["events"] if cur["events"] >= 0 else 1 << 62):
            per_sha[cls] = {"seed": f"0x{s['seed']:016x}", "events": s["events"], "signature": s["signature"],
                            "world": s.get("world"), "exsim_args": args, "campaign_id": cid, "dirty": dirty}
    if failures:
        fpath.write_text(json.dumps(keep, indent=1, sort_keys=True) + "\n")

    record = {
        "campaign_id": cid,
        "utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_sha": sha,
        "dirty": dirty,
        "host": platform.node(),
        "platform": f"{platform.system().lower()}-{platform.machine()}",
        "exsim": os.path.relpath(a.exsim, REPO) if os.path.isabs(a.exsim) else a.exsim,
        "args": args,
        "seed_base": f"0x{base:016x}",
        "seeds_run": len(seeds),
        "seeds_requested": a.seeds,
        "budget_minutes": a.budget_minutes,
        "stopped_by_budget": skipped != 0,
        "passed": len(seeds) - len(failures),
        "failed": len(failures),
        "determinism_mismatches": len(mismatches),
        "events_total": sum(max(0, s["events"]) for s in seeds),
        "wall_s": round(wall, 3),
        "jobs": a.jobs,
        "failures": [{"seed": f"0x{s['seed']:016x}", "signature": s["signature"], "world": s.get("world")}
                     for s in failures[:50]],
        "faults": dict(sorted(faults.items())),
        "probes_missing": missing,
    }
    with open(ledger_dir / "campaigns.jsonl", "a") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")

    print(f"campaign {cid}: seeds={len(seeds)} passed={record['passed']} failed={len(failures)} "
          f"mismatches={len(mismatches)} events={record['events_total']} wall={wall:.1f}s "
          f"({record['events_total'] / max(wall, 1e-9):.0f} events/s over {a.jobs} jobs)")
    by_class = collections.Counter(signature_class(s["signature"]) for s in failures)
    for cls, n in sorted(by_class.items()):
        kept = per_sha[cls]
        where = f" in {kept['world']}" if kept.get("world") else ""
        print(f"  failures {cls}: {n} (kept {kept['seed']}{where}, {kept['events']} events)")
    if missing:
        print(f"  must-hit probes never hit: {', '.join(missing)}")
    if skipped:
        print(f"  budget: {a.budget_minutes:g} minutes ran {len(seeds)} of {a.seeds} seeds")
    if failures or mismatches:
        return 1
    if a.require_probes and missing:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
