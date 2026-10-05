#!/usr/bin/env python3
"""Runs failover trials repeatedly and summarizes them (plan 10 §7, R-10 skeleton).

Each trial is one process of exchange_failover_trial (tests/integration/exchange/
ha_trial.h): a primary, a backup and witnessd on one host, the fault of its class, the
rejoin of the lost node, and the trial's own oracle checks. This runner then re-checks
every trial independently (check_trial_oracles.py), measures the line-A takeover from
the capture (analyze_pcap.py) and writes OUT/summary.json with, per class, the trial
count, passes, every violation, and p50/p90/p99/max of the timings.

Functional only. On localhost or in a VM the timestamps are software receive times and
the fault, the nodes and the capture share one host, so the timings are indicative,
never T25 evidence. The lab harness keeps these interfaces: a trial directory with
trial.json and capture.pcap (hardware-timestamped on host C), checked by the same two
scripts.

Classes: F1 (SIGKILL primary), F1-partial (F1 during a partial fill), F1-divergent
(F1 after a short A-B cut: the restarted primary truncates its journal), F6 (A-B link
cut: solo, never a takeover), F7 (SIGKILL backup), F7-resume (F7, then the solo
primary restarts: RESUME). Every class ends with the lost node rejoining (10 §5).

Usage:
  run_trials.py --bin BUILD_DIR --out OUT [--classes F1,F6,F7] [--trials N] [--seed-base S]
                [--t-d-ms N --t-ack-ms N --rto-ms N --tie-break-ms N --heartbeat-ms N]
                [--phase1 N --phase2 N --phase3 N] [--keep] [--label TEXT]
Exit status: 0 every trial passed both checks, 1 otherwise, 2 usage.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CLASSES = ["F1", "F1-partial", "F1-divergent", "F6", "F7", "F7-resume"]
TIMINGS = ["t_takeover", "fault_to_first_line_a", "fault_to_solo_primary", "restart_to_paired",
           "restart_to_resumed", "pcap_t_takeover"]


def percentile(values, q):
    if not values:
        return None
    v = sorted(values)
    k = (len(v) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def run(cmd, timeout):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e:
        return -9, e.stdout or "", f"timeout after {timeout} s"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bin", required=True, help="build directory (exchange_failover_trial, journal tools)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--classes", default=",".join(CLASSES))
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--seed-base", type=int, default=1)
    for k in ("t-d-ms", "t-ack-ms", "rto-ms", "tie-break-ms", "heartbeat-ms", "phase1", "phase2", "phase3"):
        ap.add_argument("--" + k, type=int)
    ap.add_argument("--timeout", type=int, default=600, help="seconds per trial")
    ap.add_argument("--keep", action="store_true", help="keep passing trial directories too")
    ap.add_argument("--repl-thread", action="store_true", help="the replica on its own thread (split mode)")
    ap.add_argument("--label", default="", help="where this ran (e.g. mac, vm)")
    args = ap.parse_args(argv)
    trial_bin = os.path.join(args.bin, "tests/integration/exchange/exchange_failover_trial")
    if not os.access(trial_bin, os.X_OK):
        print(f"run_trials: {trial_bin} not found (build exchange_failover_trial)", file=sys.stderr)
        return 2
    classes = [c for c in args.classes.split(",") if c]
    unknown = [c for c in classes if c not in CLASSES]
    if unknown:
        print(f"run_trials: unknown classes {unknown}; known: {CLASSES}", file=sys.stderr)
        return 2
    os.makedirs(args.out, exist_ok=True)
    extra = []
    for k in ("t_d_ms", "t_ack_ms", "rto_ms", "tie_break_ms", "heartbeat_ms", "phase1", "phase2", "phase3"):
        v = getattr(args, k)
        if v is not None:
            extra += ["--" + k.replace("_", "-"), str(v)]
    if args.repl_thread:
        extra.append("--repl-thread")
    summary = {"label": args.label, "timestamps": "software (indicative only)", "trial_args": extra,
               "started": time.strftime("%Y-%m-%dT%H:%M:%S"), "classes": {}}
    all_ok = True
    for cls in classes:
        rows = []
        for i in range(args.trials):
            seed = args.seed_base + i
            tdir = os.path.join(args.out, cls, f"trial-{seed:05d}")
            t0 = time.time()
            code, out, err = run([trial_bin, "--class", cls, "--seed", str(seed), "--out", tdir] + extra, args.timeout)
            row = {"seed": seed, "dir": tdir, "trial_exit": code, "wall_s": round(time.time() - t0, 3)}
            try:
                with open(os.path.join(tdir, "trial.json")) as f:
                    trial = json.load(f)
            except (OSError, ValueError):
                trial = {"pass": False, "violations": [f"no trial.json (exit {code}): {err.strip()[:500]}"],
                         "ms": {}, "num": {}}
            row["trial_pass"] = bool(trial.get("pass"))
            row["violations"] = list(trial.get("violations", []))
            row["ms"] = dict(trial.get("ms", {}))
            if trial.get("str", {}).get("final_primary_journal"):
                c2, o2, e2 = run([sys.executable, os.path.join(HERE, "check_trial_oracles.py"), tdir, "--bin", args.bin],
                                 args.timeout)
                row["oracles_pass"] = c2 == 0
                try:
                    row["violations"] += [f"[checker] {v}" for v in json.loads(o2).get("violations", [])]
                except ValueError:
                    row["violations"].append(f"[checker] exit {c2}: {e2.strip()[:500]}")
                num = trial.get("num", {})
                if cls.startswith("F1") and "t_fault_ns" in num:
                    c3, o3, _ = run([sys.executable, os.path.join(HERE, "analyze_pcap.py"),
                                     os.path.join(tdir, "capture.pcap"), "--line-a", str(num["line_a_port"]),
                                     "--line-b", str(num["line_b_port"]), "--fault-ns", str(num["t_fault_ns"])],
                                    args.timeout)
                    try:
                        t = json.loads(o3).get("takeover") or {}
                        if t.get("t_takeover_ns") is not None:
                            row["ms"]["pcap_t_takeover"] = t["t_takeover_ns"] / 1e6
                    except ValueError:
                        pass
            else:
                row["oracles_pass"] = False
            ok = row["trial_pass"] and row["oracles_pass"] and code == 0
            row["pass"] = ok
            all_ok &= ok
            rows.append(row)
            print(f"{cls} seed {seed}: {'PASS' if ok else 'FAIL'} ({row['wall_s']} s)"
                  + ("" if ok else "  " + "; ".join(row["violations"])[:400]), flush=True)
            if ok and not args.keep:
                shutil.rmtree(tdir, ignore_errors=True)
        stats = {}
        for k in TIMINGS:
            vals = [r["ms"][k] for r in rows if k in r["ms"]]
            if vals:
                stats[k] = {"n": len(vals), "p50": percentile(vals, 0.5), "p90": percentile(vals, 0.9),
                            "p99": percentile(vals, 0.99), "max": max(vals)}
        summary["classes"][cls] = {"trials": len(rows), "passed": sum(r["pass"] for r in rows),
                                   "timings_ms": stats, "trials_detail": rows}
    summary["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    with open(os.path.join(args.out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print(f"{'class':14} {'trials':>6} {'passed':>6}  timings (ms, software: indicative)")
    for cls, c in summary["classes"].items():
        t = "; ".join(f"{k} p50 {v['p50']:.1f} max {v['max']:.1f}" for k, v in c["timings_ms"].items())
        print(f"{cls:14} {c['trials']:>6} {c['passed']:>6}  {t}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
