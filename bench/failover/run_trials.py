#!/usr/bin/env python3
"""Runs failover trials repeatedly and summarizes them (plan 10 §7, R-10; T25 in the lab).

Each trial is one process of exchange_failover_trial (tests/integration/exchange/
ha_trial.h): a primary, a backup and witnessd, the fault of its class, the rejoin of the
lost node, and the trial's own oracle checks. This runner then re-checks every trial
independently (check_trial_oracles.py), measures the line-A takeover from the capture
(analyze_pcap.py) and writes OUT/summary.json with, per class, the trial count, passes,
every violation, p50/p90/p99/max of the timings and the class's pass criteria.

Two deployments:
  on this host (default): the nodes are local processes, the A-B link a relay, and the
      capture the subscriber's own (kernel software timestamps). Functional only: the
      timings are indicative, never T25 evidence.
  --lab LAB.toml: hosts A and B run the nodes (lab/failover/t25_node.sh over ssh, or in
      the network namespaces of lab/failover/vm_netns.sh for the VM dry run), this host is
      C: witnessd, the clients and the line capture (tcpdump; in the lab with NIC hardware
      timestamps). The runner refuses a lab file with TBD_ values; it renders both nodes'
      configurations (exchange_failover_trial --render-config) and deploys them first.
      T25 evidence needs a lab file with t25 = true and timestamps = "hardware", 0 capture
      drops in every trial, and per class the N of METHODOLOGY §17.

Classes (plan 10 §7): F1 SIGKILL primary, F1-partial, F1-divergent, F2 SIGSTOP primary
(SIGCONT after the takeover: it must exit as deposed), F3 every data NIC of the primary
down (lab), F4 kernel panic on the primary's host (lab), F5 BMC power off (lab), F6 A-B
link cut, F7 SIGKILL backup, F7-resume, F8 witnessd killed, F9 F1 while snapshotd writes
a snapshot, F10 F1 under the T20 paired-mode load (lab, M14).

Pass criteria (METHODOLOGY §17, plan 10 §7), per class, reported in summary.json:
  takeover classes (F1-F5, F9, F10): N >= 1,000 (F5 >= 100); max T_takeover < 50 ms;
      F2, F3: the deposed node exits with 3 and sends no output of the new epoch;
  F6, F7: N >= 200; solo mode on A in every trial (one SOLO grant, nothing else); release
      stall <= T_ack + 5 ms (probe orders needed: --probe-us);
  F8: N >= 200; no epoch change; service continues; "alarm within 10 ms" cannot be met:
      the replica does not watch the witness between requests (reported as unsupported);
  every trial: 0 oracle violations.
On this host the N and the timing bound are reported but not applied (verdict "functional").

Usage:
  run_trials.py --bin BUILD_DIR --out OUT [--classes F1,F6,...] [--trials N] [--trials-F5 N]
                [--seed-base S] [--t-d-ms N --t-ack-ms N --rto-ms N --tie-break-ms N --heartbeat-ms N]
                [--t-w-ms N] [--phase1 N --phase2 N --phase3 N] [--probe-us N] [--repl-thread]
                [--lab LAB.toml] [--keep] [--label TEXT]
Exit status: 0 every trial passed both checks, 1 otherwise, 2 usage, 3 the lab is not
described (TBD_ values).
"""
import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
LOCAL_CLASSES = ["F1", "F1-partial", "F1-divergent", "F2", "F6", "F7", "F7-resume", "F8", "F9"]
LAB_CLASSES = ["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F1-partial", "F1-divergent",
               "F7-resume"]
TAKEOVER = {"F1", "F1-partial", "F1-divergent", "F2", "F3", "F4", "F5", "F9", "F10"}
SOLO = {"F6", "F7", "F7-resume"}
REQUIRED_N = {"F1": 1000, "F2": 1000, "F3": 1000, "F4": 1000, "F5": 100, "F6": 200, "F7": 200, "F8": 200,
              "F9": 1000, "F10": 1000}
PASS_MAX_MS = 50.0
PROBE_PRICE = 1_490_000  # Prober::kPrice (ha_trial.h): ITCH price, 4 decimals
TIMINGS = ["t_takeover", "t_new", "t_first_new_order_ack", "fault_to_first_line_a", "fault_to_solo_primary",
           "release_stall", "restart_to_paired", "restart_to_resumed", "host_back", "nlog_freeze_to_request",
           "nlog_request_to_grant", "xclock_fault_to_freeze"]


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


# ---- the lab description --------------------------------------------------------------------

def tbd_values(obj, prefix=""):
    """Every TBD_ value of the parsed TOML, as 'key = value'."""
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += tbd_values(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += tbd_values(v, f"{prefix}[{i}]")
    elif isinstance(obj, str) and "TBD_" in obj:
        out.append(f"{prefix} = {obj}")
    return out


def lab_spec(lab, build, out_dir, classes=()):
    """The key = value description exchange_failover_trial reads (ha_trial.h LabSpec), and
    the configuration deployments (local path, node key). With F9 among the classes the
    nodes mark a snapshot every 1,000 records, so snapshotd is writing one often enough
    for node.A.kill_during_snapshot to catch it."""
    sub = {"repo": REPO, "build": os.path.abspath(build)}

    def fill(s):
        for k, v in sub.items():
            s = s.replace("{" + k + "}", v)
        return s

    repo, nbuild, state = fill(lab["repo"]), fill(lab["build"]), lab.get("state", "/var/tmp/lle-t25")
    c, lines = lab["c"], lab["lines"]
    group_a, group_b = lines["a"].rsplit(":", 1)[0], lines["b"].rsplit(":", 1)[0]
    spec = {
        "lab.name": lab.get("name", "lab"),
        "lab.timestamps": lab.get("timestamps", "software"),
        "lab.t25": "1" if lab.get("t25") else "0",
        "c.ip": c["ip"],
        "witness.listen": f"{c['ip']}:{c.get('witness_port', 7400)}",
        "lines.a": lines["a"],
        "lines.b": lines["b"],
        "capture.start": c["capture_start"].replace("{iface}", c["capture_iface"]).replace("{group_a}", group_a)
                                           .replace("{group_b}", group_b),
        "capture.stop": c["capture_stop"],
        "capture.settle_ms": str(c.get("capture_settle_ms", 1000)),
    }
    overrides = list(lab.get("common_overrides", []))
    if "F9" in classes and not any(o.replace(" ", "").startswith("journal.snapshot_every=") for o in overrides):
        overrides.append("journal.snapshot_every = 1000")
    for i, o in enumerate(overrides):
        spec[f"common.override.{i}"] = o
    if lab.get("link", {}).get("cut"):
        spec["link.cut"] = lab["link"]["cut"]
        spec["link.heal"] = lab["link"]["heal"]
    if lab.get("load", {}).get("start"):
        spec["load.start"] = lab["load"]["start"]
        spec["load.stop"] = lab["load"]["stop"]
    emulate = bool(lab.get("emulate_host_faults"))
    ssh_opts = lab.get("ssh_options", "")
    deploys = []
    for x, key in (("A", "a"), ("B", "b")):
        h = lab[key]
        pre = f"node.{x}."
        ssh = h.get("ssh", "")
        remote = f"ssh {ssh_opts} {shlex.quote(ssh)} " if ssh else ""
        args = [f"--state {shlex.quote(state + '/' + x)}", f"--build {shlex.quote(nbuild)}",
                f"--conf {shlex.quote(h['conf'])}"]
        if h.get("netns"):
            args.append(f"--netns {shlex.quote(h['netns'])}")
        if h.get("nics"):
            args.append(f"--nics {shlex.quote(' '.join(h['nics']))}")
        if h.get("nics_restore"):
            args.append(f"--nics-restore {shlex.quote(h['nics_restore'])}")
        if emulate:
            args.append("--emulate-host-faults")
        script = f"{h.get('sudo', '')} bash {repo}/lab/failover/t25_node.sh {' '.join(args)}".strip()
        # Over ssh the whole command line is one argument of the remote shell.
        base = (remote + shlex.quote(script)) if ssh else script

        def cmd(rest, base=base, ssh=ssh, script=script, remote=remote):
            return (remote + shlex.quote(script + " " + rest)) if ssh else script + " " + rest

        spec.update({
            pre + "ip": h["ip"], pre + "repl": h["repl"], pre + "data_dir": h["data_dir"],
            pre + "start": cmd("start {fresh}"),
            pre + "kill9": cmd("signal KILL"), pre + "stop": cmd("signal STOP"), pre + "cont": cmd("signal CONT"),
            pre + "exit_code": cmd("exit-code"), pre + "output": cmd("output"),
            pre + "collect": f"mkdir -p {{dest}}/journal && {cmd('pack-journal')} | tar -x -C {{dest}}/journal && "
                             f"{cmd('pack-nlog')} > {{dest}}/node.nlog && {cmd('output')} > {{dest}}/node.out",
            pre + "nics_down": cmd("nics down"), pre + "nics_up": cmd("nics up"),
            pre + "panic": cmd("panic"),
            pre + "kill_during_snapshot": cmd("kill-during-snapshot"),
            pre + "snapshotd_start": cmd("snapshotd start"), pre + "snapshotd_stop": cmd("snapshotd stop"),
        })
        if emulate:
            spec[pre + "power_off"] = cmd("signal KILL")
            spec[pre + "power_on"] = "true"
            spec[pre + "wait_up"] = "true"
        else:
            spec[pre + "power_off"] = h.get("power_off", "")
            spec[pre + "power_on"] = h.get("power_on", "")
            probe = f"ssh {ssh_opts} {shlex.quote(ssh)} true" if ssh else "true"
            spec[pre + "wait_up"] = f"for i in $(seq 1 900); do {probe} 2>/dev/null && exit 0; sleep 1; done; exit 1"
        for name, port in h.get("ports", {}).items():
            spec[f"{pre}port.{name}"] = str(port)
        for i, o in enumerate(h.get("overrides", [])):
            spec[f"{pre}override.{i}"] = o
        local_conf = os.path.join(out_dir, f"ha{x}.conf")
        dep = lab.get("deploy", "scp -q {local} {ssh}:{remote}")
        deploys.append((x, local_conf, dep.replace("{local}", shlex.quote(local_conf)).replace("{ssh}", ssh)
                        .replace("{remote}", shlex.quote(h["conf"]))))
    return spec, deploys


def write_spec(spec, path):
    with open(path, "w") as f:
        f.write("# exchange_failover_trial --lab-spec (written by bench/failover/run_trials.py --lab)\n")
        for k in sorted(spec):
            f.write(f"{k} = {spec[k]}\n")


# ---- per trial ------------------------------------------------------------------------------

def analyze(row, trial, tdir, lab, cls, args):
    """analyze_pcap.py on the trial's capture: T_takeover, T_new, the deposed node's late
    output (F2, F3), the release stall (F6, F7)."""
    num, strs = trial.get("num", {}), trial.get("str", {})
    hardware = bool(lab) and lab.get("timestamps") == "hardware"
    line_a = strs.get("line_a") or str(num.get("line_a_port", ""))
    line_b = strs.get("line_b") or str(num.get("line_b_port", ""))
    if lab:
        old, new = strs.get("sender_a_ip"), strs.get("sender_b_ip")
    else:
        old, new = f":{num.get('sender_a_port')}", f":{num.get('sender_b_port')}"
    cmd = [sys.executable, os.path.join(HERE, "analyze_pcap.py"), os.path.join(tdir, "capture.pcap"),
           "--line-a", line_a, "--line-b", line_b, "--old-sender", old,
           "--timestamps", "hardware" if hardware else "software",
           "--capture-drops", str(num.get("capture_drops", 0 if not lab else -1))]
    if cls in TAKEOVER:
        cmd += ["--takeover", "--new-sender", new]
        if not hardware and "t_fault_ns" in num:
            cmd += ["--fault-ns", str(num["t_fault_ns"]), "--fault-done-ns", str(num.get("t_fault_done_ns", num["t_fault_ns"]))]
        if "new_epoch_first_itch_seq" in num:
            cmd += ["--new-epoch-seq", str(num["new_epoch_first_itch_seq"])]
    if cls in SOLO and args.probe_us:
        cmd += ["--probe-price", str(PROBE_PRICE)]
    code, out, err = run(cmd, args.timeout)
    try:
        rep = json.loads(out)
    except ValueError:
        row["violations"].append(f"[analyze] exit {code}: {err.strip()[:300]}")
        return
    row["capture_valid"] = rep.get("valid", False)
    t = rep.get("takeover") or {}
    if t.get("t_takeover_ns") is not None:
        row["ms"]["t_takeover"] = t["t_takeover_ns"] / 1e6  # the capture's (the trial's own is software)
        row["takeover_method"] = t.get("method")
    elif cls in TAKEOVER:
        row["violations"].append("[analyze] no takeover in the capture")
    if t.get("t_new_ns") is not None:
        row["ms"]["t_new"] = t["t_new_ns"] / 1e6
    if cls in ("F2", "F3") and t.get("old_sender_new_epoch_packets"):
        row["violations"].append(f"[analyze] the deposed primary sent {t['old_sender_new_epoch_packets']} packets "
                                 "with output of the new epoch")
    rel = rep.get("release")
    if rel:
        row["ms"]["release_stall"] = rel["release_stall_ns"] / 1e6


def run_trial(trial_bin, cls, seed, tdir, extra, args, lab):
    t0 = time.time()
    code, out, err = run([trial_bin, "--class", cls, "--seed", str(seed), "--out", tdir] + extra, args.timeout)
    row = {"seed": seed, "dir": tdir, "trial_exit": code, "wall_s": round(time.time() - t0, 3)}
    try:
        with open(os.path.join(tdir, "trial.json")) as f:
            trial = json.load(f)
    except (OSError, ValueError):
        trial = {"pass": False, "violations": [f"no trial.json (exit {code}): {err.strip()[:500]}"], "ms": {}, "num": {}}
    row["trial_pass"] = bool(trial.get("pass"))
    row["violations"] = list(trial.get("violations", []))
    row["notes"] = list(trial.get("notes", []))
    row["ms"] = dict(trial.get("ms", {}))
    num = trial.get("num", {})
    row["num"] = {k: num[k] for k in ("capture_drops", "grants_promote", "grants_solo", "grants_join", "grants_resume",
                                      "deposed_exit_code", "snapshot_in_progress", "probes_sent", "probes_late",
                                      "orders_resent", "rejoin_truncated") if k in num}
    if trial.get("str", {}).get("final_primary_journal"):
        c2, o2, e2 = run([sys.executable, os.path.join(HERE, "check_trial_oracles.py"), tdir, "--bin", args.bin],
                         args.timeout)
        row["oracles_pass"] = c2 == 0
        try:
            row["violations"] += [f"[checker] {v}" for v in json.loads(o2).get("violations", [])]
        except ValueError:
            row["violations"].append(f"[checker] exit {c2}: {e2.strip()[:500]}")
        analyze(row, trial, tdir, lab, cls, args)
    else:
        row["oracles_pass"] = False
    row["pass"] = row["trial_pass"] and row["oracles_pass"] and code == 0 and not any(
        v.startswith("[analyze]") for v in row["violations"])
    return row


# ---- per class ------------------------------------------------------------------------------

def criteria(cls, rows, lab, args, t_ack_ms):
    """The class's pass criteria (module comment): name -> {"ok": True|False|None, "detail"}.
    None: not applicable here or not supported."""
    c = {}
    n = len(rows)
    need = REQUIRED_N.get(cls)
    on_lab = bool(lab)
    c["oracles"] = {"ok": all(r["oracles_pass"] and r["trial_pass"] for r in rows),
                    "detail": f"{sum(r['pass'] for r in rows)} of {n} trials passed every check"}
    if need is not None:
        c["trials"] = {"ok": (n >= need) if on_lab else None, "detail": f"{n} trials (N >= {need})"}
    if cls in TAKEOVER:
        vals = [r["ms"]["t_takeover"] for r in rows if "t_takeover" in r["ms"]]
        mx = max(vals) if vals else None
        c["max_t_takeover"] = {"ok": (mx is not None and mx < PASS_MAX_MS and len(vals) == n) if on_lab else None,
                               "detail": f"max {mx:.3f} ms over {len(vals)} trials (< {PASS_MAX_MS} ms)" if mx is not None
                               else "no T_takeover"}
    if cls in ("F2", "F3"):
        ok = all(r["num"].get("deposed_exit_code") == 3 for r in rows)
        c["deposed"] = {"ok": ok, "detail": "the cut-off primary exited with 3 and sent no output of the new epoch"}
    if cls in SOLO:
        ok = all(r["num"].get("grants_solo") == 1 and r["num"].get("grants_promote") == 0 for r in rows)
        c["solo_mode"] = {"ok": ok, "detail": "one SOLO grant and no PROMOTE in every trial"}
        stalls = [r["ms"]["release_stall"] for r in rows if "release_stall" in r["ms"]]
        bound = t_ack_ms + 5.0
        if stalls:
            c["release_stall"] = {"ok": (max(stalls) <= bound and len(stalls) == n) if on_lab else None,
                                  "detail": f"max {max(stalls):.3f} ms over {len(stalls)} trials (<= T_ack + 5 = {bound} ms)"}
        else:
            c["release_stall"] = {"ok": False if on_lab else None,
                                  "detail": "not measured (needs --probe-us: probe orders mark the release stream)"}
    if cls == "F8":
        ok = all(not any(r["num"].get(k, 0) for k in ("grants_promote", "grants_solo", "grants_join", "grants_resume"))
                 for r in rows)
        c["no_epoch_change"] = {"ok": ok, "detail": "no grant in any trial"}
        c["service_continues"] = {"ok": all(r["trial_pass"] for r in rows),
                                  "detail": "both roles unchanged and phase 2 traded on both nodes"}
        c["alarm_within_10ms"] = {"ok": None, "detail": "unsupported: the replica does not watch the witness between "
                                                        "requests, so there is no witness-loss alarm"}
    if on_lab:
        drops = [r["num"].get("capture_drops", -1) for r in rows]
        c["capture"] = {"ok": all(d == 0 for d in drops),
                        "detail": f"capture drops per trial: {sorted(set(drops))} (a trial with any drop, or no report, is invalid)"}
    return c


def verdict(cls, crit, lab):
    if not lab:
        return "functional" if crit["oracles"]["ok"] else "fail"
    if any(v["ok"] is False for v in crit.values()):
        return "fail"
    if any(v["ok"] is None for v in crit.values()):
        return "incomplete"
    return "pass"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bin", required=True, help="build directory (exchange_failover_trial, journal tools)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--classes")
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--trials-F5", dest="trials_f5", type=int, help="trials of F5 (default: --trials)")
    ap.add_argument("--seed-base", type=int, default=1)
    for k in ("t-d-ms", "t-ack-ms", "rto-ms", "tie-break-ms", "heartbeat-ms", "phase1", "phase2", "phase3", "probe-us"):
        ap.add_argument("--" + k, type=int)
    ap.add_argument("--t-w-ms", type=int, help="witness tie-break T_w (= --tie-break-ms)")
    ap.add_argument("--timeout", type=int, default=900, help="seconds per trial")
    ap.add_argument("--keep", action="store_true", help="keep passing trial directories too")
    ap.add_argument("--repl-thread", action="store_true", help="the replica on its own thread (split mode)")
    ap.add_argument("--lab", help="the lab description (lab/failover/t25-lab.toml, or vm-dryrun.toml)")
    ap.add_argument("--label", default="", help="where this ran (e.g. mac, vm)")
    args = ap.parse_args(argv)
    if args.t_w_ms is not None:
        args.tie_break_ms = args.t_w_ms
    trial_bin = os.path.join(args.bin, "tests/integration/exchange/exchange_failover_trial")
    if not os.access(trial_bin, os.X_OK):
        print(f"run_trials: {trial_bin} not found (build exchange_failover_trial)", file=sys.stderr)
        return 2
    lab = None
    if args.lab:
        import tomllib
        with open(args.lab, "rb") as f:
            lab = tomllib.load(f)
        tbd = tbd_values(lab)
        if tbd:
            print(f"run_trials: refusing: {args.lab} does not describe the lab yet (METHODOLOGY §18):", file=sys.stderr)
            for t in tbd:
                print(f"  {t}", file=sys.stderr)
            return 3
    known = LAB_CLASSES if lab else LOCAL_CLASSES
    classes = [c for c in (args.classes or ",".join(known)).split(",") if c]
    unknown = [c for c in classes if c not in known]
    if unknown:
        print(f"run_trials: unknown classes {unknown}; known{' (lab)' if lab else ''}: {known}", file=sys.stderr)
        return 2
    os.makedirs(args.out, exist_ok=True)
    extra = []
    for k in ("t_d_ms", "t_ack_ms", "rto_ms", "tie_break_ms", "heartbeat_ms", "phase1", "phase2", "phase3", "probe_us"):
        v = getattr(args, k)
        if v is not None:
            extra += ["--" + k.replace("_", "-"), str(v)]
    if args.repl_thread:
        extra.append("--repl-thread")
    t_ack_ms = args.t_ack_ms if args.t_ack_ms is not None else 1000
    summary = {"label": args.label, "started": time.strftime("%Y-%m-%dT%H:%M:%S"), "trial_args": extra,
               "deployment": "lab" if lab else "local", "classes": {}}
    if lab:
        spec, deploys = lab_spec(lab, args.bin, os.path.abspath(args.out), classes)
        spec_path = os.path.join(os.path.abspath(args.out), "lab.spec")
        write_spec(spec, spec_path)
        for x, local_conf, dep in deploys:
            code, out, err = run([trial_bin, "--render-config", x, "--lab-spec", spec_path] + extra, 60)
            if code != 0:
                print(f"run_trials: rendering node {x}'s configuration failed: {err}", file=sys.stderr)
                return 2
            with open(local_conf, "w") as f:
                f.write(out)
            code, out2, err2 = run(["/bin/sh", "-c", dep], 120)
            if code != 0:
                print(f"run_trials: deploying node {x}'s configuration failed ({dep}): {out2}{err2}", file=sys.stderr)
                return 2
        extra += ["--lab-spec", spec_path]
        valid = lab.get("t25") is True and lab.get("timestamps") == "hardware"
        summary.update({"lab": lab.get("name"), "lab_file": os.path.abspath(args.lab),
                        "timestamps": lab.get("timestamps"),
                        "emulated_host_faults": bool(lab.get("emulate_host_faults")),
                        "t25_lab": valid})
    else:
        summary["timestamps"] = "software (kernel receive times; indicative only)"
    all_ok = True
    for cls in classes:
        n_trials = args.trials_f5 if (cls == "F5" and args.trials_f5) else args.trials
        rows = []
        for i in range(n_trials):
            seed = args.seed_base + i
            tdir = os.path.join(os.path.abspath(args.out), cls, f"trial-{seed:05d}")
            row = run_trial(trial_bin, cls, seed, tdir, extra, args, lab)
            all_ok &= row["pass"]
            rows.append(row)
            print(f"{cls} seed {seed}: {'PASS' if row['pass'] else 'FAIL'} ({row['wall_s']} s)"
                  + ("" if row["pass"] else "  " + "; ".join(row["violations"])[:400]), flush=True)
            if row["pass"] and not args.keep:
                shutil.rmtree(tdir, ignore_errors=True)
        stats = {}
        for k in TIMINGS:
            vals = [r["ms"][k] for r in rows if k in r["ms"]]
            if vals:
                stats[k] = {"n": len(vals), "p50": percentile(vals, 0.5), "p90": percentile(vals, 0.9),
                            "p99": percentile(vals, 0.99), "max": max(vals)}
        crit = criteria(cls, rows, lab, args, t_ack_ms)
        entry = {"trials": len(rows), "passed": sum(r["pass"] for r in rows), "timings_ms": stats,
                 "criteria": crit, "verdict": verdict(cls, crit, lab), "trials_detail": rows}
        if lab:
            entry["valid_for_t25"] = (summary["t25_lab"] and entry["verdict"] == "pass"
                                      and not (cls in ("F4", "F5") and summary["emulated_host_faults"]))
        summary["classes"][cls] = entry
    summary["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    with open(os.path.join(args.out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    print(f"{'class':14} {'trials':>6} {'passed':>6}  {'verdict':10} timings (ms)")
    for cls, c in summary["classes"].items():
        t = "; ".join(f"{k} p50 {v['p50']:.1f} max {v['max']:.1f}" for k, v in c["timings_ms"].items()
                      if k in ("t_takeover", "t_new", "fault_to_solo_primary", "release_stall", "restart_to_paired",
                               "restart_to_resumed"))
        print(f"{cls:14} {c['trials']:>6} {c['passed']:>6}  {c['verdict']:10} {t}")
    if lab and not summary["t25_lab"]:
        print(f"run_trials: {summary['lab']}: not the T25 lab (t25 = false or software timestamps): never T25 evidence")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
