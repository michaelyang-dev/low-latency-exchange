#!/usr/bin/env python3
"""Re-checks the oracles of one failover trial from its artifacts (plan 10 §7-§8, R-10).

A trial directory (written by exchange_failover_trial, tests/integration/exchange/
ha_trial.h; in the lab by the clients and the capture host) holds:
  trial.json        class, session ids, phases, line ports, fault time, grants, journals
  clients/USER.N.bin  each connection's sequenced OUCH stream ([u16 BE length][message]);
                    clients/DELTA.bin the prober's one connection, if it ran
  feed.bin          the feed the subscriber assembled (NASDAQ BinaryFILE)
  capture.pcap      every line packet as received (the lab: host C's hardware capture)
  both nodes' journals (trial.json names them; the lab's are copied into the trial)

This script checks, independently of the trial's own verdict:
  O-LEDGER   every order accepted exactly once, every execution reported once to each
             side, fills add up (crossing pairs: 100 each; F1-partial: the resting order
             filled by every buy);
  O-STREAM   each session's two connections agree where they overlap and the session's
             stream equals journal_replay --emit-ouch of the final primary's journal
             (the prober's too; its probes are accepted at most once, never executed);
  O-MOLD     the assembled feed equals journal_replay --emit of the final primary's
             journal; every line packet from every sender carries the feed's bytes at its
             sequence numbers; per line and sender, sequence numbers never step back;
  O-JOURNAL  journal_diff of the two journals reports them identical (after a rejoin, and
             after F8, where nobody was lost);
  O-CLASS    the witness grants recorded in trial.json fit the class: one PROMOTE for a
             takeover (F1*, F2-F5, F9, F10), one SOLO for F6/F7*, nothing for F8; then
             one JOIN if the lost node rejoined; RESUME only for F7-resume; the cut-off
             node of F2, F3 and F6 exited as deposed (3).

Usage:
  check_trial_oracles.py TRIAL_DIR [--bin BUILD_DIR | --journal-replay P --journal-diff P]
Prints a JSON verdict. Exit status: 0 all oracles hold, 1 a violation, 2 usage or a
missing artifact.
"""
import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze_pcap  # noqa: E402


def framed(path):
    """[u16 BE length][message]... -> list of messages (a zero-length record ends it)."""
    with open(path, "rb") as f:
        data = f.read()
    out, at = [], 0
    while at + 2 <= len(data):
        n = struct.unpack(">H", data[at:at + 2])[0]
        at += 2
        if n == 0:
            break
        out.append(data[at:at + n])
        at += n
    return out


def ouch_by_session(path):
    """journal_replay --emit-ouch: [u32 BE session][u16 BE length][message]..."""
    with open(path, "rb") as f:
        data = f.read()
    out, at = {}, 0
    while at + 6 <= len(data):
        sid, n = struct.unpack(">IH", data[at:at + 6])
        at += 6
        out.setdefault(sid, []).append(data[at:at + n])
        at += n
    return out


def ledger(msgs):
    accepted, executions, filled = {}, {}, {}
    for m in msgs:
        t = chr(m[0]) if m else "?"
        if t == "A":
            urn = struct.unpack(">I", m[9:13])[0]
            accepted[urn] = accepted.get(urn, 0) + 1
        elif t == "E":
            urn, qty = struct.unpack(">II", m[9:17])
            match = struct.unpack(">Q", m[26:34])[0]
            executions[match] = executions.get(match, 0) + 1
            filled[urn] = filled.get(urn, 0) + qty
    return accepted, executions, filled


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("trial_dir")
    ap.add_argument("--bin", help="build directory holding apps/journal_replay and apps/journal_diff")
    ap.add_argument("--journal-replay")
    ap.add_argument("--journal-diff")
    args = ap.parse_args(argv)
    replay = args.journal_replay or (args.bin and os.path.join(args.bin, "apps/journal_replay/journal_replay"))
    diff = args.journal_diff or (args.bin and os.path.join(args.bin, "apps/journal_diff/journal_diff"))
    if not replay or not diff:
        print("check_trial_oracles: give --bin or both --journal-replay and --journal-diff", file=sys.stderr)
        return 2
    d = args.trial_dir
    try:
        with open(os.path.join(d, "trial.json")) as f:
            trial = json.load(f)
    except (OSError, ValueError) as e:
        print(f"check_trial_oracles: {e}", file=sys.stderr)
        return 2
    cls, num, strs = trial["class"], trial["num"], trial["str"]
    violations = []

    def fail(msg):
        violations.append(msg)

    # Regeneration of the final primary's journal.
    final_journal = strs.get("final_primary_journal")
    if not final_journal or not os.path.isdir(final_journal):
        print("check_trial_oracles: trial.json names no final primary journal (the trial did not finish)",
              file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        itch_path, ouch_path = os.path.join(tmp, "itch.bin"), os.path.join(tmp, "ouch.bin")
        r = subprocess.run([replay, final_journal, "--emit", itch_path, "--emit-ouch", ouch_path],
                           capture_output=True, text=True)
        if r.returncode != 0:
            fail(f"journal_replay failed ({r.returncode}): {r.stdout}{r.stderr}")
            regen_itch, regen_ouch = [], {}
        else:
            regen_itch, regen_ouch = framed(itch_path), ouch_by_session(ouch_path)

    # O-STREAM and O-LEDGER.
    sessions = {"ALPHA": num.get("session_ALPHA", 1), "BRAVO": num.get("session_BRAVO", 2)}
    streams = {}
    for user, sid in sessions.items():
        conns = [framed(os.path.join(d, "clients", f"{user}.{n}.bin")) for n in ("A", "B")]
        common = min(len(c) for c in conns)
        for i in range(common):
            if conns[0][i] != conns[1][i]:
                fail(f"O-STREAM: {user}: the two connections differ at sequence {i + 1}")
                break
        streams[user] = max(conns, key=len)
        if regen_ouch and regen_ouch.get(sid, []) != streams[user]:
            fail(f"O-STREAM: {user}: stream differs from the regeneration "
                 f"({len(streams[user])} vs {len(regen_ouch.get(sid, []))} messages)")
    if num.get("session_DELTA"):
        d_path = os.path.join(d, "clients", "DELTA.bin")
        delta = framed(d_path) if os.path.exists(d_path) else None
        if delta is None:
            fail("O-STREAM: DELTA: clients/DELTA.bin missing")
        else:
            if regen_ouch and regen_ouch.get(num["session_DELTA"], []) != delta:
                fail(f"O-STREAM: DELTA: stream differs from the regeneration "
                     f"({len(delta)} vs {len(regen_ouch.get(num['session_DELTA'], []))} messages)")
            ld, ed, _ = ledger(delta)
            if any(c != 1 for c in ld.values()):
                fail("O-LEDGER: DELTA: a probe accepted more than once")
            if ed:
                fail("O-LEDGER: DELTA: probes executed")
    n = num.get("phase1", 0) + num.get("phase2", 0) + num.get("phase3", 0)
    la, ea, fa = ledger(streams["ALPHA"])
    lb, eb, fb = ledger(streams["BRAVO"])
    if num.get("partial"):
        if la.get(1) != 1:
            fail(f"O-LEDGER: ALPHA's resting order accepted {la.get(1, 0)} times")
        if fa.get(1) != n * 100:
            fail(f"O-LEDGER: ALPHA's resting order filled {fa.get(1, 0)} of {n * 100}")
        if set(la) != {1}:
            fail("O-LEDGER: ALPHA has unexpected orders")
    else:
        for u in range(1, n + 1):
            if la.get(u) != 1 or fa.get(u) != 100:
                fail(f"O-LEDGER: ALPHA urn {u}: accepted {la.get(u, 0)}, filled {fa.get(u, 0)}")
    for u in range(1, n + 1):
        if lb.get(u) != 1 or fb.get(u) != 100:
            fail(f"O-LEDGER: BRAVO urn {u}: accepted {lb.get(u, 0)}, filled {fb.get(u, 0)}")
    both = dict(ea)
    for m, c in eb.items():
        both[m] = both.get(m, 0) + c
    if len(both) != n:
        fail(f"O-LEDGER: {len(both)} match numbers for {n} fills")
    bad = [m for m, c in both.items() if c != 2]
    if bad:
        fail(f"O-LEDGER: {len(bad)} match numbers not reported exactly once to each side (first {bad[0]})")

    # O-MOLD.
    feed = framed(os.path.join(d, "feed.bin"))
    if regen_itch and feed != regen_itch:
        fail(f"O-MOLD: the assembled feed ({len(feed)}) differs from the regeneration ({len(regen_itch)})")
    # The lab's lines are multicast groups (trial.json str.line_a/line_b "IP:PORT").
    line_a = analyze_pcap.parse_endpoint(strs["line_a"]) if strs.get("line_a") else (None, int(num["line_a_port"]))
    line_b = analyze_pcap.parse_endpoint(strs["line_b"]) if strs.get("line_b") else (None, int(num["line_b_port"]))
    packets = analyze_pcap.line_packets(os.path.join(d, "capture.pcap"), line_a, line_b)
    mismatches = 0
    for p in packets:
        if p["malformed"]:
            fail(f"O-MOLD: malformed packet on line {p['line']} from {p['sender']}")
            continue
        for i, m in enumerate(p["msgs"]):
            s = p["seq"] + i
            if s < 1 or s > len(feed) or feed[s - 1] != m:
                mismatches += 1
    if mismatches:
        fail(f"O-MOLD: {mismatches} line messages differ from the feed")
    senders = analyze_pcap.summarize(packets)
    for s in senders:
        if s["back_steps"]:
            fail(f"O-MOLD: line {s['line']} sender {s['sender']} stepped back {s['back_steps']} times")

    # O-JOURNAL.
    if num.get("rejoin") or cls == "F8":
        r = subprocess.run([diff, strs["journal_a"], strs["journal_b"]], capture_output=True, text=True)
        if r.returncode != 0:
            fail(f"O-JOURNAL: journals differ after the rejoin: {r.stdout.strip()}")

    # O-CLASS.
    g = {k: num.get("grants_" + k, 0) for k in ("promote", "solo", "join", "resume")}
    takeover = cls.startswith("F1") or cls in ("F2", "F3", "F4", "F5", "F9", "F10")
    solo = cls in ("F6", "F7", "F7-resume")
    if takeover and (g["promote"] != 1 or g["solo"] != 0):
        fail(f"O-CLASS: {cls} expects one PROMOTE and no SOLO grant: {g}")
    if solo and (g["promote"] != 0 or g["solo"] != 1):
        fail(f"O-CLASS: {cls} expects one SOLO and no PROMOTE grant (no takeover): {g}")
    if cls == "F8" and any(g.values()):
        fail(f"O-CLASS: F8 expects no grant at all (no epoch change): {g}")
    if num.get("rejoin") and g["join"] != 1:
        fail(f"O-CLASS: one JOIN grant expected: {g}")
    if g["resume"] != (1 if cls == "F7-resume" else 0):
        fail(f"O-CLASS: unexpected RESUME grants: {g}")
    if cls in ("F2", "F3", "F6") and num.get("deposed_exit_code") != 3:
        fail(f"O-CLASS: {cls}: the cut-off node exited with {num.get('deposed_exit_code')} (deposed is 3)")

    verdict = {"trial_dir": d, "class": cls, "trial_pass": trial.get("pass"), "oracles_pass": not violations,
               "violations": violations, "feed_messages": len(feed), "line_packets": len(packets),
               "line_senders": [{k: s[k] for k in ("line", "sender", "packets", "messages", "forward_jumps",
                                                   "back_steps")} for s in senders]}
    print(json.dumps(verdict, indent=2))
    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main())
