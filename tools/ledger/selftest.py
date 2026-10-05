#!/usr/bin/env python3
"""Self-test for the DST ledger and campaign tooling (registered with ctest).

    python3 tools/ledger/selftest.py [--exsim path/to/exsim]

Without --exsim only the pure-Python parts run. With it, shrink.py and
tools/sim/campaign.py are exercised end to end against `exsim --canary`
(planted bugs: they never enter the real ledger). Writes only to a temp dir.
"""
from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "tools" / "sim"))
import campaign  # noqa: E402
import gen_ledger_md  # noqa: E402
import ledger  # noqa: E402
import shrink  # noqa: E402

EXAMPLE = HERE / "testdata" / "bugs.example.yaml"
checks = 0


def check(cond: bool, what: str) -> None:
    global checks
    if not cond:
        raise AssertionError(what)
    checks += 1


def py(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, cwd=REPO)


def test_ledger() -> None:
    data = ledger.load(EXAMPLE)
    check(ledger.validate(data) == [], f"example validates: {ledger.validate(data)}")
    check(len(ledger.counted(data)) == 1, "one counted bug in example")
    try:
        import yaml  # type: ignore

        check(ledger.parse_yaml_subset(EXAMPLE.read_text()) == yaml.safe_load(EXAMPLE.read_text()),
              "fallback parser agrees with PyYAML")
    except ImportError:
        pass
    real = ledger.load(ledger.DEFAULT_LEDGER)
    check(ledger.validate(real) == [], "sim/ledger/bugs.yaml validates")

    def errs(mut) -> list[str]:
        d = copy.deepcopy(data)
        mut(d)
        return ledger.validate(d)

    check(any("never counted" in e for e in errs(lambda d: d["bugs"][1].update(counted=True))),
          "counted canary is rejected")
    check(any("rule 5" in e for e in errs(lambda d: d["bugs"][0].pop("regression_test"))),
          "counted bug without regression test is rejected")
    check(any("dedup by fix" in e for e in errs(lambda d: d["bugs"].append(
        dict(copy.deepcopy(d["bugs"][0]), id="DST-003")))), "duplicate fix_sha is rejected")
    check(any("duplicate id" in e for e in errs(lambda d: d["bugs"].append(copy.deepcopy(d["bugs"][1])))),
          "duplicate id is rejected")
    check(any("missing required field 'seed'" in e for e in errs(lambda d: d["bugs"][0].pop("seed"))),
          "missing seed is rejected")
    check(any("'signature'" in e for e in errs(lambda d: d["bugs"][0].update(signature="nonsense"))),
          "malformed signature is rejected")
    check(any("unknown field" in e for e in errs(lambda d: d["bugs"][0].update(colour="red"))),
          "unknown field is rejected")
    check(ledger.parse_signature("O-SEQ:12:0x00000000000000ab") ==
          {"oracle": "O-SEQ", "event_index": 12, "msg_hash": "0x00000000000000ab"}, "signature string parses")
    check(ledger.parse_seed("0x1c") == 28 and ledger.parse_seed(28) == 28 and ledger.parse_seed("x") is None,
          "seed parsing")


def test_generator() -> None:
    r = py(str(HERE / "gen_ledger_md.py"), "--ledger", str(EXAMPLE))
    check(r.returncode == 0, f"generator runs: {r.stderr}")
    out = r.stdout
    check("| DST-001 |" in out and "| DST-002 |" in out, "rows rendered")
    check("**Verified (published)** | **0**" in out, "unverified bugs are not published")
    with tempfile.TemporaryDirectory() as td:
        vf = Path(td) / "verified.jsonl"
        vf.write_text(json.dumps({"id": "DST-001", "verified": True}) + "\n")
        out2 = py(str(HERE / "gen_ledger_md.py"), "--ledger", str(EXAMPLE), "--verified", str(vf)).stdout
    check("**Verified (published)** | **1**" in out2, "verified count published")
    check(out == py(str(HERE / "gen_ledger_md.py"), "--ledger", str(EXAMPLE)).stdout, "generator is deterministic")
    with tempfile.TemporaryDirectory() as td:
        ef = Path(td) / "empty.yaml"
        ef.write_text("schema_version: 1\nbugs: []\n")
        empty = py(str(HERE / "gen_ledger_md.py"), "--ledger", str(ef)).stdout
    check("No entries yet." in empty and "| Ledger entries | 0 |" in empty, "empty ledger renders")
    real = py(str(HERE / "gen_ledger_md.py"))
    check(real.returncode == 0 and "Ledger validation problems" not in real.stdout, "real ledger renders cleanly")


def test_verify_dry_run() -> None:
    with tempfile.TemporaryDirectory() as td:
        ef = Path(td) / "empty.yaml"
        ef.write_text("schema_version: 1\nbugs: []\n")
        r = py(str(HERE / "verify_bugs.py"), "--dry-run", "--ledger", str(ef))
    check(r.returncode == 0 and "counted=0 verified=0" in r.stdout, f"empty ledger verifies vacuously: {r.stdout}")
    r = py(str(HERE / "verify_bugs.py"), "--dry-run")
    check(r.returncode == 0 and "copy working tree" in r.stdout, f"uncommitted entries reproduce from a copy: {r.stdout}")
    r = py(str(HERE / "verify_bugs.py"), "--dry-run", "--ledger", str(EXAMPLE))
    check(r.returncode == 0 and "DST-001: FAILED" in r.stdout and "dst/DST-001/found" in r.stdout,
          f"example bug's found tag is not fetchable here: {r.stdout}")


def test_ddmin() -> None:
    need = {"3", "17", "22"}
    calls = [0]

    def t(sub: list[str]) -> bool:
        calls[0] += 1
        return need <= set(sub)

    out = shrink.ddmin([str(i) for i in range(32)], t)
    check(sorted(out, key=int) == ["3", "17", "22"], f"ddmin finds the 1-minimal subset: {out}")
    check(shrink.ddmin(["a", "b"], lambda s: True) == [], "ddmin returns empty when nothing is needed")


FAKE_EXSIM = """#!/usr/bin/env python3
import os, signal, sys
seed = int([a for a in sys.argv if a.startswith("--seed=")][0].split("=")[1], 16)
n = int([a for a in sys.argv if a.startswith("--seeds=")][0].split("=")[1])
for s in range(seed, seed + n):
    if s == 5:
        sys.stdout.flush()
        # SIGKILL, not SIGSEGV/SIGABRT: those wake the macOS crash reporter on every run.
        os.kill(os.getpid(), signal.SIGKILL)
    print(f"seed=0x{s:016x} result=PASS events=10 trace_hash=0x{s:016x}", flush=True)
print("result=PASS")
"""


def test_campaign_accounting() -> None:
    """A crashing exsim must still give every seed a verdict (TB CFO: crashes count)."""
    with tempfile.TemporaryDirectory() as td:
        fake = Path(td) / "fake_exsim.py"
        fake.write_text(FAKE_EXSIM)
        fake.chmod(0o755)
        led = Path(td) / "ledger"
        r = py(str(REPO / "tools" / "sim" / "campaign.py"), "--exsim", str(fake), "--seeds", "20", "--jobs", "3",
               "--batch", "7", "--seed-base", "0", "--ledger-dir", str(led))
        check(r.returncode == 1, f"campaign with a crashing seed fails: {r.stdout} {r.stderr}")
        rec = json.loads((led / "campaigns.jsonl").read_text().splitlines()[-1])
        check(rec["seeds_run"] == 20 and rec["failed"] == 1, f"every seed accounted for: {rec}")
        check(rec["failures"][0]["signature"].startswith("ABORT"), f"crash recorded as ABORT: {rec['failures']}")


def find_canary_seed(exsim: str, world: str) -> int:
    r = subprocess.run([exsim, "--seed=1", "--seeds=80", "--canary", f"--world={world}", "--quiet"],
                       capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if line.startswith("seed=") and "result=FAIL" in line:
            return int(line.split()[0].split("=")[1], 16)
    raise AssertionError(f"no canary failure found for {world}")


def test_exsim(exsim: str) -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    head = subprocess.run([exsim, f"--seed={sha}", "--world=wal", "--safety-ms=1", "--quiet"],
                          capture_output=True, text=True).stdout.splitlines()[0]
    check(f"seed=0x{campaign.fold_hex(sha):016x}" in head, f"campaign folds commit seeds like exsim: {head}")
    check(f"seed=0x{campaign.fold_hex('1c'):016x}" == "seed=0x000000000000001c", "short hex folds to itself")

    with tempfile.TemporaryDirectory() as td:
        seed = find_canary_seed(exsim, "stream")
        out = Path(td) / "min.txt"
        r = py(str(HERE / "shrink.py"), "--exsim", exsim, "--seed", hex(seed), "--out", str(out), "--",
               "--canary", "--world=stream")
        check(r.returncode == 0, f"shrink succeeds: {r.stdout} {r.stderr}")
        text = out.read_text()
        args_line = next(x for x in text.splitlines() if x.startswith("# args="))
        args = args_line.split("=", 1)[1].split()
        rep = subprocess.run([exsim, f"--seed={hex(seed)}", *args, f"--replay={out}", "--quiet"],
                             capture_output=True, text=True)
        check("signature=O-PREFIX:" in rep.stdout, f"min_trace replays to the same oracle: {rep.stdout}")
        n_events = sum(1 for x in text.splitlines() if x and not x.startswith("#"))
        check(n_events <= 2, f"stream canary needs at most a crash or two: {n_events}")

        led = Path(td) / "ledger"
        r = py(str(REPO / "tools" / "sim" / "campaign.py"), "--exsim", exsim, "--seeds", "30", "--jobs", "4",
               "--batch", "7", "--seed-base", "1", "--canary", "--world", "pingpong", "--ledger-dir", str(led))
        check(r.returncode == 1, f"canary campaign fails: {r.stdout}")
        fs = json.loads((led / "failing_seeds.json").read_text())
        per_sha = next(iter(fs.values()))
        check("O-EXACTLY-ONCE" in per_sha, f"failing seed kept per signature class: {per_sha}")
        rec = json.loads((led / "campaigns.jsonl").read_text().splitlines()[-1])
        check(rec["seeds_run"] == 30 and rec["failed"] > 0, f"campaign record counts seeds: {rec}")
        r = py(str(REPO / "tools" / "sim" / "campaign.py"), "--exsim", exsim, "--seeds", "12", "--jobs", "3",
               "--batch", "5", "--seed-base", "100", "--check-determinism", "--ledger-dir", str(led))
        check(r.returncode == 0, f"clean campaign passes: {r.stdout}")
        rec = json.loads((led / "campaigns.jsonl").read_text().splitlines()[-1])
        check(rec["seeds_run"] == 12 and rec["failed"] == 0 and rec["determinism_mismatches"] == 0,
              f"clean campaign record: {rec}")
        check(len((led / "campaigns.jsonl").read_text().splitlines()) == 2, "campaigns.jsonl is append-only")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exsim")
    a = ap.parse_args()
    test_ledger()
    test_generator()
    test_verify_dry_run()
    test_ddmin()
    test_campaign_accounting()
    if a.exsim:
        test_exsim(a.exsim)
    print(f"selftest: {checks} checks passed{'' if a.exsim else ' (no --exsim: end-to-end skipped)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
