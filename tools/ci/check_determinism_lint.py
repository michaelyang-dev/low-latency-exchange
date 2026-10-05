#!/usr/bin/env python3
"""Source-level determinism lint (docs/plan/01 §5 "Rules"; docs/design/determinism.md).

Complements tools/ci/check_sim_purity.sh, which inspects symbols in sim builds.
This script reads the sources of the deterministic components and reports:

  R1  banned randomness, clocks and threads: std:: random engines and
      distributions (implementation-defined), rand/srand, std::chrono clocks,
      std::thread / std::this_thread, time();
  R2  iteration over unordered containers (hash order is not stable across
      standard libraries or insertion histories): a range-for, .begin() or
      std::begin() on a variable declared as std::unordered_*;
  R3  ordered containers keyed by pointers (iteration order follows addresses);
  R4  floating point in decision code (engine, LOB, books, sequencer);
  R5  real waiting: a wait primitive (conc::spin_until/spin_until_for, the
      Spin/SpinPause/Backoff policies, cpu_relax, yield_thread, sched_yield) or an
      #include that reaches concurrent/wait.h, runtime/launcher.h or
      runtime/pinning.h, directly or through other project headers (followed
      transitively from src/). Sim-built cores must never block, spin or yield;
      the queues themselves (src/concurrent/*_ring.h, mpsc_*.h) are fine.

A finding is accepted only with a justification comment on the same line:
    // determinism-ok: <reason>

usage: tools/ci/check_determinism_lint.py [--root DIR] [paths...]
       tools/ci/check_determinism_lint.py --selftest   # planted violations must all be found
Exit status 1 if there are findings.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DETERMINISTIC = [
    "src/engine", "src/lob", "src/book", "src/sequencer", "src/journal", "src/snapshot", "src/outlog",
    "src/proto", "src/witness", "src/repl",
]
DECISION = ("src/engine", "src/lob", "src/book", "src/sequencer")

R1 = re.compile(
    r"std::(uniform_int_distribution|uniform_real_distribution|normal_distribution|bernoulli_distribution|"
    r"discrete_distribution|random_device|mt19937(_64)?|minstd_rand0?|default_random_engine|ranlux\w*|knuth_b)\b"
    r"|(?<![\w.:>])s?rand\s*\("
    r"|std::chrono::(system_clock|steady_clock|high_resolution_clock)"
    r"|std::(thread|jthread|this_thread)\b"
    r"|(?<![\w.:>])time\s*\(\s*(nullptr|NULL|0)?\s*\)"
)
UNORDERED_DECL = re.compile(r"std::unordered_(?:map|set|multimap|multiset)\s*<[^;{]*>\s*&?\s*(\w+)\s*(?:[;{=(]|$)")
POINTER_KEYED = re.compile(r"std::(?:map|set|multimap|multiset)\s*<\s*(?:const\s+)?[\w:]+\s*\*")
FLOAT = re.compile(r"(?<![\w.])(float|double|long double)\b")
WAIT = re.compile(
    r"\b(spin_until|spin_until_for|yield_thread|cpu_relax|sched_yield)\s*\("
    r"|\bconc::(Spin|SpinPause|Backoff)\b"
    r"|\brt::Launcher\b"
)
WAIT_HEADERS = ("concurrent/wait.h", "runtime/launcher.h", "runtime/pinning.h")
INCLUDE = re.compile(r'^\s*#\s*include\s*"([^"]+)"')
OK = "determinism-ok"


def reaches_wait_header(root: Path, inc: str, seen: set[str]) -> str | None:
    """Returns the include chain if `inc` (a path relative to src/) is or includes a
    wait header, following project includes transitively."""
    if inc in WAIT_HEADERS:
        return inc
    if inc in seen:
        return None
    seen.add(inc)
    f = root / "src" / inc
    if not f.is_file():
        return None
    for line in f.read_text(errors="replace").splitlines():
        m = INCLUDE.match(line)
        if m and OK not in line:
            chain = reaches_wait_header(root, m.group(1), seen)
            if chain:
                return f"{inc} -> {chain}"
    return None


def strip_comments(line: str) -> str:
    i = line.find("//")
    return line if i < 0 else line[:i]


def lint_file(path: Path, rel: str, root: Path | None = None) -> list[str]:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return []
    out: list[str] = []
    code = [strip_comments(l) for l in lines]
    names = set()
    for c in code:
        for m in UNORDERED_DECL.finditer(c):
            names.add(m.group(1))
    iter_res = [
        re.compile(rf"for\s*\([^;)]*:\s*(?:this->)?{re.escape(n)}\s*\)") for n in names
    ] + [re.compile(rf"(?<![\w.]){re.escape(n)}\s*\.\s*c?begin\s*\(|std::c?begin\s*\(\s*{re.escape(n)}\s*\)") for n in names]
    decision = rel.startswith(DECISION)
    for i, (raw, c) in enumerate(zip(lines, code), start=1):
        if OK in raw:
            continue
        if R1.search(c):
            out.append(f"{rel}:{i}: R1 banned randomness/clock/thread: {raw.strip()}")
        if any(r.search(c) for r in iter_res):
            out.append(f"{rel}:{i}: R2 iteration over an unordered container: {raw.strip()}")
        if POINTER_KEYED.search(c):
            out.append(f"{rel}:{i}: R3 pointer-keyed ordered container: {raw.strip()}")
        if decision and FLOAT.search(c):
            out.append(f"{rel}:{i}: R4 floating point in decision code: {raw.strip()}")
        if WAIT.search(c):
            out.append(f"{rel}:{i}: R5 wait primitive in deterministic code: {raw.strip()}")
        m = INCLUDE.match(raw)
        if m and root is not None:
            chain = reaches_wait_header(root, m.group(1), set())
            if chain:
                out.append(f"{rel}:{i}: R5 include reaches a wait header ({chain}): {raw.strip()}")
    return out


SELFTEST = {
    "src/engine/bad_random.h": ("std::mt19937 gen(1);\nint x = rand();\nauto t = std::chrono::steady_clock::now();\n", 3),
    "src/journal/bad_iter.cpp": (
        "std::unordered_map<int, Order> orders_;\nvoid f() { for (auto& [k, v] : orders_) use(v); }\n"
        "void g() { auto it = orders_.begin(); }\n", 2),
    "src/book/bad_ptr.h": ("std::map<const Level*, int> by_level_;\n", 1),
    "src/engine/bad_float.h": ("double fee = 0.1;\n", 1),
    "src/engine/ok.h": ("double x = 0;  // determinism-ok: diagnostics only, never in a decision\n"
                        "std::unordered_map<int, int> m_;\nint v = m_.at(3);\n", 0),
    "src/proto/float_ok_outside_decision.h": ("double ratio = 1.0;\n", 0),
    "src/engine/bad_wait.cpp": ('#include "concurrent/wait.h"\nvoid f() { conc::spin_until([] { return true; }, conc::Backoff{}); }\n'
                                "void g() { conc::detail::yield_thread(); sched_yield(); }\n", 3),  # one per line
    "src/journal/bad_transitive.h": ('#include "util/helper.h"\n', 1),
    "src/util/helper.h": ('#include "runtime/launcher.h"\n', None),  # support file, not linted itself
    "src/journal/queue_ok.h": ('#include "concurrent/broadcast_ring.h"\n#include "concurrent/mpsc_scq.h"\n', 0),
    "src/engine/wait_ok.h": ('#include "concurrent/wait.h"  // determinism-ok: selftest of the marker\n', 0),
}


def selftest() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        bad = 0
        for rel, (text, _) in SELFTEST.items():
            f = root / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(text)
        for rel, (text, want) in SELFTEST.items():
            if want is None:
                continue
            f = root / rel
            got = len(lint_file(f, rel, root))
            status = "ok" if got == want else "FAIL"
            if got != want:
                bad += 1
            print(f"selftest {status}: {rel}: {got} finding(s), expected {want}")
        return 1 if bad else 0


def main() -> int:
    if "--selftest" in sys.argv[1:]:
        return selftest()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    ap.add_argument("paths", nargs="*", help="files or directories (default: the deterministic components)")
    a = ap.parse_args()
    root = Path(a.root)
    targets = [root / p for p in (a.paths or DETERMINISTIC)]
    findings: list[str] = []
    nfiles = 0
    for t in targets:
        files = [t] if t.is_file() else sorted(p for p in t.rglob("*") if p.suffix in {".h", ".hpp", ".cpp", ".cc"})
        for f in files:
            nfiles += 1
            findings += lint_file(f, f.relative_to(root).as_posix(), root)
    for line in findings:
        print(line)
    print(f"determinism lint: {nfiles} files, {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
