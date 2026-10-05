#!/usr/bin/env python3
"""Build docs/results/EVIDENCE.md from campaign summaries (docs/plan/12 §8).

Every numeric statement is generated from a summary.json value; nothing is typed
by hand. Rows are PASS / MISS / PENDING (no evidence yet) / STALE (evidence whose
source tree hashes differ from HEAD; re-run required, docs/plan/12 §7).

Non-numeric targets are never passed on the mere existence of a file:
  kind = "fuzz_ops"     sums fuzz/ledger/runs.jsonl per book at the current source
                        tree hash (the same FNV-1a content hash the harnesses record);
  kind = "bug_count"    counts bugs through tools/ledger/ledger.py's counting rules;
  kind = "command"      runs a check (e.g. the dependency audit): PASS iff it exits 0;
  status_from = <doc>   reads an explicit marker the evidence document carries:
                        <!-- evidence-status: met | partial | pending -->
                        (a document without the marker is UNVERIFIED).
Rows may also be IN PROGRESS (evidence accumulating, threshold not reached) or
PARTIAL (the evidence document says some criteria are unmet).

usage: build_evidence.py [--check]   (--check exits non-zero if the file is out of date)
"""
from __future__ import annotations

import glob
import json
import operator
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OPS = {"<=": operator.le, "<": operator.lt, ">=": operator.ge, ">": operator.gt}


def head_tree(path: str) -> str:
    try:
        return subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", f"HEAD:{path}"], text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except subprocess.CalledProcessError:
        return "unknown"


def latest_summary(target: str) -> tuple[Path | None, dict | None]:
    cands = sorted(ROOT.glob(f"results/*-{target}-*/summary.json"))
    if not cands:
        return None, None
    return cands[-1], json.loads(cands[-1].read_text())


def fresh(summary: dict) -> bool:
    return all(h == head_tree(p) for p, h in summary.get("source_tree_hashes", {}).items())


def row_numeric(tid: str, spec: dict) -> tuple[str, str, str]:
    path, s = latest_summary(spec["campaign_target"])
    if s is None:
        return "PENDING", "no campaign yet", "—"
    m = s["metrics"]
    link = str(path.parent.relative_to(ROOT))
    if "metrics" in spec:
        vals = [m[k]["median"] for k in spec["metrics"] if k in m]
        if len(vals) != len(spec["metrics"]):
            return "PENDING", "metric missing in summary", link
        text = spec["statement"].format(p50=vals[0], p99=vals[1])
        ok = all(OPS[spec["op"]](v, t) for v, t in zip(vals, spec["thresholds"]))
    else:
        metric = spec["metric"]
        # Coarse-counter rule (docs/perf/METHODOLOGY.md): if the host's counter
        # steps exceed the pre-registered threshold, the mean is the headline.
        step = m.get(spec.get("coarse_step_metric", "tsc_min_step_ns"), {}).get("median")
        if "coarse_metric" in spec and step is not None and step > spec["coarse_threshold_ns"]:
            metric = spec["coarse_metric"]
        if metric not in m:
            return "PENDING", "metric missing in summary", link
        v = m[metric]["median"]
        text = spec["statement"].format(value=v, value_m=v / 1e6)
        ok = True if spec.get("kind") == "published" else OPS[spec["op"]](v, spec["threshold"])
    status = ("PASS" if ok else "MISS") if fresh(s) else "STALE"
    return status, text, link


def tree_hash(dirs: list[str]) -> str:
    """FNV-1a 64 over (relative path, 0, contents, 0) of every file, sorted by path:
    the definition lobdiff/itch_replay_diff record in the ledger (fuzz/lob/provenance.hpp)."""
    h = 0xCBF29CE484222325
    def eat(b: bytes) -> None:
        nonlocal h
        for x in b:
            h = ((h ^ x) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    files = sorted(p.relative_to(ROOT).as_posix() for d in dirs for p in (ROOT / d).rglob("*") if p.is_file())
    for f in files:
        eat(f.encode())
        eat(b"\0")
        eat((ROOT / f).read_bytes())
        eat(b"\0")
    return f"{h:016x}"


def fuzz_group(ledger: Path, g: dict) -> tuple[dict, dict, int, str]:
    """Release and sanitizer ops per book of one group at its current tree hash."""
    tree = tree_hash(g["tree_dirs"])
    rel: dict[str, int] = {b: 0 for b in g["books"]}
    san: dict[str, int] = {b: 0 for b in g["books"]}
    div = 0
    for line in ledger.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("harness") not in g["harnesses"] or r.get("tree") != tree:
            continue
        v = r.get("variant")
        if v not in rel:
            continue
        div += int(r.get("divergences", 0))
        if r.get("build") == "Release":
            rel[v] += int(r.get("ops", 0))
        elif "address" in str(r.get("build", "")):
            san[v] += int(r.get("ops", 0))
    return rel, san, div, tree


def row_fuzz_ops(tid: str, spec: dict) -> tuple[str, str, str]:
    ledger = ROOT / spec["ledger"]
    if not ledger.exists():
        return "PENDING", "no ledger", "—"
    parts, ok, any_div = [], True, False
    for g in spec["groups"]:
        rel, san, div, tree = fuzz_group(ledger, g)
        lo_rel, lo_san = min(rel.values()), min(san.values())
        parts.append(f"{g['label']}: min {lo_rel / 1e9:.2f}e9 Release / {lo_san / 1e6:.0f}e6 ASan+UBSan per book "
                     f"({len(rel)} books, tree {tree}, {div} divergences)")
        ok = ok and div == 0 and lo_rel >= spec["threshold"] and lo_san >= spec["sanitizer_threshold"]
        any_div = any_div or div > 0
    text = f"{spec['statement']}: " + "; ".join(parts)
    return ("PASS" if ok else ("MISS" if any_div else "IN PROGRESS")), text, spec["ledger"]


def row_bug_count(tid: str, spec: dict) -> tuple[str, str, str]:
    sys.path.insert(0, str(ROOT / "tools/ledger"))
    import ledger  # type: ignore[import-not-found]
    path = ROOT / spec["ledger"]
    if not path.exists():
        return "PENDING", "no ledger", "—"
    data = ledger.load(path)
    errs = ledger.validate(data)
    n = len(ledger.counted(data))
    text = f"{spec['statement']}: {n} (threshold {spec['threshold']}){'; ledger has ' + str(len(errs)) + ' problems' if errs else ''}"
    return ("PASS" if n >= spec["threshold"] and not errs else "IN PROGRESS"), text, spec["ledger"]


def row_command(tid: str, spec: dict) -> tuple[str, str, str]:
    r = subprocess.run(spec["command"], shell=True, cwd=ROOT, capture_output=True, text=True)
    return ("PASS" if r.returncode == 0 else "MISS"), spec["statement"], f"`{spec['command']}`"


def row_doc_status(tid: str, spec: dict) -> tuple[str, str, str]:
    present = [a for a in spec["artifacts"] if (ROOT / a).exists()]
    doc = ROOT / spec["status_from"]
    if not doc.exists():
        return "PENDING", spec["statement"], ", ".join(present) or "—"
    import re
    text = doc.read_text()
    # A per-target marker (<!-- evidence-status T07: met -->) wins over the document-wide one.
    m = re.search(rf"<!--\s*evidence-status\s+{re.escape(tid)}:\s*(met|partial|pending)\s*-->", text) or \
        re.search(r"<!--\s*evidence-status:\s*(met|partial|pending)\s*-->", text)
    status = {"met": "PASS", "partial": "PARTIAL", "pending": "PENDING"}[m.group(1)] if m else "UNVERIFIED"
    return status, spec["statement"], ", ".join(present)


def row_artifact(tid: str, spec: dict) -> tuple[str, str, str]:
    present = [a for a in spec["artifacts"] if (ROOT / a).exists()]
    if "count_glob" in spec:
        n = len(glob.glob(str(ROOT / spec["count_glob"])))
        ok = OPS[spec["op"]](n, spec["threshold"])
        return ("PASS" if ok else "PENDING"), f"{spec['statement']}: {n}", ", ".join(present) or "—"
    # Existence alone proves nothing: such a row stays UNVERIFIED until it gets a
    # kind or a status_from document.
    return ("UNVERIFIED" if len(present) == len(spec["artifacts"]) else "PENDING"), spec["statement"], ", ".join(present) or "—"


def build() -> str:
    specs = tomllib.loads((ROOT / "tools/evidence/targets.toml").read_text())
    lines = ["# Evidence ledger", "",
             "_Generated by `tools/evidence/build_evidence.py` from `results/*/summary.json`. Do not edit by hand._", "",
             "| Target | Status | Statement (measured) | Evidence |", "|---|---|---|---|"]
    for tid, spec in specs.items():
        if "campaign_target" in spec:
            status, text, link = row_numeric(tid, spec)
        elif spec.get("kind") == "fuzz_ops":
            status, text, link = row_fuzz_ops(tid, spec)
        elif spec.get("kind") == "bug_count":
            status, text, link = row_bug_count(tid, spec)
        elif spec.get("kind") == "command":
            status, text, link = row_command(tid, spec)
        elif "status_from" in spec:
            status, text, link = row_doc_status(tid, spec)
        else:
            status, text, link = row_artifact(tid, spec)
        lines.append(f"| {tid} | {status} | {text} | {link} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    out = ROOT / "docs/results/EVIDENCE.md"
    content = build()
    if "--check" in sys.argv:
        current = out.read_text() if out.exists() else ""
        if current != content:
            print("docs/results/EVIDENCE.md is out of date; run tools/evidence/build_evidence.py", file=sys.stderr)
            return 1
        return 0
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
