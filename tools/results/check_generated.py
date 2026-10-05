#!/usr/bin/env python3
"""Fail if any generated results report differs from a fresh render (docs/plan/12 §8)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/results"))
import render  # noqa: E402


def main() -> int:
    bad = []
    for fam in render.FAMILIES:
        p = ROOT / "docs/results" / f"{fam}.md"
        if not p.exists() or p.read_text() != render.render(fam):
            bad.append(str(p.relative_to(ROOT)))
    rc = subprocess.call([sys.executable, str(ROOT / "tools/evidence/build_evidence.py"), "--check"])
    for b in bad:
        print(f"out of date (hand-edited or stale): {b}", file=sys.stderr)
    return 1 if bad or rc else 0


if __name__ == "__main__":
    sys.exit(main())
