#!/usr/bin/env python3
"""Write the found_patch of an uncommitted bug fix (docs/plan/09 §10).

Before fixing a bug, snapshot the files you will change:

    python3 tools/ledger/make_found_patch.py snapshot DST-007 src/journal/recovery.cpp src/journal/segment.h

Fix the bug, then emit the patch that turns the fixed working tree back into
the tree the seed was found at (applied with `git apply -p1` by verify_bugs.py):

    python3 tools/ledger/make_found_patch.py write DST-007   # -> sim/ledger/patches/DST-007.patch

Snapshots live in sim/ledger/patches/.snapshots/<ID>/ (repository-relative paths).
They are git-ignored local scratch: the .patch is the record.
"""
from __future__ import annotations

import difflib
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PATCHES = REPO / "sim" / "ledger" / "patches"


def snapshot(bid: str, files: list[str]) -> int:
    base = PATCHES / ".snapshots" / bid
    for f in files:
        src = (REPO / f).resolve()
        rel = src.relative_to(REPO)
        dst = base / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        print(f"snapshot {rel}")
    return 0


def write(bid: str) -> int:
    base = PATCHES / ".snapshots" / bid
    if not base.is_dir():
        print(f"no snapshot for {bid}", file=sys.stderr)
        return 2
    out: list[str] = []
    for snap in sorted(p for p in base.rglob("*") if p.is_file()):
        rel = snap.relative_to(base).as_posix()
        fixed = (REPO / rel).read_text().splitlines(keepends=True)
        found = snap.read_text().splitlines(keepends=True)
        diff = list(difflib.unified_diff(fixed, found, f"a/{rel}", f"b/{rel}"))
        if diff:
            out.append(f"diff --git a/{rel} b/{rel}\n")
            out.extend(x if x.endswith("\n") else x + "\n\\ No newline at end of file\n" for x in diff)
    if not out:
        print(f"{bid}: snapshot equals the working tree (nothing fixed?)", file=sys.stderr)
        return 1
    PATCHES.mkdir(parents=True, exist_ok=True)
    path = PATCHES / f"{bid}.patch"
    path.write_text("".join(out))
    print(f"wrote {path.relative_to(REPO)}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[1] == "snapshot":
        return snapshot(argv[2], argv[3:])
    if len(argv) == 3 and argv[1] == "write":
        return write(argv[2])
    print(__doc__, file=sys.stderr)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
