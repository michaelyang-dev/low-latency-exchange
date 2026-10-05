#!/usr/bin/env python3
"""Checks that every counted, uncommitted bug's found_patch still applies to the working
tree (docs/plan/09 §10).

Until a fix is committed and tagged, verify_bugs.py rebuilds the found tree as "the
working tree with found_patch applied". Any later edit inside the patched lines makes
the patch stale, and the bug can no longer be reproduced from its seed. This check is
cheap (git apply --check), so it runs with the unit tests. After an intentional edit,
regenerate the patch (make_found_patch.py write DST-NNN) and re-run verify_bugs.py.

usage: check_found_patches.py [--ledger sim/ledger/bugs.yaml]   exit 1 if any patch is stale
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ledger  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ledger", default=str(ROOT / "sim/ledger/bugs.yaml"))
    a = ap.parse_args()
    stale = checked = 0
    for b in ledger.load(a.ledger)["bugs"]:
        if not b.get("counted") or str(b.get("sha_found", "")) != "uncommitted":
            continue
        patch = b.get("found_patch")
        if not patch:
            print(f"{b['id']}: uncommitted but has no found_patch")
            stale += 1
            continue
        checked += 1
        r = subprocess.run(["git", "-C", str(ROOT), "apply", "--check", "-p1", str(ROOT / patch)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            stale += 1
            print(f"{b['id']}: {patch} no longer applies to the working tree:\n{r.stderr.strip()}")
        else:
            print(f"{b['id']}: {patch} applies")
    print(f"found patches checked={checked} stale={stale}")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
