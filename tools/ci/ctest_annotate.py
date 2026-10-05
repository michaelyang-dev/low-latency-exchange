#!/usr/bin/env python3
"""Reports a failed ctest run as GitHub Actions error annotations (tools/ci/ctest.sh).

    python3 tools/ci/ctest_annotate.py <ctest build directory>

GitHub keeps at most 10 error annotations per step, and the job log needs a login, so:
one annotation names every failed test, and up to MAX_DETAILS more carry the end of a
failed test's output from Testing/Temporary/LastTest.log.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

MAX_DETAILS = 8
TAIL_LINES = 25
LINE_CHARS = 240


def escape(s: str) -> str:
    # Workflow-command data escaping: %, CR and LF.
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(s: str) -> str:
    return escape(s).replace(":", "%3A").replace(",", "%2C")


def outputs(log: str) -> dict[str, list[str]]:
    """Test name -> output lines, from ctest's LastTest.log."""
    out: dict[str, list[str]] = {}
    for m in re.finditer(r'^\d+/\d+ Test: (?P<name>.+?)\n.*?^Output:\n-+\n(?P<body>.*?)^<end of output>',
                         log, flags=re.M | re.S):
        out[m["name"].strip()] = m["body"].splitlines()
    return out


def main(argv: list[str]) -> int:
    tmp = Path(argv[1] if len(argv) > 1 else ".") / "Testing" / "Temporary"
    failed_file = tmp / "LastTestsFailed.log"
    if not failed_file.is_file():
        return 0
    failed = [line.split(":", 1)[-1].strip() for line in failed_file.read_text().splitlines() if line.strip()]
    if not failed:
        return 0
    print(f"::error::ctest failed ({len(failed)}): {escape(', '.join(failed))}")
    log = tmp / "LastTest.log"
    outs = outputs(log.read_text(errors="replace")) if log.is_file() else {}
    for name in failed[:MAX_DETAILS]:
        lines = [x[:LINE_CHARS] for x in outs.get(name, [])][-TAIL_LINES:]
        body = "\n".join(lines) if lines else "(no output recorded)"
        print(f"::error title={escape_property(name)}::{escape(body)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
