#!/usr/bin/env python3
"""Checks that every relative link in the repository's Markdown resolves (docs/plan/12 §8:
"CI checks ... that every link resolves").

For each [text](target) and <a href="target"> in tracked-looking Markdown files (the
build, data and dependency directories are skipped):
  * external links (scheme://, mailto:) are not fetched;
  * the path part must name an existing file or directory, relative to the linking file
    (or to the repository root for a leading "/");
  * a "#fragment" on a Markdown target must match a heading of that file (GitHub's slug
    rules) or an explicit <a id="..."> / <a name="..."> anchor.

usage: check_doc_links.py [--selftest] [ROOT]     exit status 1 if any link is broken
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

SKIP_DIRS = {".git", "build", "data", "_deps", "node_modules", ".cache"}
LINK = re.compile(r"(?<!!)\[(?:[^\]\[]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
IMG = re.compile(r"!\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
HREF = re.compile(r"<a\s+[^>]*href=\"([^\"]+)\"")
ANCHOR = re.compile(r"<a\s+[^>]*(?:id|name)=\"([^\"]+)\"")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
FENCE = re.compile(r"^\s*(```|~~~)")


def slug(text: str) -> str:
    """GitHub's heading anchor: lowercase, drop punctuation except - and _, spaces to -."""
    text = re.sub(r"<[^>]+>", "", text)          # inline HTML
    text = re.sub(r"`([^`]*)`", r"\1", text)      # code spans keep their text
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # links keep their text
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def anchors_of(md: Path, cache: dict[Path, set[str]]) -> set[str]:
    if md in cache:
        return cache[md]
    found: set[str] = set()
    counts: dict[str, int] = {}
    in_fence = False
    for line in md.read_text(errors="replace").splitlines():
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for a in ANCHOR.findall(line):
            found.add(a)
        m = HEADING.match(line)
        if m:
            s = slug(m.group(2))
            n = counts.get(s, 0)
            found.add(s if n == 0 else f"{s}-{n}")
            counts[s] = n + 1
    cache[md] = found
    return found


def links_of(md: Path) -> list[tuple[int, str]]:
    out = []
    in_fence = False
    for no, line in enumerate(md.read_text(errors="replace").splitlines(), 1):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        line = re.sub(r"`[^`]*`", "", line)  # links inside code spans are text
        for rx in (LINK, IMG, HREF):
            for t in rx.findall(line):
                out.append((no, t))
    return out


def check(root: Path) -> list[str]:
    errors: list[str] = []
    cache: dict[Path, set[str]] = {}
    for md in sorted(root.rglob("*.md")):
        rel = md.relative_to(root)
        if any(p in SKIP_DIRS for p in rel.parts):
            continue
        for no, target in links_of(md):
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
                continue  # http:, https:, mailto:, ...
            path, _, frag = target.partition("#")
            if path == "":
                dest = md
            elif path.startswith("/"):
                dest = root / path.lstrip("/")
            else:
                dest = (md.parent / path)
            if not dest.exists():
                errors.append(f"{rel}:{no}: {target}: no such file")
                continue
            if frag and dest.is_file() and dest.suffix == ".md" and frag not in anchors_of(dest.resolve(), cache):
                errors.append(f"{rel}:{no}: {target}: no heading or anchor '{frag}'")
    return errors


def selftest() -> int:
    with tempfile.TemporaryDirectory() as d:
        r = Path(d)
        (r / "docs").mkdir()
        (r / "docs" / "a.md").write_text(
            "# Title\n## 7. Takeover measurement (T25)\n<a id=\"defs\"></a>\n"
            "[ok](b.md) [ok2](b.md#sub-heading) [self](#title) [num](#7-takeover-measurement-t25) [x](#defs)\n"
            "[bad](missing.md) [badfrag](b.md#nope) [web](https://example.com)\n"
            "```\n[ignored](nowhere.md)\n```\n`[code](nowhere.md)`\n")
        (r / "docs" / "b.md").write_text("# B\n## Sub heading\n")
        errs = check(r)
        want = {"docs/a.md:5: missing.md: no such file", "docs/a.md:5: b.md#nope: no heading or anchor 'nope'"}
        if set(errs) != want:
            print("selftest FAILED:", errs)
            return 1
    print("selftest ok")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] == "--selftest":
        return selftest()
    root = Path(args[0]) if args else Path(__file__).resolve().parents[2]
    errors = check(root)
    for e in errors:
        print(e)
    print(f"broken links: {len(errors)}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
