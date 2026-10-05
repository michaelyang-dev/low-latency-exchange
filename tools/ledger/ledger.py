#!/usr/bin/env python3
"""DST bug ledger: schema, loading and the published counting rules (docs/plan/09 §10).

The source of truth is sim/ledger/bugs.yaml:

    schema_version: 1
    bugs:
      - id: DST-001
        title: "journal loses tail after torn write"
        ...

Fields (09 §10). `exsim_args` is an extension: the extra exsim flags the seed
needs to reproduce (world, mode, disabled classes), recorded by campaign.py.

Counting rules are applied mechanically (validate() reports violations):
  1. production code, not harness code      -> category == "production"
  2. found by exsim                         -> campaign_id and oracle present
  3. committed SHA, reproduces from seed    -> sha_found and seed present
     (until the owner commits and tags, sha_found/fix_sha may be "uncommitted":
     the fix tree is the working tree and found_patch turns it back into the
     tree the seed was found at; verify_bugs.py reproduces from that)
  4. distinct root cause, deduplicated by fix -> unique fix_sha among counted bugs
  5. fixed, with a seed-independent regression test -> fix_sha, regression_test
Never counted: canaries, mutation-testing mutants, harness determinism bugs,
planted bugs (category canary | mutant | harness | planted).

Uses PyYAML when installed; otherwise a small parser for the subset of YAML
this file uses (block mappings and lists, inline [a, b] lists, scalars).
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
DEFAULT_LEDGER = REPO / "sim" / "ledger" / "bugs.yaml"


@dataclass(frozen=True)
class Field:
    name: str
    kind: str  # str | int | bool | list | map | seed | sha | utc
    required: bool
    doc: str


# Order is the order of 09 §10; the generator prints in this order.
FIELDS: tuple[Field, ...] = (
    Field("id", "str", True, "DST-NNN"),
    Field("title", "str", True, "one-line summary"),
    Field("component", "str", True, "production component (e.g. journal, repl, gateway)"),
    Field("targets", "list", True, "target IDs (e.g. [T05, T26])"),
    Field("category", "str", True, "production | harness | canary | mutant | planted"),
    Field("found_utc", "utc", True, "ISO-8601 UTC time the failing seed was found"),
    Field("campaign_id", "str", True, "campaign that found it (campaigns.jsonl)"),
    Field("sha_found", "sha", True, "commit the seed fails at (tag dst/DST-NNN/found), or 'uncommitted'"),
    Field("found_patch", "str", False, "uncommitted only: patch (git apply -p1) turning the fix tree into the found tree"),
    Field("seed", "seed", True, "exsim seed (decimal or 0x hex)"),
    Field("exsim_args", "list", False, "extra exsim flags needed to reproduce"),
    Field("swarm_digest", "str", True, "swarm_digest printed by exsim"),
    Field("platform", "str", True, "e.g. linux-x86_64, macos-arm64"),
    Field("build", "str", True, "e.g. sim-RelWithDebInfo"),
    Field("oracle", "str", True, "oracle ID that fired (O-SEQ, ...)"),
    Field("signature", "map", True, "{oracle, event_index, msg_hash} as printed by exsim"),
    Field("introduced_sha", "sha", False, "bisected with the regression test"),
    Field("root_cause", "str", False, "what was wrong"),
    Field("fix_sha", "sha", False, "commit that fixes it (tag dst/DST-NNN/fix), or 'uncommitted'"),
    Field("regression_test", "str", False, "tests/sim_regressions/DST-NNN_*"),
    Field("min_trace", "str", False, "shrunk reproduction (shrink.py output)"),
    Field("verify_run_url", "str", False, "last verify_bugs.py run"),
    Field("counted", "bool", True, "counts toward T23b"),
    Field("count_reason", "str", True, "why it counts / does not count"),
)
FIELD_NAMES = tuple(f.name for f in FIELDS)
CATEGORIES = ("production", "harness", "canary", "mutant", "planted")
NEVER_COUNTED = ("harness", "canary", "mutant", "planted")
ID_RE = re.compile(r"^DST-\d{3,}$")
SHA_RE = re.compile(r"^([0-9a-f]{7,40}|uncommitted)$")
UNCOMMITTED = "uncommitted"
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?Z$")
SIG_RE = re.compile(r"^(?P<oracle>[A-Z][A-Z0-9-]*):(?P<event>\d+):(?P<hash>0x[0-9a-f]{16})$")


# ---------------------------------------------------------------------------
# Minimal YAML subset (fallback when PyYAML is absent)


def _scalar(tok: str) -> Any:
    t = tok.strip()
    if t == "" or t in ("~", "null"):
        return None
    if t in ("true", "True"):
        return True
    if t in ("false", "False"):
        return False
    if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
        body = t[1:-1]
        return body.replace('\\"', '"').replace("\\\\", "\\") if t[0] == '"' else body.replace("''", "'")
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1].strip()
        if not inner:
            return []
        return [_scalar(x) for x in _split_inline(inner)]
    if t.startswith("{") and t.endswith("}"):
        inner = t[1:-1].strip()
        out: dict[str, Any] = {}
        for item in _split_inline(inner) if inner else []:
            k, _, v = item.partition(":")
            out[k.strip()] = _scalar(v)
        return out
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"0x[0-9a-fA-F]+", t):
        return int(t, 16)  # as YAML 1.1 (PyYAML) does
    return t


def _split_inline(s: str) -> list[str]:
    parts, depth, quote, cur = [], 0, "", []
    for ch in s:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def _strip_comment(line: str) -> str:
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def parse_yaml_subset(text: str) -> Any:
    lines = []
    for raw in text.splitlines():
        s = _strip_comment(raw)
        if s.strip():
            lines.append((len(s) - len(s.lstrip(" ")), s.strip()))
    pos = 0

    def block(indent: int) -> Any:
        nonlocal pos
        if pos >= len(lines):
            return None
        if lines[pos][1].startswith("- ") or lines[pos][1] == "-":
            out_list: list[Any] = []
            while pos < len(lines) and lines[pos][0] == indent and (lines[pos][1].startswith("- ") or lines[pos][1] == "-"):
                content = lines[pos][1][1:].strip()
                if not content:
                    pos += 1
                    out_list.append(block(lines[pos][0]) if pos < len(lines) and lines[pos][0] > indent else None)
                elif ":" in content and not content.startswith(("[", "{", '"', "'")) and _is_key(content):
                    # "- key: value" opens a mapping whose keys sit at indent + 2.
                    lines[pos] = (indent + 2, content)
                    out_list.append(block(indent + 2))
                else:
                    pos += 1
                    out_list.append(_scalar(content))
            return out_list
        out_map: dict[str, Any] = {}
        while pos < len(lines) and lines[pos][0] == indent and not lines[pos][1].startswith("- "):
            key, _, rest = lines[pos][1].partition(":")
            pos += 1
            rest = rest.strip()
            if rest:
                out_map[key.strip()] = _scalar(rest)
            elif pos < len(lines) and lines[pos][0] > indent:
                out_map[key.strip()] = block(lines[pos][0])
            elif pos < len(lines) and lines[pos][0] == indent and lines[pos][1].startswith("- "):
                out_map[key.strip()] = block(indent)
            else:
                out_map[key.strip()] = None
        return out_map

    return block(lines[0][0]) if lines else None


def _is_key(s: str) -> bool:
    key, sep, _ = s.partition(":")
    return bool(sep) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", key.strip()) is not None


def load_text(text: str) -> dict[str, Any]:
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(text)
    except ImportError:
        data = parse_yaml_subset(text)
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError("ledger: top level must be a mapping with a 'bugs' list")
    bugs = data.get("bugs") or []
    if not isinstance(bugs, list):
        raise ValueError("ledger: 'bugs' must be a list")
    data["bugs"] = bugs
    return data


def load(path: Path | str = DEFAULT_LEDGER) -> dict[str, Any]:
    return load_text(Path(path).read_text())


# ---------------------------------------------------------------------------
# Signatures and validation


def parse_signature(sig: Any) -> dict[str, Any] | None:
    """Accepts exsim's 'O-X:123:0x...' string or a {oracle, event_index, msg_hash} map."""
    if isinstance(sig, str):
        m = SIG_RE.match(sig.strip())
        if not m:
            return None
        return {"oracle": m["oracle"], "event_index": int(m["event"]), "msg_hash": m["hash"]}
    if isinstance(sig, dict) and {"oracle", "event_index", "msg_hash"} <= set(sig):
        mh = sig["msg_hash"]
        mh = f"0x{mh:016x}" if isinstance(mh, int) else str(mh).lower()
        return {"oracle": str(sig["oracle"]), "event_index": int(sig["event_index"]), "msg_hash": mh}
    return None


def format_signature(sig: dict[str, Any]) -> str:
    return f"{sig['oracle']}:{sig['event_index']}:{sig['msg_hash']}"


def parse_seed(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if 0 <= v < 2**64 else None
    if isinstance(v, str):
        s = v.strip().lower()
        try:
            return int(s, 16) if s.startswith("0x") else int(s)
        except ValueError:
            return None
    return None


def _check_kind(f: Field, v: Any) -> str | None:
    if f.kind == "str" and not isinstance(v, str):
        return "must be a string"
    if f.kind == "bool" and not isinstance(v, bool):
        return "must be true or false"
    if f.kind == "list" and not isinstance(v, list):
        return "must be a list"
    if f.kind == "map" and parse_signature(v) is None:
        return "must be {oracle, event_index, msg_hash} or 'ORACLE:EVENT:0xHASH'"
    if f.kind == "seed" and parse_seed(v) is None:
        return "must be a u64 (decimal or 0x hex)"
    if f.kind == "sha" and not (isinstance(v, str) and SHA_RE.match(v)):
        return "must be a quoted 7-40 hex commit sha (unquoted digits parse as numbers)"
    if f.kind == "utc" and not (isinstance(v, str) and UTC_RE.match(v)):
        return "must be ISO-8601 UTC (YYYY-MM-DDTHH:MM:SSZ)"
    return None


def validate(data: dict[str, Any]) -> list[str]:
    """Schema and counting-rule violations, as human-readable strings."""
    errs: list[str] = []
    seen_ids: set[str] = set()
    counted_fixes: dict[str, str] = {}
    for i, bug in enumerate(data.get("bugs", [])):
        where = f"bugs[{i}]"
        if not isinstance(bug, dict):
            errs.append(f"{where}: must be a mapping")
            continue
        bid = bug.get("id")
        where = f"{bid or where}"
        for k in bug:
            if k not in FIELD_NAMES:
                errs.append(f"{where}: unknown field '{k}'")
        for f in FIELDS:
            v = bug.get(f.name)
            if v is None or v == "":
                if f.required:
                    errs.append(f"{where}: missing required field '{f.name}'")
                continue
            problem = _check_kind(f, v)
            if problem:
                errs.append(f"{where}: '{f.name}' {problem}")
        if isinstance(bid, str):
            if not ID_RE.match(bid):
                errs.append(f"{where}: id must look like DST-NNN")
            if bid in seen_ids:
                errs.append(f"{where}: duplicate id")
            seen_ids.add(bid)
        cat = bug.get("category")
        if cat is not None and cat not in CATEGORIES:
            errs.append(f"{where}: category must be one of {', '.join(CATEGORIES)}")
        sig = parse_signature(bug.get("signature"))
        if sig and bug.get("oracle") and sig["oracle"] != bug.get("oracle"):
            errs.append(f"{where}: signature oracle {sig['oracle']} != oracle {bug.get('oracle')}")
        if bug.get("counted") is True:
            for reason in counting_violations(bug):
                errs.append(f"{where}: counted but {reason}")
            fix = fix_key(bug)
            if fix is not None:
                if fix in counted_fixes:
                    errs.append(f"{where}: same fix_sha as {counted_fixes[fix]} (rule 4: one root cause, dedup by fix)")
                counted_fixes[fix] = str(bid)
    return errs


def fix_key(bug: dict[str, Any]) -> str | None:
    """Identity of the fix for rule 4: the fix commit, or the patch until committed."""
    fix = bug.get("fix_sha")
    if not isinstance(fix, str) or not fix:
        return None
    if fix == UNCOMMITTED:
        patch = bug.get("found_patch")
        return f"patch:{patch}" if isinstance(patch, str) and patch else None
    return fix


def counting_violations(bug: dict[str, Any]) -> list[str]:
    """Why a bug may not count under 09 §10 (empty list = it may count)."""
    out = []
    if bug.get("category") in NEVER_COUNTED:
        out.append(f"category '{bug.get('category')}' is never counted")
    elif bug.get("category") != "production":
        out.append("rule 1: not production code")
    if not bug.get("campaign_id") or not bug.get("oracle"):
        out.append("rule 2: not found by an exsim campaign")
    if not bug.get("sha_found") or parse_seed(bug.get("seed")) is None:
        out.append("rule 3: no seed@sha_found")
    elif bug.get("sha_found") == UNCOMMITTED:
        patch = bug.get("found_patch")
        if not isinstance(patch, str) or not (REPO / patch).is_file():
            out.append("rule 3: sha_found is uncommitted but found_patch is missing")
        if bug.get("fix_sha") not in (UNCOMMITTED, None):
            out.append("rule 3: an uncommitted found tree needs fix_sha 'uncommitted' (the working tree)")
    if not bug.get("fix_sha"):
        out.append("rule 5: not fixed (no fix_sha)")
    if not bug.get("regression_test"):
        out.append("rule 5: no seed-independent regression test")
    return out


def counted(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [b for b in data.get("bugs", []) if isinstance(b, dict) and b.get("counted") is True]


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_LEDGER
    data = load(path)
    errs = validate(data)
    for e in errs:
        print(f"ledger: {e}", file=sys.stderr)
    print(f"ledger: {path}: {len(data['bugs'])} bugs, {len(counted(data))} counted, {len(errs)} problems")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
