#!/usr/bin/env python3
"""specgen: OUCH 5.0 layout table -> C++ headers, markdown, lint (03-protocols s2).

Input : src/proto/ouch50/spec/ouch50_fields.csv (the single source of truth)
Output: src/proto/ouch50/ouch50_layout.gen.h    constants, enums, descriptor tables, static_asserts
        src/proto/ouch50/ouch50_messages.gen.h  value structs, typed views, TagSet, visitors

Usage:
  specgen.py              regenerate both headers in place
  specgen.py --check      lint the CSV and fail if the checked-in headers are stale
  specgen.py --markdown   print the human-readable layout tables to stdout

The generated headers are committed so the CMake build never needs Python.
"""
from __future__ import annotations

import argparse
import csv
import pathlib
import re
import sys
from dataclasses import dataclass, field

ROOT = pathlib.Path(__file__).resolve().parents[2]
CSV_PATH = ROOT / "src/proto/ouch50/spec/ouch50_fields.csv"
LAYOUT_PATH = ROOT / "src/proto/ouch50/ouch50_layout.gen.h"
MESSAGES_PATH = ROOT / "src/proto/ouch50/ouch50_messages.gen.h"

FIXED_TYPE_LEN = {"type": 1, "u8": 1, "u16": 2, "u32": 4, "u64": 8, "price": 8, "ts": 8, "char": 1, "applen": 2}
TAG_TYPE_LEN = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "price": 8, "sprice4": 4, "char": 1}
FIELD_TYPE_CPP = {
    "type": "Type", "u8": "U8", "u16": "U16", "u32": "U32", "u64": "U64", "price": "Price",
    "sprice4": "SPrice4", "ts": "Timestamp", "alpha": "Alpha", "char": "Char", "applen": "AppLen",
}
RULES = {"Req": "Required", "Opt": "Optional", "Opt*": "OptionalUnlessUserRefIdx", "none": "None"}
EXPECTED_COUNTS = {"in": 8, "out": 17}
EXPECTED_TAGS = 26
OTHER = 0x000F


class SpecError(Exception):
    pass


@dataclass
class EnumValue:
    name: str
    raw: str
    code: int  # byte value (char enums) or u16 code
    direction: str
    doc: str


@dataclass
class Enum:
    name: str
    type: str  # char | u16
    values: list[EnumValue] = field(default_factory=list)

    def allowed(self, direction: str, subset: list[str] | None) -> list[EnumValue]:
        out = []
        for v in self.values:
            if direction != "both" and v.direction not in ("both", direction):
                continue
            if subset is not None and v.raw not in subset:
                continue
            out.append(v)
        return out


@dataclass
class Check:
    kind: str  # None | Enum | LimitOrMarket | ZeroOrLimit | Range
    lo: int = 0
    hi: int = 0


@dataclass
class Field:
    name: str
    offset: int
    length: int
    type: str
    enum: str | None
    subset: list[str] | None
    check: Check
    reject: int
    doc: str


@dataclass
class Message:
    letter: str
    direction: str
    name: str
    fixed_len: int
    rule: str
    allowed_tags: list[int]
    doc: str
    fields: list[Field] = field(default_factory=list)

    @property
    def base_len(self) -> int:
        return self.fixed_len if self.rule == "none" else self.fixed_len - 2

    @property
    def min_len(self) -> int:
        return self.fixed_len if self.rule in ("none", "Req") else self.base_len


@dataclass
class TagDef:
    number: int
    name: str
    length: int
    type: str
    enum: str | None
    check: Check
    reject: int
    doc: str


@dataclass
class Spec:
    messages: list[Message]
    tags: dict[int, TagDef]
    enums: dict[str, Enum]


# ----------------------------------------------------------------------------- parsing


def snake(name: str) -> str:
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    return s.lower()


def parse_int(s: str) -> int:
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def parse_check(s: str, where: str) -> Check:
    s = s.strip()
    if not s:
        return Check("None")
    if s == "limit_or_market":
        return Check("LimitOrMarket")
    if s == "zero_or_limit":
        return Check("ZeroOrLimit")
    m = re.fullmatch(r"range:(\d+):(\d+)", s)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        if lo > hi:
            raise SpecError(f"{where}: empty range {s}")
        return Check("Range", lo, hi)
    raise SpecError(f"{where}: unknown check '{s}'")


def parse_enum_value(raw: str, etype: str, where: str) -> int:
    if etype == "u16":
        v = parse_int(raw)
        if not 0 <= v <= 0xFFFF:
            raise SpecError(f"{where}: u16 code out of range")
        return v
    if len(raw) == 1:
        return ord(raw)
    if raw.lower().startswith("0x"):
        v = int(raw, 16)
        if not 0 <= v <= 0xFF:
            raise SpecError(f"{where}: byte value out of range")
        return v
    raise SpecError(f"{where}: char enum value must be one character or 0xNN, got '{raw}'")


def load(path: pathlib.Path) -> Spec:
    messages: list[Message] = []
    by_key: dict[tuple[str, str], Message] = {}
    tags: dict[int, TagDef] = {}
    enums: dict[str, Enum] = {}
    pending_fields: list[tuple[int, dict]] = []
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        expected = ["kind", "message", "direction", "field", "offset", "len", "type", "enum", "check", "reject",
                    "appendage", "allowed_tags", "value", "doc"]
        if reader.fieldnames != expected:
            raise SpecError(f"CSV header mismatch: {reader.fieldnames}")
        for lineno, row in enumerate(reader, start=2):
            kind = (row["kind"] or "").strip()
            if not kind or kind.startswith("#"):
                continue
            where = f"{path.name}:{lineno}"
            if kind == "msg":
                letter = row["message"].strip()
                direction = row["direction"].strip()
                if len(letter) != 1 or direction not in ("in", "out"):
                    raise SpecError(f"{where}: bad message key")
                rule = row["appendage"].strip()
                if rule not in RULES:
                    raise SpecError(f"{where}: bad appendage rule '{rule}'")
                allowed = [int(t) for t in row["allowed_tags"].split()] if row["allowed_tags"].strip() else []
                m = Message(letter, direction, row["field"].strip(), int(row["len"]), rule, allowed,
                            row["doc"].strip())
                if (direction, letter) in by_key:
                    raise SpecError(f"{where}: duplicate message {direction} {letter}")
                by_key[(direction, letter)] = m
                messages.append(m)
            elif kind == "field":
                pending_fields.append((lineno, row))
            elif kind == "tag":
                num = int(row["value"])
                if num in tags:
                    raise SpecError(f"{where}: duplicate tag {num}")
                enum = row["enum"].strip() or None
                tags[num] = TagDef(num, row["field"].strip(), int(row["len"]), row["type"].strip(), enum,
                                   parse_check(row["check"], where),
                                   parse_int(row["reject"]) if row["reject"].strip() else OTHER, row["doc"].strip())
            elif kind == "enum":
                ename = row["enum"].strip()
                etype = row["type"].strip()
                if etype not in ("char", "u16"):
                    raise SpecError(f"{where}: enum type must be char or u16")
                e = enums.setdefault(ename, Enum(ename, etype))
                if e.type != etype:
                    raise SpecError(f"{where}: enum {ename} mixes types")
                direction = row["direction"].strip() or "both"
                if direction not in ("both", "in", "out"):
                    raise SpecError(f"{where}: bad enum direction")
                raw = row["value"]
                if raw.strip() != raw and raw.strip() != "":
                    raise SpecError(f"{where}: stray whitespace in enum value")
                code = parse_enum_value(raw, etype, where)
                e.values.append(EnumValue(row["field"].strip(), raw, code, direction, row["doc"].strip()))
            else:
                raise SpecError(f"{where}: unknown row kind '{kind}'")

    for lineno, row in pending_fields:
        where = f"{path.name}:{lineno}"
        key = (row["direction"].strip(), row["message"].strip())
        if key not in by_key:
            raise SpecError(f"{where}: field for unknown message {key}")
        enum_col = row["enum"].strip()
        subset = None
        enum = None
        if enum_col:
            if ":" in enum_col:
                enum, sub = enum_col.split(":", 1)
                subset = sub.split("|")
            else:
                enum = enum_col
        check = parse_check(row["check"], where)
        if enum and check.kind == "None":
            check = Check("Enum")
        elif enum:
            raise SpecError(f"{where}: a field has either an enum or a check, not both")
        by_key[key].fields.append(
            Field(row["field"].strip(), int(row["offset"]), int(row["len"]), row["type"].strip(), enum, subset, check,
                  parse_int(row["reject"]) if row["reject"].strip() else OTHER, row["doc"].strip()))
    return Spec(messages, tags, enums)


# ----------------------------------------------------------------------------- lint


def lint(spec: Spec) -> list[str]:
    errs: list[str] = []
    counts = {"in": 0, "out": 0}
    reject_codes = {v.code for v in spec.enums.get("RejectReason", Enum("RejectReason", "u16")).values}
    used_enums: set[str] = set()

    for m in spec.messages:
        counts[m.direction] += 1
        tag = f"{m.direction}:{m.letter} {m.name}"
        if not m.fields:
            errs.append(f"{tag}: no fields")
            continue
        # Tiling: contiguous from 0, no gaps or overlaps, total == spec fixed length.
        pos = 0
        for fd in m.fields:
            if fd.offset != pos:
                errs.append(f"{tag}: field {fd.name} at offset {fd.offset}, expected {pos} (gap or overlap)")
            pos = fd.offset + fd.length
            if fd.type not in FIXED_TYPE_LEN and fd.type != "alpha":
                errs.append(f"{tag}: field {fd.name} has unknown type {fd.type}")
            elif fd.type != "alpha" and FIXED_TYPE_LEN[fd.type] != fd.length:
                errs.append(f"{tag}: field {fd.name} length {fd.length} does not match type {fd.type}")
            if fd.enum:
                used_enums.add(fd.enum)
                e = spec.enums.get(fd.enum)
                if e is None:
                    errs.append(f"{tag}: field {fd.name} references unknown enum {fd.enum}")
                else:
                    if (e.type == "char") != (fd.type == "char") or (e.type == "u16") != (fd.type == "u16"):
                        errs.append(f"{tag}: field {fd.name} type {fd.type} does not match enum {e.name}")
                    if fd.subset is not None:
                        raws = {v.raw for v in e.values}
                        for s in fd.subset:
                            if s not in raws:
                                errs.append(f"{tag}: field {fd.name} subset value '{s}' not in {e.name}")
                    if not e.allowed(m.direction, fd.subset):
                        errs.append(f"{tag}: field {fd.name} allows no values")
            elif fd.type == "char":
                errs.append(f"{tag}: char field {fd.name} must reference an enum")
            if fd.check.kind in ("LimitOrMarket", "ZeroOrLimit") and fd.type != "price":
                errs.append(f"{tag}: price check on non-price field {fd.name}")
            if fd.check.kind == "Range" and fd.type not in ("u8", "u16", "u32", "u64"):
                errs.append(f"{tag}: range check on non-integer field {fd.name}")
            if fd.check.kind != "None" and m.direction != "in" and fd.check.kind != "Enum":
                errs.append(f"{tag}: value checks other than enums apply to inbound fields only ({fd.name})")
            if reject_codes and fd.reject not in reject_codes:
                errs.append(f"{tag}: field {fd.name} reject code 0x{fd.reject:04X} is not a RejectReason")
        if pos != m.fixed_len:
            errs.append(f"{tag}: fields cover {pos} bytes, spec fixed length is {m.fixed_len}")
        first = m.fields[0]
        if first.name != "Type" or first.type != "type" or first.offset != 0:
            errs.append(f"{tag}: first field must be Type at offset 0")
        names = [fd.name for fd in m.fields]
        if len(set(names)) != len(names):
            errs.append(f"{tag}: duplicate field names")
        applens = [fd for fd in m.fields if fd.type == "applen"]
        if m.rule == "none":
            if applens:
                errs.append(f"{tag}: rule none but has an AppendageLength field")
            if m.allowed_tags:
                errs.append(f"{tag}: rule none but lists allowed tags")
        else:
            if len(applens) != 1 or m.fields[-1].type != "applen":
                errs.append(f"{tag}: AppendageLength must be the last field")
        if m.direction == "out" and (len(m.fields) < 2 or m.fields[1].name != "Timestamp" or m.fields[1].offset != 1):
            errs.append(f"{tag}: outbound messages start with Type then Timestamp")
        if m.direction == "in" and m.rule == "Opt*":
            errs.append(f"{tag}: Opt* is an outbound rule")
        if m.direction == "out" and m.rule == "Opt":
            errs.append(f"{tag}: Opt is an inbound rule")
        for t in m.allowed_tags:
            if t not in spec.tags:
                errs.append(f"{tag}: allowed tag {t} is not in the registry")
        if len(set(m.allowed_tags)) != len(m.allowed_tags):
            errs.append(f"{tag}: duplicate allowed tags")
        if m.allowed_tags != sorted(m.allowed_tags):
            errs.append(f"{tag}: allowed tags must be sorted")
        if m.rule != "none" and 28 not in m.allowed_tags:
            errs.append(f"{tag}: every appendage-bearing message accepts UserRefIdx (28)")

    letters = {}
    for m in spec.messages:
        if (m.direction, m.letter) in letters:
            errs.append(f"duplicate message {m.direction}:{m.letter}")
        letters[(m.direction, m.letter)] = m
    for d, n in EXPECTED_COUNTS.items():
        if counts[d] != n:
            errs.append(f"expected {n} {d}bound messages, found {counts[d]}")

    if len(spec.tags) != EXPECTED_TAGS:
        errs.append(f"expected {EXPECTED_TAGS} tags, found {len(spec.tags)}")
    tag_names = set()
    for t in spec.tags.values():
        if not 1 <= t.number <= 31:
            errs.append(f"tag {t.number}: out of the supported range 1..31")
        if t.name in tag_names:
            errs.append(f"tag {t.number}: duplicate name {t.name}")
        tag_names.add(t.name)
        if t.type == "alpha":
            if t.length < 1:
                errs.append(f"tag {t.number}: bad alpha length")
        elif t.type not in TAG_TYPE_LEN:
            errs.append(f"tag {t.number}: unknown type {t.type}")
        elif TAG_TYPE_LEN[t.type] != t.length:
            errs.append(f"tag {t.number}: length {t.length} does not match type {t.type}")
        if t.enum:
            used_enums.add(t.enum)
            if t.enum not in spec.enums:
                errs.append(f"tag {t.number}: unknown enum {t.enum}")
            elif t.type != "char":
                errs.append(f"tag {t.number}: enum tags must be char")
        elif t.type == "char":
            errs.append(f"tag {t.number}: char tag must reference an enum")
        if t.check.kind == "Range" and t.type not in ("u8", "u16", "u32", "u64"):
            errs.append(f"tag {t.number}: range check on non-integer tag")
        if t.check.kind in ("LimitOrMarket", "ZeroOrLimit") and t.type != "price":
            errs.append(f"tag {t.number}: price check on non-price tag")
        if reject_codes and t.reject not in reject_codes:
            errs.append(f"tag {t.number}: reject code 0x{t.reject:04X} is not a RejectReason")
    for t in spec.tags.values():
        if not any(t.number in m.allowed_tags for m in spec.messages):
            errs.append(f"tag {t.number}: not allowed on any message")

    for e in spec.enums.values():
        names = [v.name for v in e.values]
        codes = [v.code for v in e.values]
        if len(set(names)) != len(names):
            errs.append(f"enum {e.name}: duplicate enumerator names")
        if len(set(codes)) != len(codes):
            errs.append(f"enum {e.name}: duplicate wire values")
        if e.name not in used_enums:
            errs.append(f"enum {e.name}: not referenced by any field or tag (enum completeness)")
    return errs


# ----------------------------------------------------------------------------- C++ emission

HEADER_BANNER = """\
// GENERATED by tools/specgen/specgen.py from src/proto/ouch50/spec/ouch50_fields.csv.
// DO NOT EDIT. Regenerate with: python3 tools/specgen/specgen.py
// OUCH 5.0 rev 1.05 (Nasdaq, updated October 2025).
"""


def cpp_char(code: int) -> str:
    if code == 0x20:
        return "' '"
    c = chr(code)
    if c in "'\\":
        return "'\\" + c + "'"
    if 0x21 <= code <= 0x7E:
        return f"'{c}'"
    return f"static_cast<char>(0x{code:02X})"


def byteset_words(codes: list[int]) -> list[int]:
    w = [0, 0, 0, 0]
    for c in codes:
        w[c >> 6] |= 1 << (c & 63)
    return w


def mask_of(tags: list[int]) -> int:
    m = 0
    for t in tags:
        m |= 1 << t
    return m


class Emitter:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, s: str = "") -> None:
        self.lines.append(s)

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def msg_ns(m: Message) -> str:
    return "in" if m.direction == "in" else "out"


def cpp_value_type(spec: Spec, typ: str, length: int, enum: str | None) -> str:
    if typ == "char":
        return enum
    if typ == "u16" and enum:
        return enum
    return {
        "u8": "std::uint8_t", "u16": "std::uint16_t", "u32": "std::uint32_t", "u64": "std::uint64_t",
        "price": "std::uint64_t", "ts": "std::uint64_t", "sprice4": "std::int32_t",
    }.get(typ, f"Alpha<{length}>")


def set_name(enum: str, direction: str, subset: list[str] | None, spec: Spec) -> str:
    base = f"kSet{enum}{direction.capitalize()}"
    if subset is not None:
        codes = sorted(parse_enum_value(s, spec.enums[enum].type, enum) for s in subset)
        base += "_" + "".join(f"{c:02X}" for c in codes)
    return base


def emit_layout(spec: Spec) -> str:
    e = Emitter()
    e(HEADER_BANNER.rstrip())
    e("#pragma once")
    e("#include <array>")
    e("#include <cstddef>")
    e("#include <cstdint>")
    e("#include <string_view>")
    e()
    e('#include "proto/ouch50/spec_types.h"')
    e()
    e("namespace lle::ouch50 {")
    e()
    e("// " + "-" * 76 + " enumerations")
    for en in spec.enums.values():
        under = "char" if en.type == "char" else "std::uint16_t"
        e(f"enum class {en.name} : {under} {{")
        for v in en.values:
            val = cpp_char(v.code) if en.type == "char" else f"0x{v.code:04X}"
            doc = f"  // {v.doc}" if v.doc else ""
            dirnote = f" [{v.direction}]" if v.direction != "both" and en.name not in ("RejectReason",) else ""
            if dirnote and not doc:
                doc = f"  //{dirnote}"
            elif dirnote:
                doc += dirnote
            e(f"  {v.name} = {val},{doc}")
        e("};")
        e()
    # Name lookup for diagnostics.
    for en in spec.enums.values():
        under = "char" if en.type == "char" else "std::uint16_t"
        e(f"[[nodiscard]] constexpr std::string_view to_string({en.name} v) noexcept {{")
        e("  switch (v) {")
        for v in en.values:
            e(f"    case {en.name}::{v.name}: return \"{v.name}\";")
        e("  }")
        e("  return {};")
        e("}")
    e()
    e("// " + "-" * 76 + " value sets (direction-filtered)")
    sets: dict[str, list[int]] = {}
    set_enum: dict[str, str] = {}

    def need_set(enum: str, direction: str, subset: list[str] | None) -> str:
        name = set_name(enum, direction, subset, spec)
        if name not in sets:
            sets[name] = sorted(v.code for v in spec.enums[enum].allowed(direction, subset))
            set_enum[name] = enum
        return name

    field_set: dict[tuple[str, str, str], str] = {}
    for m in spec.messages:
        for fd in m.fields:
            if fd.enum:
                field_set[(m.direction, m.letter, fd.name)] = need_set(fd.enum, m.direction, fd.subset)
    tag_set: dict[int, str] = {}
    for t in spec.tags.values():
        if t.enum:
            tag_set[t.number] = need_set(t.enum, "both", None)
    for en in spec.enums.values():
        for d in ("both", "in", "out"):
            if en.allowed(d, None):
                need_set(en.name, d, None)
    for name in sorted(sets):
        if spec.enums[set_enum[name]].type == "char":
            w = byteset_words(sets[name])
            words = ", ".join(f"0x{x:016X}ull" for x in w)
            e(f"inline constexpr ByteSet {name}{{{{{words}}}}};")
        else:
            vals = ", ".join(f"0x{x:04X}" for x in sets[name])
            e(f"inline constexpr std::uint16_t {name}[] = {{{vals}}};")
    e()
    e("// Membership of every enumerator, by direction.")
    for en in spec.enums.values():
        for d in ("in", "out"):
            name = set_name(en.name, d, None, spec)
            if not en.allowed(d, None):
                e(f"[[nodiscard]] constexpr bool is_valid_{d}bound({en.name}) noexcept {{ return false; }}")
            elif en.type == "char":
                e(f"[[nodiscard]] constexpr bool is_valid_{d}bound({en.name} v) noexcept "
                  f"{{ return {name}.contains(static_cast<std::uint8_t>(v)); }}")
            else:
                e(f"[[nodiscard]] constexpr bool is_valid_{d}bound({en.name} v) noexcept {{")
                e(f"  for (const std::uint16_t c : {name})")
                e("    if (c == static_cast<std::uint16_t>(v)) return true;")
                e("  return false;")
                e("}")
    e()

    # --- tags
    e("// " + "-" * 76 + " TagValue registry (Appendix A)")
    e("enum class Tag : std::uint8_t {")
    for t in sorted(spec.tags.values(), key=lambda x: x.number):
        e(f"  {t.name} = {t.number},  // {t.length} byte(s) {t.type}{(' ' + t.enum) if t.enum else ''}")
    e("};")
    e()
    e(f"inline constexpr std::size_t kTagCount = {len(spec.tags)};")
    e("inline constexpr std::size_t kTagTableSize = 32;")
    e(f"inline constexpr std::uint32_t kKnownTags = 0x{mask_of(list(spec.tags)):08X}u;")
    e()
    e("[[nodiscard]] constexpr std::uint32_t tag_bit(Tag t) noexcept { return 1u << static_cast<unsigned>(t); }")
    e()
    e("inline constexpr std::array<TagDesc, kTagTableSize> kTags = {{")
    for n in range(32):
        t = spec.tags.get(n)
        if t is None:
            e(f"    {{nullptr, {n}, 0, FieldType::U8, CheckKind::None, 0, nullptr, 0, 0}},")
            continue
        chk = t.check.kind
        chars = f"&{tag_set[n]}" if t.enum else "nullptr"
        if t.enum:
            chk = "Enum"
        e(f"    {{\"{t.name}\", {n}, {t.length}, FieldType::{FIELD_TYPE_CPP[t.type]}, CheckKind::{chk}, "
          f"0x{t.reject:04X}, {chars}, {t.check.lo}ull, {t.check.hi}ull}},")
    e("}};")
    e()
    e("[[nodiscard]] constexpr const TagDesc* find_tag(std::uint8_t tag) noexcept {")
    e("  return (tag < kTagTableSize && kTags[tag].value_len != 0) ? &kTags[tag] : nullptr;")
    e("}")
    e()

    # --- per-message layout constants
    e("// " + "-" * 76 + " per-message layout")
    e("namespace layout {")
    for d in ("in", "out"):
        e(f"namespace {d} {{")
        for m in [x for x in spec.messages if x.direction == d]:
            e(f"// {m.doc}")
            e(f"struct {m.name} {{")
            e(f"  static constexpr char kType = {cpp_char(ord(m.letter))};")
            e(f"  static constexpr std::size_t kFixedLen = {m.fixed_len};")
            e(f"  static constexpr std::size_t kBaseLen = {m.base_len};")
            e(f"  static constexpr std::size_t kMinLen = {m.min_len};")
            e(f"  static constexpr AppendageRule kRule = AppendageRule::{RULES[m.rule]};")
            e(f"  static constexpr std::uint32_t kAllowedTags = 0x{mask_of(m.allowed_tags):08X}u;")
            maxlen = m.fixed_len + sum(2 + spec.tags[t].length for t in m.allowed_tags)
            e(f"  static constexpr std::size_t kMaxLen = {maxlen};  // fixed part + every allowed tag once")
            for fd in m.fields:
                e(f"  static constexpr std::size_t k{fd.name}Off = {fd.offset};")
                e(f"  static constexpr std::size_t k{fd.name}Len = {fd.length};")
            e("};")
        e(f"}}  // namespace {d}")
    e("}  // namespace layout")
    e()
    e("// Tiling: every field starts where the previous one ends; the last ends at the spec length.")
    for m in spec.messages:
        q = f"layout::{msg_ns(m)}::{m.name}"
        prev = None
        for fd in m.fields:
            if prev is None:
                e(f"static_assert({q}::k{fd.name}Off == 0);")
            else:
                e(f"static_assert({q}::k{fd.name}Off == {q}::k{prev.name}Off + {q}::k{prev.name}Len);")
            prev = fd
        e(f"static_assert({q}::k{prev.name}Off + {q}::k{prev.name}Len == {q}::kFixedLen);")
        e(f"static_assert({q}::kFixedLen == {m.fixed_len});")
    e()

    # --- descriptor tables
    e("// " + "-" * 76 + " descriptor tables (strict validation walks these)")
    e("namespace detail {")
    for m in spec.messages:
        e(f"inline constexpr FieldDesc kFields{m.direction.capitalize()}{m.name}[] = {{")
        for fd in m.fields:
            chars = "nullptr"
            codes = "nullptr"
            count = 0
            if fd.enum:
                sname = field_set[(m.direction, m.letter, fd.name)]
                if spec.enums[fd.enum].type == "char":
                    chars = f"&{sname}"
                else:
                    codes = sname
                    count = len(sets[sname])
            e(f"    {{\"{fd.name}\", {fd.offset}, {fd.length}, FieldType::{FIELD_TYPE_CPP[fd.type]}, "
              f"CheckKind::{fd.check.kind}, 0x{fd.reject:04X}, {chars}, {codes}, {count}, {fd.check.lo}ull, "
              f"{fd.check.hi}ull}},")
        e("};")
    e("}  // namespace detail")
    e()
    for d, label in (("in", "Inbound"), ("out", "Outbound")):
        ms = [x for x in spec.messages if x.direction == d]
        e(f"inline constexpr std::array<MsgDesc, {len(ms)}> k{label}Messages = {{{{")
        for m in ms:
            e(f"    {{\"{m.name}\", {cpp_char(ord(m.letter))}, Direction::{label}, AppendageRule::{RULES[m.rule]}, "
              f"{m.fixed_len}, {m.base_len}, 0x{mask_of(m.allowed_tags):08X}u, "
              f"detail::kFields{d.capitalize()}{m.name}, {len(m.fields)}}},")
        e("}};")
        e(f"inline constexpr std::array<std::int8_t, 256> k{label}Index = [] {{")
        e("  std::array<std::int8_t, 256> t{};")
        e("  for (auto& v : t) v = -1;")
        for i, m in enumerate(ms):
            e(f"  t[static_cast<unsigned char>({cpp_char(ord(m.letter))})] = {i};")
        e("  return t;")
        e("}();")
        e(f"[[nodiscard]] constexpr const MsgDesc* find_{d}bound(std::uint8_t type) noexcept {{")
        e(f"  const int i = k{label}Index[type];")
        e(f"  return i < 0 ? nullptr : &k{label}Messages[static_cast<std::size_t>(i)];")
        e("}")
        e()

    max_in = max(m.fixed_len + sum(2 + spec.tags[t].length for t in m.allowed_tags)
                 for m in spec.messages if m.direction == "in")
    max_out = max(m.fixed_len + sum(2 + spec.tags[t].length for t in m.allowed_tags)
                  for m in spec.messages if m.direction == "out")
    e("// Longest legal message: fixed part + every allowed tag once (duplicates are illegal).")
    e("// kMaxInboundOuchLen sizes the gateway->sequencer queue slot (08-concurrency-runtime s5);")
    e("// a longer inbound message is malformed by definition.")
    e(f"inline constexpr std::size_t kMaxInboundOuchLen = {max_in};")
    e(f"inline constexpr std::size_t kMaxOutboundOuchLen = {max_out};")
    for m in spec.messages:
        e(f"static_assert(layout::{msg_ns(m)}::{m.name}::kMaxLen <= kMax{'In' if m.direction == 'in' else 'Out'}"
          f"boundOuchLen);")
    e()
    e("}  // namespace lle::ouch50")
    return e.text()


def emit_messages(spec: Spec) -> str:
    e = Emitter()
    e(HEADER_BANNER.rstrip())
    e("#pragma once")
    e("#include <cstddef>")
    e("#include <cstdint>")
    e("#include <span>")
    e("#include <utility>")
    e()
    e('#include "common/alpha.h"')
    e('#include "common/endian.h"')
    e('#include "proto/ouch50/message_view.h"')
    e('#include "proto/ouch50/ouch50_layout.gen.h"')
    e('#include "proto/ouch50/tagvalue.h"')
    e()
    e("namespace lle::ouch50 {")
    e()
    for d, label in (("in", "Inbound"), ("out", "Outbound")):
        e(f"enum class {label}Type : char {{")
        for m in [x for x in spec.messages if x.direction == d]:
            e(f"  {m.name} = {cpp_char(ord(m.letter))},")
        e("};")
    e()

    def read_expr(fd: Field) -> str:
        p = f"p + {fd.offset}"
        if fd.type == "u8":
            return f"std::to_integer<std::uint8_t>(p[{fd.offset}])"
        if fd.type == "u16":
            base = f"load_be16({p})"
            return f"static_cast<{fd.enum}>({base})" if fd.enum else base
        if fd.type == "u32":
            return f"load_be32({p})"
        if fd.type in ("u64", "price", "ts"):
            return f"load_be64({p})"
        if fd.type == "char":
            return f"static_cast<{fd.enum}>(std::to_integer<char>(p[{fd.offset}]))"
        if fd.type == "alpha":
            return f"Alpha<{fd.length}>::from_wire({p})"
        raise SpecError(fd.type)

    def write_stmt(fd: Field, member: str) -> str:
        p = f"p + {fd.offset}"
        if fd.type == "u8":
            return f"p[{fd.offset}] = static_cast<std::byte>({member});"
        if fd.type == "u16":
            v = f"static_cast<std::uint16_t>({member})" if fd.enum else member
            return f"store_be16({p}, {v});"
        if fd.type == "u32":
            return f"store_be32({p}, {member});"
        if fd.type in ("u64", "price", "ts"):
            return f"store_be64({p}, {member});"
        if fd.type == "char":
            return f"p[{fd.offset}] = static_cast<std::byte>(std::to_underlying({member}));"
        if fd.type == "alpha":
            return f"{member}.to_wire({p});"
        raise SpecError(fd.type)

    for d in ("in", "out"):
        e(f"namespace {d} {{")
        e()
        for m in [x for x in spec.messages if x.direction == d]:
            q = f"layout::{d}::{m.name}"
            data = [fd for fd in m.fields if fd.type not in ("type", "applen")]
            e(f"// {m.doc}")
            e(f"struct {m.name} {{")
            e(f"  using Layout = {q};")
            e(f"  static constexpr char kType = Layout::kType;")
            e(f"  static constexpr Direction kDirection = Direction::{'Inbound' if d == 'in' else 'Outbound'};")
            e(f"  static constexpr AppendageRule kRule = Layout::kRule;")
            e(f"  static constexpr std::size_t kFixedLen = Layout::kFixedLen;")
            e(f"  static constexpr std::size_t kBaseLen = Layout::kBaseLen;")
            e(f"  static constexpr std::size_t kMinLen = Layout::kMinLen;")
            e(f"  static constexpr std::size_t kMaxLen = Layout::kMaxLen;")
            e(f"  static constexpr std::uint32_t kAllowedTags = Layout::kAllowedTags;")
            e(f"  static constexpr const char* kName = \"{m.name}\";")
            e()
            for fd in data:
                ctype = cpp_value_type(spec, fd.type, fd.length, fd.enum)
                init = "{}"
                if fd.enum:
                    first = spec.enums[fd.enum].allowed(d, fd.subset)[0]
                    init = f"{{{fd.enum}::{first.name}}}"
                e(f"  {ctype} {snake(fd.name)}{init};")
            e()
            e("  // Writes the fixed part up to (not including) Appendage Length.")
            e("  void encode_base(std::byte* p) const noexcept {")
            e(f"    p[0] = static_cast<std::byte>(kType);")
            for fd in data:
                e(f"    {write_stmt(fd, snake(fd.name))}")
            e("  }")
            e(f"  [[nodiscard]] static {m.name} decode_base(const std::byte* p) noexcept {{")
            e(f"    {m.name} m;")
            for fd in data:
                e(f"    m.{snake(fd.name)} = {read_expr(fd)};")
            if not data:
                e("    (void)p;")
            e("    return m;")
            e("  }")
            e(f"  friend bool operator==(const {m.name}&, const {m.name}&) = default;")
            e("};")
            e()
            e(f"class {m.name}View : public MessageView<{m.name}> {{")
            e(" public:")
            e("  using MessageView::MessageView;")
            for fd in data:
                ctype = cpp_value_type(spec, fd.type, fd.length, fd.enum)
                expr = read_expr(fd).replace("p[", "p()[").replace("(p + ", "(p() + ")
                e(f"  [[nodiscard]] {ctype} {snake(fd.name)}() const noexcept {{ return {expr}; }}")
            e("};")
            e()
            e(f"// Calls f(name, value) for every fixed field after Type, in wire order.")
            e(f"template <class F>")
            e(f"void for_each_field(const {m.name}View& v, F&& f) {{")
            for fd in data:
                e(f"  f(\"{fd.name}\", v.{snake(fd.name)}());")
            if not data:
                e("  (void)v;")
                e("  (void)f;")
            e("}")
            e()
        e(f"}}  // namespace {d}")
        e()

    # Dispatch by type letter.
    for d, label in (("in", "Inbound"), ("out", "Outbound")):
        e(f"// Invokes f with the typed {d}bound view for `type`; returns false for an unknown type.")
        e("template <class F>")
        e(f"bool visit_{d}bound(char type, std::span<const std::byte> bytes, F&& f) {{")
        e("  switch (type) {")
        for m in [x for x in spec.messages if x.direction == d]:
            e(f"    case {cpp_char(ord(m.letter))}: f({d}::{m.name}View(bytes)); return true;")
        e("    default: return false;")
        e("  }")
        e("}")
        e()

    # TagSet
    tags = sorted(spec.tags.values(), key=lambda x: x.number)
    e("// Decoded appendage: one member per registry tag plus a presence mask.")
    e("struct TagSet {")
    e("  std::uint32_t present = 0;")
    for t in tags:
        ctype = cpp_value_type(spec, t.type, t.length, t.enum)
        e(f"  {ctype} {snake(t.name)}{{}};")
    e()
    e("  [[nodiscard]] bool has(Tag t) const noexcept { return (present & tag_bit(t)) != 0; }")
    e("  void clear(Tag t) noexcept { present &= ~tag_bit(t); }")
    for t in tags:
        ctype = cpp_value_type(spec, t.type, t.length, t.enum)
        e(f"  TagSet& set_{snake(t.name)}({ctype} v) noexcept {{")
        e(f"    {snake(t.name)} = v;")
        e(f"    present |= tag_bit(Tag::{t.name});")
        e("    return *this;")
        e("  }")
    e("  friend bool operator==(const TagSet& a, const TagSet& b) noexcept {")
    e("    if (a.present != b.present) return false;")
    for t in tags:
        e(f"    if (a.has(Tag::{t.name}) && !(a.{snake(t.name)} == b.{snake(t.name)})) return false;")
    e("    return true;")
    e("  }")
    e("};")
    e()
    e("// Writes every present tag in ascending tag order.")
    e("inline void put_tags(TagValueWriter& w, const TagSet& s) noexcept {")
    for t in tags:
        name = snake(t.name)
        if t.type == "char":
            stmt = f"w.put_char(Tag::{t.name}, std::to_underlying(s.{name}));"
        elif t.type == "alpha":
            stmt = f"w.put_alpha(Tag::{t.name}, s.{name});"
        else:
            fn = {"u8": "put_u8", "u16": "put_u16", "u32": "put_u32", "u64": "put_u64", "price": "put_u64",
                  "sprice4": "put_i32"}[t.type]
            stmt = f"w.{fn}(Tag::{t.name}, s.{name});"
        e(f"  if (s.has(Tag::{t.name})) {stmt}")
    e("}")
    e()
    e("// Fills `out` from an appendage. Unknown tags are skipped (clients must tolerate")
    e("// them, FAQ Q8); a later duplicate overwrites an earlier one. Returns false on a")
    e("// malformed element or a known tag whose value has the wrong size.")
    e("[[nodiscard]] inline bool parse_tags(TagValueRange range, TagSet& out) noexcept {")
    e("  TagValueIterator it = range.begin();")
    e("  for (; it != std::default_sentinel; ++it) {")
    e("    const TagValue& tv = *it;")
    e("    const TagDesc* d = find_tag(tv.tag);")
    e("    if (d == nullptr) continue;")
    e("    if (tv.value.size() != d->value_len) return false;")
    e("    switch (static_cast<Tag>(tv.tag)) {")
    for t in tags:
        name = snake(t.name)
        if t.type == "char":
            rd = f"static_cast<{t.enum}>(tv.ch())"
        elif t.type == "alpha":
            rd = f"tv.alpha<{t.length}>()"
        else:
            rd = {"u8": "tv.u8()", "u16": "tv.u16()", "u32": "tv.u32()", "u64": "tv.u64()", "price": "tv.u64()",
                  "sprice4": "tv.i32()"}[t.type]
        e(f"      case Tag::{t.name}: out.set_{name}({rd}); break;")
    e("    }")
    e("  }")
    e("  return !it.malformed();")
    e("}")
    e()
    e("}  // namespace lle::ouch50")
    return e.text()


# ----------------------------------------------------------------------------- markdown


def emit_markdown(spec: Spec) -> str:
    out: list[str] = []
    w = out.append
    w("# OUCH 5.0 (rev 1.05) layouts")
    w("")
    w("Generated by `tools/specgen/specgen.py --markdown` from `src/proto/ouch50/spec/ouch50_fields.csv`.")
    w("")
    for d, label in (("in", "Inbound"), ("out", "Outbound")):
        w(f"## {label} messages")
        w("")
        for m in [x for x in spec.messages if x.direction == d]:
            w(f"### `{m.letter}` {m.name}")
            w("")
            w(f"Fixed length {m.fixed_len} (min {m.min_len}); appendage `{m.rule}`; "
              f"allowed tags: {', '.join(str(t) for t in m.allowed_tags) or 'none'}. {m.doc}")
            w("")
            w("| Field | Offset | Len | Type | Values / check | Reject | Notes |")
            w("|---|---|---|---|---|---|---|")
            for fd in m.fields:
                vals = ""
                if fd.enum:
                    vals = fd.enum + (f" ({'/'.join(fd.subset)})" if fd.subset else "")
                elif fd.check.kind == "Range":
                    vals = f"{fd.check.lo}..{fd.check.hi}"
                elif fd.check.kind != "None":
                    vals = fd.check.kind
                rej = f"0x{fd.reject:04X}" if fd.check.kind != "None" else ""
                w(f"| {fd.name} | {fd.offset} | {fd.length} | {fd.type} | {vals} | {rej} | {fd.doc} |")
            w("")
    w("## TagValue registry")
    w("")
    w("| Tag | Name | Value bytes | Type | Values / check | Notes |")
    w("|---|---|---|---|---|---|")
    for t in sorted(spec.tags.values(), key=lambda x: x.number):
        vals = t.enum or (f"{t.check.lo}..{t.check.hi}" if t.check.kind == "Range" else
                          ("" if t.check.kind == "None" else t.check.kind))
        w(f"| {t.number} | {t.name} | {t.length} | {t.type} | {vals} | {t.doc} |")
    w("")
    max_in = max(m.fixed_len + sum(2 + spec.tags[t].length for t in m.allowed_tags)
                 for m in spec.messages if m.direction == "in")
    w(f"`kMaxInboundOuchLen` = {max_in}.")
    w("")
    w("## Enumerations")
    w("")
    for en in spec.enums.values():
        w(f"### {en.name}")
        w("")
        w("| Value | Name | Direction | Notes |")
        w("|---|---|---|---|")
        for v in en.values:
            shown = f"0x{v.code:04X}" if en.type == "u16" else ("space" if v.code == 0x20 else f"`{chr(v.code)}`")
            w(f"| {shown} | {v.name} | {v.direction} | {v.doc} |")
        w("")
    return "\n".join(out)


# ----------------------------------------------------------------------------- main


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", type=pathlib.Path, default=CSV_PATH)
    ap.add_argument("--check", action="store_true", help="lint and verify the checked-in headers are current")
    ap.add_argument("--markdown", action="store_true", help="print the layout tables to stdout")
    ap.add_argument("--out-dir", type=pathlib.Path, default=None, help="write headers here instead of in place")
    args = ap.parse_args()
    try:
        spec = load(args.csv)
    except SpecError as ex:
        print(f"specgen: {ex}", file=sys.stderr)
        return 1
    errs = lint(spec)
    if errs:
        for x in errs:
            print(f"specgen: lint: {x}", file=sys.stderr)
        return 1
    if args.markdown:
        sys.stdout.write(emit_markdown(spec) + "\n")
        return 0
    outputs = {LAYOUT_PATH: emit_layout(spec), MESSAGES_PATH: emit_messages(spec)}
    if args.check:
        stale = [p for p, text in outputs.items() if not p.exists() or p.read_text() != text]
        for p in stale:
            print(f"specgen: {p.relative_to(ROOT)} is stale; run tools/specgen/specgen.py", file=sys.stderr)
        if not stale:
            print("specgen: OK (lint clean, generated headers current)")
        return 1 if stale else 0
    for p, text in outputs.items():
        dest = (args.out_dir / p.name) if args.out_dir else p
        dest.write_text(text)
        print(f"specgen: wrote {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
