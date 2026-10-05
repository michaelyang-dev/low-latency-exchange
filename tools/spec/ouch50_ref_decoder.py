#!/usr/bin/env python3
"""Independent OUCH 5.0 (rev 1.05) reference decoder (03-protocols s4, s9).

Written straight from the spec tables (OUCH 5.0 s2 inbound, s3 outbound,
Appendix A tags, Appendix B-D enumerations), NOT from ouch50_fields.csv or the
generated C++. Field tables list only names, lengths and value domains; offsets
are accumulated here, so an offset slip in the CSV shows up as a disagreement.

It reproduces the project's validation decisions (src/proto/ouch50/DECISIONS.md):
check order, error kinds, reject codes, the Appendage Length rules.

Canonical verdicts (identical text is produced by fuzz/ouch50/ouch50_diffgen):
  failure: E,<Error>,<offset>,<reject decimal>,<tag>
  success: K,<type>,<appendage length or ->,<field>,...|<tag>:<value>,...
  numbers in decimal; char and alpha fields as lowercase hex of the raw bytes;
  tag values typed when the tag is known and correctly sized, else x<hex>.
Inbound records are checked strictly; outbound records report
  T=<tolerant decode>;S=<strict outbound validation>.

Usage:
  ouch50_ref_decoder.py decode I|O <hex>     print the verdict for one message
  ouch50_ref_decoder.py check [--max-report N] < lines   ("D<TAB>hex<TAB>verdict")
"""
from __future__ import annotations

import argparse
import sys

# ----------------------------------------------------------------------------- spec tables

OTHER = 0x000F
INVALID_DISPLAY = 0x0003
INVALID_PEG_TYPE = 0x0005
INVALID_SIDE = 0x0009
INVALID_QUANTITY = 0x0013
INVALID_CROSS = 0x0014
INVALID_PRICE = 0x001D
INVALID_AIQ = 0x0040

SIDE = "BSTE"
TIF_ENTER = "0356E"
TIF_REPLACE = "0356"
DISPLAY_IN = "YNA"
DISPLAY_OUT = "YNAZ"
CAPACITY = "APRO"
ISO = "YN"
CROSS = "NOCHSREA"
ORDER_STATE = "LD"
EVENT = "SE"
BROKEN = "ECSX"
RESTATED = "RP"
CANCEL = "DEFGHIKQSTUXZe"
LIQUIDITY = "ACeHiJjkKLMmNnOpqRrtu078123 59".replace(" ", "")
AIQ = "*NYDOWRydowrZEPXS01245"
REJECT_CODES = frozenset(list(range(0x01, 0x34)) + [0x40])

MAX_LIMIT = 1_999_999_900
MARKET = (2_000_000_000, 0x7FFFFFFF)

# Field kinds: ("n", len) numeric; ("c", domain) one enumerated char; ("a", len) alpha;
# ("r16",) u16 reject code. Domains for checks: ("dom", chars, reject); ("px",) limit or
# market; ("qty",) 1..999,999.
def num(name, n, check=None):
    return (name, n, "n", check)


def ch(name, domain=None, reject=OTHER):
    return (name, 1, "c", ("dom", domain, reject) if domain is not None else None)


def alpha(name, n):
    return (name, n, "a", None)


TS = num("Timestamp", 8)

# Inbound (s2): fields after Type, the appendage rule, allowed tags. Spec fixed
# lengths (including Appendage Length) are listed separately as a cross-check.
INBOUND = {
    "O": ("EnterOrder", [num("UserRefNum", 4), ch("Side", SIDE, INVALID_SIDE), num("Quantity", 4, ("qty",)),
                         alpha("Symbol", 8), num("Price", 8, ("px",)), ch("TimeInForce", TIF_ENTER),
                         ch("Display", DISPLAY_IN, INVALID_DISPLAY), ch("Capacity", CAPACITY), ch("ISO", ISO),
                         ch("CrossType", CROSS, INVALID_CROSS), alpha("ClOrdID", 14)],
          "req", {2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 15, 16, 17, 24, 25, 26, 28, 29, 30}, 47),
    "U": ("ReplaceOrder", [num("OrigUserRefNum", 4), num("UserRefNum", 4), num("Quantity", 4, ("qty",)),
                           num("Price", 8, ("px",)), ch("TimeInForce", TIF_REPLACE),
                           ch("Display", DISPLAY_IN, INVALID_DISPLAY), ch("ISO", ISO), alpha("ClOrdID", 14)],
          "req", {3, 5, 6, 12, 15, 16, 17, 13, 7, 9, 10, 11, 25, 26, 28, 27, 29, 30}, 40),
    "X": ("CancelOrder", [num("UserRefNum", 4), num("Quantity", 4)], "opt", {28}, 11),
    "M": ("ModifyOrder", [num("UserRefNum", 4), ch("Side", SIDE, INVALID_SIDE), num("Quantity", 4)], "opt",
          {28, 25, 26}, 12),
    "C": ("MassCancel", [num("UserRefNum", 4), alpha("Firm", 4), alpha("Symbol", 8)], "req", {27, 24, 28}, 19),
    "D": ("DisableOrderEntry", [num("UserRefNum", 4), alpha("Firm", 4)], "req", {28}, 11),
    "E": ("EnableOrderEntry", [num("UserRefNum", 4), alpha("Firm", 4)], "req", {28}, 11),
    "Q": ("AccountQuery", [], "opt", {28}, 3),
}

# Outbound (s3). "opt*" = appendage only when echoing a non-zero UserRefIdx.
OUTBOUND = {
    "S": ("SystemEvent", [TS, ch("EventCode", EVENT)], "none", set(), 10),
    "A": ("OrderAccepted", [TS, num("UserRefNum", 4), ch("Side", SIDE), num("Quantity", 4), alpha("Symbol", 8),
                            num("Price", 8), ch("TimeInForce", TIF_ENTER), ch("Display", DISPLAY_OUT),
                            num("OrderReferenceNumber", 8), ch("Capacity", CAPACITY), ch("ISO", ISO),
                            ch("CrossType", CROSS), ch("OrderState", ORDER_STATE), alpha("ClOrdID", 14)],
          "req", {2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 24, 25, 28, 29, 30}, 64),
    "U": ("OrderReplaced", [TS, num("OrigUserRefNum", 4), num("UserRefNum", 4), ch("Side", SIDE), num("Quantity", 4),
                            alpha("Symbol", 8), num("Price", 8), ch("TimeInForce", TIF_ENTER),
                            ch("Display", DISPLAY_OUT), num("OrderReferenceNumber", 8), ch("Capacity", CAPACITY),
                            ch("ISO", ISO), ch("CrossType", CROSS), ch("OrderState", ORDER_STATE),
                            alpha("ClOrdID", 14)],
          "req", {2, 3, 5, 6, 12, 15, 16, 17, 18, 28, 29, 30}, 68),
    "C": ("OrderCanceled", [TS, num("UserRefNum", 4), num("Quantity", 4), ch("Reason", CANCEL)], "opt*", {28}, 20),
    "D": ("AiqCanceled", [TS, num("UserRefNum", 4), num("DecrementShares", 4), ch("Reason", "Q"),
                          num("QuantityPreventedFromTrading", 4), num("ExecutionPrice", 8),
                          ch("LiquidityFlag", LIQUIDITY), ch("AIQStrategy", AIQ)], "opt*", {28}, 34),
    "E": ("OrderExecuted", [TS, num("UserRefNum", 4), num("Quantity", 4), num("Price", 8),
                            ch("LiquidityFlag", LIQUIDITY), num("MatchNumber", 8)], "req", {28}, 36),
    "B": ("BrokenTrade", [TS, num("UserRefNum", 4), num("MatchNumber", 8), ch("Reason", BROKEN),
                          alpha("ClOrdID", 14)], "opt*", {28}, 38),
    "J": ("Rejected", [TS, num("UserRefNum", 4), ("Reason", 2, "r16", None), alpha("ClOrdID", 14)], "opt*",
          {28}, 31),
    "P": ("CancelPending", [TS, num("UserRefNum", 4)], "opt*", {28}, 15),
    "I": ("CancelReject", [TS, num("UserRefNum", 4)], "opt*", {28}, 15),
    "T": ("OrderPriorityUpdate", [TS, num("UserRefNum", 4), num("Price", 8), ch("Display", DISPLAY_OUT),
                                  num("OrderReferenceNumber", 8)], "opt*", {28}, 32),
    "M": ("OrderModified", [TS, num("UserRefNum", 4), ch("Side", SIDE), num("Quantity", 4)], "opt*",
          {28, 25, 26}, 20),
    "R": ("OrderRestated", [TS, num("UserRefNum", 4), ch("Reason", RESTATED)], "req", {22, 23, 1, 28}, 16),
    "X": ("MassCancelResponse", [TS, num("UserRefNum", 4), alpha("Firm", 4), alpha("Symbol", 8)], "req",
          {27, 24, 28}, 27),
    "G": ("DisableOrderEntryResponse", [TS, num("UserRefNum", 4), alpha("Firm", 4)], "req", {28}, 19),
    "K": ("EnableOrderEntryResponse", [TS, num("UserRefNum", 4), alpha("Firm", 4)], "req", {28}, 19),
    "Q": ("AccountQueryResponse", [TS, num("NextUserRefNum", 4)], "opt*", {28}, 15),
}

# Appendix A: tag -> (size, kind, check). Kinds: u (unsigned), s (signed 4-byte
# price), c (char), a (alpha). Checks: ("dom", chars, reject), ("range", lo, hi,
# reject), ("px0", reject) = 0 or a valid limit price.
TAGS = {
    1: (8, "u", None),                                   # SecondaryOrdRefNum
    2: (4, "a", None),                                   # Firm
    3: (4, "u", None),                                   # MinQty
    4: (1, "c", ("dom", "RN ", OTHER)),                  # CustomerType
    5: (4, "u", None),                                   # MaxFloor
    6: (1, "c", ("dom", "LPMRQm", INVALID_PEG_TYPE)),    # PriceType
    7: (4, "s", None),                                   # PegOffset
    9: (8, "u", ("px0", INVALID_PRICE)),                 # DiscretionPrice
    10: (1, "c", ("dom", "LPMR", INVALID_PEG_TYPE)),     # DiscretionPriceType
    11: (4, "s", None),                                  # DiscretionPegOffset
    12: (1, "c", ("dom", "PN", OTHER)),                  # PostOnly
    13: (4, "u", None),                                  # RandomReserves
    14: (4, "a", None),                                  # Route
    15: (4, "u", ("range", 0, 86399, OTHER)),            # ExpireTime (< 86400 s)
    16: (1, "c", ("dom", "YN ", OTHER)),                 # TradeNow
    17: (1, "c", ("dom", "IOTQBD ", OTHER)),             # HandleInst
    18: (1, "c", ("dom", "0123 SN", OTHER)),             # BBO Weight Indicator
    22: (4, "u", None),                                  # Display Quantity
    23: (8, "u", None),                                  # Display Price
    24: (2, "u", None),                                  # Group ID
    25: (1, "c", ("dom", "YN", OTHER)),                  # Shares Located
    26: (4, "a", None),                                  # Locate Broker
    27: (1, "c", ("dom", "BSTE", INVALID_SIDE)),         # Side
    28: (1, "u", None),                                  # UserRefIdx
    29: (1, "c", ("dom", AIQ, INVALID_AIQ)),             # AIQ Strategy
    30: (2, "a", None),                                  # AIQ Group ID
}


def _self_check() -> None:
    assert len(INBOUND) == 8 and len(OUTBOUND) == 17 and len(TAGS) == 26
    assert len(LIQUIDITY) == 29 and len(set(LIQUIDITY)) == 29
    assert len(AIQ) == 22 and len(REJECT_CODES) == 52
    for table, direction in ((INBOUND, "in"), (OUTBOUND, "out")):
        for letter, (name, fields, rule, tags, spec_len) in table.items():
            body = 1 + sum(f[1] for f in fields)
            total = body if rule == "none" else body + 2
            assert total == spec_len, (direction, letter, total, spec_len)
            assert tags <= set(TAGS), (letter, tags - set(TAGS))


_self_check()

# ----------------------------------------------------------------------------- decoding


class Fail(Exception):
    def __init__(self, error: str, offset: int, reason: int = OTHER, tag: int = 0):
        super().__init__(error)
        self.text = f"E,{error},{offset},{reason},{tag}"


def _price_ok(v: int) -> bool:
    return 1 <= v <= MAX_LIMIT or v in MARKET


def _frame(b: bytes, table: dict, lenient_e: bool):
    """Returns (spec entry, base length, has appendage length, appendage start)."""
    if not b:
        raise Fail("Empty", 0)
    letter = chr(b[0])
    entry = table.get(letter)
    if entry is None:
        raise Fail("UnknownType", 0)
    name, fields, rule, tags, spec_len = entry
    base = 1 + sum(f[1] for f in fields)
    n = len(b)
    if rule == "none":
        if n < base:
            raise Fail("TooShort", 0)
        if n > base:
            raise Fail("TooLong", 0)
        return entry, base, False
    optional = rule in ("opt", "opt*") or (lenient_e and letter == "E" and table is OUTBOUND)
    if optional:
        if n < base:
            raise Fail("TooShort", 0)
        if n == base:
            return entry, base, False
        if n == base + 1:
            raise Fail("AppendageLengthMismatch", base)
    elif n < base + 2:
        raise Fail("TooShort", 0)
    app_len = int.from_bytes(b[base:base + 2], "big")
    if base + 2 + app_len != n:
        raise Fail("AppendageLengthMismatch", base)
    pos = base + 2
    while pos < n:
        el = b[pos]
        if el == 0 or pos + 1 + el > n:
            raise Fail("MalformedTagValue", pos)
        pos += 1 + el
    return entry, base, True


def _elements(b: bytes, start: int):
    pos = start
    while pos < len(b):
        el = b[pos]
        yield pos, b[pos + 1], b[pos + 2:pos + 1 + el]
        pos += 1 + el


def _check_fields(fields, b: bytes) -> None:
    off = 1
    for name, size, kind, check in fields:
        if kind == "r16":
            if int.from_bytes(b[off:off + 2], "big") not in REJECT_CODES:
                raise Fail("BadFieldValue", off, OTHER)
        elif check is not None:
            if check[0] == "dom":
                if chr(b[off]) not in check[1]:
                    raise Fail("BadFieldValue", off, check[2])
            elif check[0] == "px":
                if not _price_ok(int.from_bytes(b[off:off + size], "big")):
                    raise Fail("BadFieldValue", off, INVALID_PRICE)
            elif check[0] == "qty":
                if not 1 <= int.from_bytes(b[off:off + size], "big") <= 999_999:
                    raise Fail("BadFieldValue", off, INVALID_QUANTITY)
        off += size


def _check_tags(allowed: set, b: bytes, start: int) -> None:
    seen = set()
    for pos, tag, value in _elements(b, start):
        spec = TAGS.get(tag)
        if spec is None:
            raise Fail("UnknownTag", pos, OTHER, tag)
        if tag not in allowed:
            raise Fail("DisallowedTag", pos, OTHER, tag)
        if tag in seen:
            raise Fail("DuplicateTag", pos, OTHER, tag)
        seen.add(tag)
        size, kind, check = spec
        if len(value) != size:
            raise Fail("BadTagLength", pos, OTHER, tag)
        if check is None:
            continue
        if check[0] == "dom":
            ok, reject = chr(value[0]) in check[1], check[2]
        elif check[0] == "range":
            v = int.from_bytes(value, "big")
            ok, reject = check[1] <= v <= check[2], check[3]
        else:  # px0
            v = int.from_bytes(value, "big")
            ok, reject = v == 0 or 1 <= v <= MAX_LIMIT, check[1]
        if not ok:
            raise Fail("BadTagValue", pos, reject, tag)


def _render(entry, b: bytes, base: int, has_applen: bool) -> str:
    name, fields, rule, tags, spec_len = entry
    parts = ["K", chr(b[0]), str(int.from_bytes(b[base:base + 2], "big")) if has_applen else "-"]
    off = 1
    for fname, size, kind, check in fields:
        raw = b[off:off + size]
        parts.append(raw.hex() if kind in ("c", "a") else str(int.from_bytes(raw, "big")))
        off += size
    out_tags = []
    if has_applen:
        for pos, tag, value in _elements(b, base + 2):
            spec = TAGS.get(tag)
            if spec is None or spec[0] != len(value):
                out_tags.append(f"{tag}:x{value.hex()}")
            elif spec[1] == "u":
                out_tags.append(f"{tag}:{int.from_bytes(value, 'big')}")
            elif spec[1] == "s":
                out_tags.append(f"{tag}:{int.from_bytes(value, 'big', signed=True)}")
            else:
                out_tags.append(f"{tag}:{value.hex()}")
    return ",".join(parts) + "|" + ",".join(out_tags)


def _has_nonzero_user_ref_idx(b: bytes, start: int) -> bool:
    for pos, tag, value in _elements(b, start):
        if tag == 28:
            return len(value) == 1 and value[0] != 0
    return False


def inbound_strict(b: bytes) -> str:
    try:
        entry, base, has_applen = _frame(b, INBOUND, False)
        _check_fields(entry[1], b)
        if has_applen:
            _check_tags(entry[3], b, base + 2)
        return _render(entry, b, base, has_applen)
    except Fail as f:
        return f.text


def outbound_tolerant(b: bytes) -> str:
    try:
        entry, base, has_applen = _frame(b, OUTBOUND, True)
        return _render(entry, b, base, has_applen)
    except Fail as f:
        return f.text


def outbound_strict(b: bytes) -> str:
    try:
        entry, base, has_applen = _frame(b, OUTBOUND, False)
        _check_fields(entry[1], b)
        if has_applen:
            _check_tags(entry[3], b, base + 2)
            if entry[2] == "opt*" and not _has_nonzero_user_ref_idx(b, base + 2):
                raise Fail("AppendageRule", base)
        return _render(entry, b, base, has_applen)
    except Fail as f:
        return f.text


def verdict(direction: str, b: bytes) -> str:
    if direction == "I":
        return inbound_strict(b)
    return f"T={outbound_tolerant(b)};S={outbound_strict(b)}"


# ----------------------------------------------------------------------------- CLI


def check_stream(stream, max_report: int) -> tuple[int, int]:
    total = bad = 0
    for line in stream:
        line = line.rstrip("\n")
        if not line:
            continue
        direction, hx, expected = line.split("\t", 2)
        got = verdict(direction, bytes.fromhex(hx))
        total += 1
        if got != expected:
            bad += 1
            if bad <= max_report:
                print(f"DISAGREE {direction} {hx}\n  c++: {expected}\n  ref: {got}", file=sys.stderr)
    return total, bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decode")
    d.add_argument("direction", choices=["I", "O"])
    d.add_argument("hex")
    c = sub.add_parser("check")
    c.add_argument("--max-report", type=int, default=20)
    args = ap.parse_args()
    if args.cmd == "decode":
        print(verdict(args.direction, bytes.fromhex(args.hex)))
        return 0
    total, bad = check_stream(sys.stdin, args.max_report)
    print(f"checked={total} disagreements={bad}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
