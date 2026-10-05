#!/usr/bin/env python3
"""MoldUDP64 line analysis of a capture (plan 10 §7, T25 interface; R-10).

Reads a classic pcap (microsecond or nanosecond timestamps, either byte order;
Ethernet with optional 802.1Q tags, Linux cooked v1/v2, or raw IPv4), keeps the UDP
datagrams addressed to the line A / line B destinations, decodes their MoldUDP64
headers and reports, per line and per sender, packets, messages, sequence range and
sequence gaps. With --fault-ns it computes the takeover time of plan 10 §7:

    T_takeover = t_rx(first line-A packet sourced by the new primary)
               - t_rx(last line-A packet sourced by the old primary before the fault)

Localhost trials (tests/integration/exchange/ha_trial.h) write software receive
timestamps, so their T_takeover is indicative only. The lab capture on host C is a
hardware-timestamped pcap of the same form (tcpdump -j adapter_unsynced
--time-stamp-precision nano); pass its multicast groups as --line-a/--line-b and its
drop count as --capture-drops (a run is valid only with 0 drops).

Usage:
  analyze_pcap.py CAPTURE --line-a [IP:]PORT [--line-b [IP:]PORT] [--fault-ns NS]
                  [--old-sender IP:PORT] [--new-sender IP:PORT] [--capture-drops N]
Prints a JSON report. Exit status: 0 ok, 1 no takeover found when --fault-ns was
given, 2 usage or unreadable capture.
"""
import argparse
import json
import struct
import sys

MOLD_HEADER = 20
END_OF_SESSION = 0xFFFF


def read_pcap(path):
    """Yields (ts_ns, frame_bytes, linktype) for every record of a classic pcap."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        raise ValueError("not a pcap file (too short)")
    magic = data[:4]
    table = {
        b"\xd4\xc3\xb2\xa1": ("<", 1000),  # microseconds, little endian
        b"\xa1\xb2\xc3\xd4": (">", 1000),
        b"\x4d\x3c\xb2\xa1": ("<", 1),  # nanoseconds
        b"\xa1\xb2\x3c\x4d": (">", 1),
    }
    if magic not in table:
        raise ValueError("not a classic pcap file (pcapng is not supported: convert with editcap -F pcap)")
    endian, scale = table[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    at = 24
    while at + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", data[at:at + 16])
        at += 16
        frame = data[at:at + incl]
        at += incl
        yield sec * 1_000_000_000 + frac * scale, frame, linktype


def udp_of(frame, linktype):
    """(src_ip, src_port, dst_ip, dst_port, payload) of an IPv4/UDP frame, else None."""
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        ethertype = struct.unpack(">H", frame[12:14])[0]
        off = 14
        while ethertype in (0x8100, 0x88A8) and len(frame) >= off + 4:
            ethertype = struct.unpack(">H", frame[off + 2:off + 4])[0]
            off += 4
        if ethertype != 0x0800:
            return None
        ip = frame[off:]
    elif linktype == 113:  # Linux cooked v1
        if len(frame) < 16 or struct.unpack(">H", frame[14:16])[0] != 0x0800:
            return None
        ip = frame[16:]
    elif linktype == 276:  # Linux cooked v2
        if len(frame) < 20 or struct.unpack(">H", frame[0:2])[0] != 0x0800:
            return None
        ip = frame[20:]
    elif linktype in (101, 228):  # raw IPv4
        ip = frame
    else:
        return None
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 17:
        return None
    ihl = (ip[0] & 0x0F) * 4
    udp = ip[ihl:]
    if len(udp) < 8:
        return None
    sport, dport, ulen = struct.unpack(">HHH", udp[0:6])
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    return src, sport, dst, dport, udp[8:ulen] if ulen >= 8 else udp[8:]


def parse_mold(payload):
    """(session, seq, count, [messages]) of a MoldUDP64 packet, or None if malformed."""
    if len(payload) < MOLD_HEADER:
        return None
    session = payload[0:10]
    seq, count = struct.unpack(">QH", payload[10:20])
    msgs = []
    if count not in (0, END_OF_SESSION):
        at = MOLD_HEADER
        for _ in range(count):
            if at + 2 > len(payload):
                return None
            n = struct.unpack(">H", payload[at:at + 2])[0]
            at += 2
            if at + n > len(payload):
                return None
            msgs.append(payload[at:at + n])
            at += n
        if at != len(payload):
            return None
    return session, seq, count, msgs


def parse_endpoint(text):
    """'[IP:]PORT' -> (ip or None, port)."""
    if ":" in text:
        ip, port = text.rsplit(":", 1)
        return ip, int(port)
    return None, int(text)


def matches(ep, ip, port):
    return ep is not None and ep[1] == port and (ep[0] is None or ep[0] == ip)


def line_packets(capture, line_a, line_b=None):
    """Every MoldUDP64 packet of the two lines, in capture order:
    dicts {line, ts_ns, sender, session, seq, count, msgs} (sender = 'ip:port')."""
    out = []
    for ts, frame, lt in read_pcap(capture):
        u = udp_of(frame, lt)
        if u is None:
            continue
        src, sport, dst, dport, payload = u
        if matches(line_a, dst, dport):
            line = "A"
        elif matches(line_b, dst, dport):
            line = "B"
        else:
            continue
        m = parse_mold(payload)
        out.append({"line": line, "ts_ns": ts, "sender": f"{src}:{sport}", "malformed": m is None,
                    "session": m[0].decode("ascii", "replace") if m else "", "seq": m[1] if m else 0,
                    "count": m[2] if m else 0, "msgs": m[3] if m else []})
    return out


def summarize(packets):
    """Per line and sender: packets, messages, sequence range, forward jumps, back steps."""
    per = {}
    for p in packets:
        key = (p["line"], p["sender"])
        s = per.setdefault(key, {"line": p["line"], "sender": p["sender"], "packets": 0, "messages": 0,
                                 "heartbeats": 0, "end_of_session": 0, "first_seq": None, "next_seq": None,
                                 "forward_jumps": 0, "back_steps": 0, "malformed": 0,
                                 "first_ns": p["ts_ns"], "last_ns": p["ts_ns"]})
        s["packets"] += 1
        s["last_ns"] = p["ts_ns"]
        if p["malformed"]:
            s["malformed"] += 1
            continue
        n = len(p["msgs"])
        s["messages"] += n
        if p["count"] == 0:
            s["heartbeats"] += 1
        if p["count"] == END_OF_SESSION:
            s["end_of_session"] += 1
        if s["first_seq"] is None and n:
            s["first_seq"] = p["seq"]
        if s["next_seq"] is not None:
            if p["seq"] < s["next_seq"] and n:
                s["back_steps"] += 1
            elif p["seq"] > s["next_seq"]:
                s["forward_jumps"] += 1
        end = p["seq"] + n
        s["next_seq"] = end if s["next_seq"] is None else max(s["next_seq"], end)
    return sorted(per.values(), key=lambda s: (s["line"], s["first_ns"]))


def takeover(packets, fault_ns, old_sender=None, new_sender=None):
    """T_takeover per plan 10 §7 on line A, in ns, with the senders it used."""
    a = [p for p in packets if p["line"] == "A"]
    before = [p for p in a if p["ts_ns"] <= fault_ns]
    if old_sender is None:
        if not before:
            return None
        counts = {}
        for p in before:
            counts[p["sender"]] = counts.get(p["sender"], 0) + 1
        old_sender = max(counts, key=counts.get)
    last_old = max((p["ts_ns"] for p in before if p["sender"] == old_sender), default=None)
    after = [p for p in a if p["ts_ns"] > fault_ns and p["sender"] != old_sender
             and (new_sender is None or p["sender"] == new_sender)]
    if not after or last_old is None:
        return {"old_sender": old_sender, "new_sender": new_sender, "t_takeover_ns": None}
    first_new = min(after, key=lambda p: p["ts_ns"])
    return {"old_sender": old_sender, "new_sender": first_new["sender"],
            "last_old_ns": last_old, "first_new_ns": first_new["ts_ns"],
            "t_takeover_ns": first_new["ts_ns"] - last_old,
            "fault_to_first_new_ns": first_new["ts_ns"] - fault_ns}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("capture")
    ap.add_argument("--line-a", required=True, help="line A destination [IP:]PORT")
    ap.add_argument("--line-b", help="line B destination [IP:]PORT")
    ap.add_argument("--fault-ns", type=int, help="fault injection time (capture clock, ns)")
    ap.add_argument("--old-sender", help="IP:PORT of the old primary's line-A sender")
    ap.add_argument("--new-sender", help="IP:PORT of the new primary's line-A sender")
    ap.add_argument("--capture-drops", type=int, default=0, help="drops reported by the capture tool")
    ap.add_argument("--timestamps", default="software", choices=["software", "hardware"])
    args = ap.parse_args(argv)
    try:
        pk = line_packets(args.capture, parse_endpoint(args.line_a),
                          parse_endpoint(args.line_b) if args.line_b else None)
    except (OSError, ValueError) as e:
        print(f"analyze_pcap: {e}", file=sys.stderr)
        return 2
    report = {"capture": args.capture, "timestamps": args.timestamps, "capture_drops": args.capture_drops,
              "valid": args.capture_drops == 0, "packets": len(pk), "senders": summarize(pk)}
    status = 0
    if args.fault_ns is not None:
        t = takeover(pk, args.fault_ns, args.old_sender, args.new_sender)
        report["takeover"] = t
        if not t or t.get("t_takeover_ns") is None:
            status = 1
    print(json.dumps(report, indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
