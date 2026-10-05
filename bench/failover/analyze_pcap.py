#!/usr/bin/env python3
"""MoldUDP64 line analysis of a capture (plan 10 §7, T25 interface; R-10).

Reads a classic pcap (microsecond or nanosecond timestamps, either byte order;
Ethernet with optional 802.1Q tags, Linux cooked v1/v2, or raw IPv4), keeps the UDP
datagrams addressed to the line A / line B destinations, decodes their MoldUDP64
headers and reports, per line and per sender, packets, messages, sequence range and
sequence gaps. With --takeover it computes the takeover time of plan 10 §7:

    T_takeover = t_rx(first line-A packet sourced by the new primary)
               - t_rx(last line-A packet sourced by the old primary before the fault)

The new primary never sends on line A before it takes over, so its first line-A packet
is the end point. The start point:
  - with --fault-ns (a software capture on the clock that took the fault time: the
    localhost and VM trials): the old primary's last line-A packet at or before
    --fault-done-ns (the fault command had returned; default --fault-ns);
  - without (the lab's hardware capture: an unsynchronized PHC that no host clock can
    be compared with): the old primary's line-A packet that starts its longest silence
    before the end point (within --window-ms). A primary that emits a packet every
    20 us (METHODOLOGY §17) has no silence but the fault's; a stopped node's packets
    after SIGCONT (F2) or after its NICs return (F3) come after that silence.
Also:
  --new-epoch-seq S  T_new: the first line-A packet carrying output of the new epoch's
                     records (MoldUDP64 sequence >= S), from the same start point;
                     packets of the old primary after the takeover that carry such
                     output are counted (F2, F3: the deposed node sends none);
  --probe-price P    the release stall (F6, F7): the longest gap between the old
                     primary's line-A data packets while probe orders (ITCH Add Order
                     at price P, 4 decimals) were flowing.
Senders are IP:PORT, IP (any port: the lab's two hosts) or :PORT (one host).

Localhost trials (tests/integration/exchange/ha_trial.h) write kernel software receive
timestamps, so their T_takeover is indicative only. The lab capture on host C is a
hardware-timestamped pcap of the same form (tcpdump -j adapter_unsynced
--time-stamp-precision nano); pass its multicast groups as --line-a/--line-b, its drop
count as --capture-drops (a run is valid only with 0 drops) and --timestamps hardware.

Usage:
  analyze_pcap.py CAPTURE --line-a [IP:]PORT [--line-b [IP:]PORT] [--takeover]
                  [--fault-ns NS [--fault-done-ns NS]] [--window-ms MS]
                  [--old-sender S] [--new-sender S] [--new-epoch-seq S] [--probe-price P]
                  [--capture-drops N] [--timestamps software|hardware]
Prints a JSON report. Exit status: 0 ok, 1 no takeover found when one was asked for
(--takeover or --fault-ns), 2 usage or unreadable capture.
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


def sender_matches(spec, sender):
    """spec 'IP:PORT', 'IP' or ':PORT' against a packet's 'ip:port' sender."""
    if spec is None:
        return True
    ip, _, port = sender.rpartition(":")
    if spec.startswith(":"):
        return port == spec[1:]
    if ":" in spec:
        return spec == sender
    return ip == spec


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


def takeover(packets, fault_ns=None, old_sender=None, new_sender=None, fault_done_ns=None, window_ms=10_000,
             new_epoch_seq=None):
    """T_takeover per plan 10 §7 on line A, in ns, with the senders and the method it used
    (see the module comment); T_new with new_epoch_seq."""
    a = [p for p in packets if p["line"] == "A"]
    if old_sender is None:
        # The first line-A sender of the capture is the primary before the fault.
        if not a:
            return None
        old_sender = a[0]["sender"]
    old = [p for p in a if sender_matches(old_sender, p["sender"])]
    cand = [p for p in a if not sender_matches(old_sender, p["sender"])
            and (new_sender is None or sender_matches(new_sender, p["sender"]))
            and (fault_ns is None or p["ts_ns"] > fault_ns)]
    out = {"old_sender": old_sender, "new_sender": new_sender, "t_takeover_ns": None}
    if not cand or not old:
        return out
    first_new = min(cand, key=lambda p: p["ts_ns"])
    out["new_sender"] = first_new["sender"]
    out["first_new_ns"] = first_new["ts_ns"]
    end = first_new["ts_ns"]
    last_old = None
    if fault_ns is not None:
        bound = fault_done_ns if fault_done_ns is not None else fault_ns
        last_old = max((p["ts_ns"] for p in old if p["ts_ns"] <= bound), default=None)
        out["method"] = "fault-clock"
        out["fault_to_first_new_ns"] = end - fault_ns
    else:
        # The start of the old primary's longest silence before the end point.
        ts = sorted(p["ts_ns"] for p in old if end - window_ms * 1_000_000 <= p["ts_ns"] < end)
        best = None
        for i, t in enumerate(ts):
            nxt = ts[i + 1] if i + 1 < len(ts) else end
            if best is None or nxt - t > best[0]:
                best = (nxt - t, t)
        last_old = best[1] if best else None
        out["method"] = "longest-silence"
        if best:
            out["old_packets_in_window"] = len(ts)
            out["old_packets_after_silence"] = sum(1 for t in ts if t > best[1])
    if last_old is None:
        return out
    out["last_old_ns"] = last_old
    out["t_takeover_ns"] = end - last_old
    if new_epoch_seq is not None:
        first_out = None
        late = 0
        for p in a:
            n = len(p["msgs"])
            carries_new = n > 0 and p["seq"] + n - 1 >= new_epoch_seq
            if sender_matches(out["new_sender"], p["sender"]) and p["ts_ns"] >= end and carries_new:
                if first_out is None or p["ts_ns"] < first_out:
                    first_out = p["ts_ns"]
            if sender_matches(old_sender, p["sender"]) and p["ts_ns"] > end and carries_new:
                late += 1
        out["new_epoch_seq"] = new_epoch_seq
        out["t_new_ns"] = first_out - last_old if first_out is not None else None
        out["old_sender_new_epoch_packets"] = late
    return out


def release_stall(packets, sender, probe_price):
    """The longest gap between `sender`'s line-A data packets while probes (ITCH Add
    Order at probe_price) were flowing: (gap ns, gap start ns, probe packets)."""
    a = [p for p in packets if p["line"] == "A" and sender_matches(sender, p["sender"]) and p["msgs"]]
    probe_ts = []
    for p in a:
        for m in p["msgs"]:
            if len(m) >= 36 and m[0:1] == b"A" and struct.unpack(">I", m[32:36])[0] == probe_price:
                probe_ts.append(p["ts_ns"])
                break
    if len(probe_ts) < 2:
        return None
    lo, hi = probe_ts[0], probe_ts[-1]
    ts = [p["ts_ns"] for p in a if lo <= p["ts_ns"] <= hi]
    best = max(((ts[i + 1] - ts[i], ts[i]) for i in range(len(ts) - 1)), default=None)
    if best is None:
        return None
    return {"release_stall_ns": best[0], "stall_start_ns": best[1], "probe_packets": len(probe_ts),
            "data_packets_in_span": len(ts)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("capture")
    ap.add_argument("--line-a", required=True, help="line A destination [IP:]PORT")
    ap.add_argument("--line-b", help="line B destination [IP:]PORT")
    ap.add_argument("--takeover", action="store_true", help="compute T_takeover (also implied by --fault-ns)")
    ap.add_argument("--fault-ns", type=int, help="fault injection time (the capture's clock, ns: software captures)")
    ap.add_argument("--fault-done-ns", type=int, help="the fault command returned (same clock)")
    ap.add_argument("--window-ms", type=int, default=10_000, help="longest-silence search window before the end point")
    ap.add_argument("--old-sender", help="the old primary's line-A sender: IP:PORT, IP or :PORT")
    ap.add_argument("--new-sender", help="the new primary's line-A sender: IP:PORT, IP or :PORT")
    ap.add_argument("--new-epoch-seq", type=int, help="first MoldUDP64 sequence number of the new epoch's records")
    ap.add_argument("--probe-price", type=int, help="ITCH price of the probe orders (release stall)")
    ap.add_argument("--capture-drops", type=int, default=0, help="drops reported by the capture tool (-1: unknown)")
    ap.add_argument("--timestamps", default="software", choices=["software", "hardware"])
    args = ap.parse_args(argv)
    if args.timestamps == "hardware" and args.fault_ns is not None:
        print("analyze_pcap: --fault-ns is a host clock reading; a hardware capture's PHC is not comparable "
              "(omit it: the longest-silence start point)", file=sys.stderr)
        return 2
    try:
        pk = line_packets(args.capture, parse_endpoint(args.line_a),
                          parse_endpoint(args.line_b) if args.line_b else None)
    except (OSError, ValueError) as e:
        print(f"analyze_pcap: {e}", file=sys.stderr)
        return 2
    report = {"capture": args.capture, "timestamps": args.timestamps, "capture_drops": args.capture_drops,
              "valid": args.capture_drops == 0, "packets": len(pk), "senders": summarize(pk)}
    status = 0
    if args.takeover or args.fault_ns is not None:
        t = takeover(pk, args.fault_ns, args.old_sender, args.new_sender, args.fault_done_ns, args.window_ms,
                     args.new_epoch_seq)
        report["takeover"] = t
        if not t or t.get("t_takeover_ns") is None:
            status = 1
    if args.probe_price is not None:
        old = args.old_sender
        if old is None:
            a = [p for p in pk if p["line"] == "A"]
            old = a[0]["sender"] if a else None
        report["release"] = release_stall(pk, old, args.probe_price) if old else None
    print(json.dumps(report, indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
