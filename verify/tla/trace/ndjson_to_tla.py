#!/usr/bin/env python3
"""Converts an exsim_ha protocol trace (NDJSON) into a TLC trace-validation run of
verify/tla/HotStandbyTrace.tla (docs/plan/10 §6, R-08).

usage: ndjson_to_tla.py TRACE.ndjson OUTDIR

Writes OUTDIR/HotStandbyTraceRun.tla (TraceLog as a TLA+ sequence of records, plus the
constants) and OUTDIR/HotStandbyTraceRun.cfg. The mapping from implementation events to
specification steps is in HotStandbyTrace.tla; this script only

  * names each journal record by its HotStandby entry: EpochStart -> [e, "ES"]; an order
    the engine executes -> [e, "a<account>u<UserRefNum>"]; any other record -> a no-op
    [e, "r<content crc>"] (the entry is fixed when the record is created and looked up
    by content crc wherever the record travels);
  * expands a release watermark into one event per index;
  * makes durability explicit where the trace implies it: before a host crash the
    node's L3 holds exactly what its next recovery finds, and after a restart what its
    journal writer reports as durable;
  * takes the joiner's incarnation of a JOIN grant from the JOIN its primary relayed, and
    orders the grant right after that relay: from the JOIN on, the primary neither
    sequences nor releases and the witness grants nothing else in that epoch, so the
    witness's decision commutes with everything in between (a crash of either node
    included). HotStandby's Rejoin is atomic, with the primary paused. The grant also
    records whether the joiner's process ever acts on it (`heard`, by looking ahead to
    its `rejoined`): a joiner that never learns of its admission before the primary goes
    solo stays recovering (RejoinStale);
  * places a JOIN grant that arrives after its primary gave the JOIN up (`join_abandoned`:
    a REJECT answered it, and the primary resumed solo service) where the primary applies
    it, or right before the primary's next crash, as RejoinStale. Until then the grant
    is invisible: the joiner incarnation it names is dead (the primary gives a JOIN up on
    a REJECT only when it is the epoch's only JOIN, which W answers once, or when a newer
    incarnation of the joiner has been seen), and W grants nothing else in that epoch.
    Known imprecision: the trace does not say which JOIN of the epoch W granted, so
    `jinc` is the joiner incarnation of the primary's last JOIN; only a witness restart
    between two JOINs of one epoch can make W record an earlier one.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def tla(v) -> str:
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return '"' + v + '"'
    if isinstance(v, dict):
        return "[" + ", ".join(f"{k} |-> {tla(x)}" for k, x in v.items()) + "]"
    raise TypeError(v)


class Converter:
    def __init__(self, events: list[dict]):
        self.ev = events
        self.out: list[dict] = []
        self.entries: dict[int, dict] = {}       # content crc -> entry
        self.release_w = {0: 0, 1: 0}            # per node, per process: release watermark
        self.durable = {0: 0, 1: 0}              # last durable index reported per node
        self.last_join_inc = {0: 0, 1: 0}        # joiner incarnation named by a node's last JOIN
        self.last_join_pos = {0: None, 1: None}  # where that JOIN was relayed in the output
        self.abandoned = {0: False, 1: False}    # the primary gave that JOIN up (join_abandoned)
        self.late: dict[int, dict | None] = {0: None, 1: None}  # a grant of a given-up JOIN, not yet applied
        self.orders: set[str] = set()
        self.max_epoch = 1
        self.max_index = 1
        self.host_crashes = 0
        self.proc_crashes = 0
        self.late_grants = 0

    def value(self, v: str, crc: int) -> str:
        if v == "es":
            return "ES"
        if v.startswith("a"):
            self.orders.add(v)
            return v
        return f"r{crc}"

    def entry_of(self, crc: int, n: int, i: int) -> dict:
        if crc not in self.entries:
            raise SystemExit(f"record crc {crc} at n{n} index {i} was never created in the trace")
        return self.entries[crc]

    def emit(self, **kw):
        if "i" in kw:
            self.max_index = max(self.max_index, kw["i"])
        if "epoch" in kw:
            self.max_epoch = max(self.max_epoch, kw["epoch"])
        self.out.append(kw)

    def next_restart(self, pos: int, n: int):
        for e in self.ev[pos + 1:]:
            if e.get("n") == n and e["ev"] == "restart":
                return e
        return None

    def run(self):
        for pos, e in enumerate(self.ev):
            k = e["ev"]
            n = e.get("n")
            if k == "init":
                self.entries[e["crc1"]] = {"e": 1, "v": "ES"}
                self.emit(ev="init", primary=e["primary"])
            elif k == "seq":
                v = self.value(e["v"], e["crc"])
                self.entries[e["crc"]] = {"e": e["ep"], "v": v}
                self.max_epoch = max(self.max_epoch, e["ep"])
                self.emit(ev="seq", n=n, i=e["idx"], ep=e["ep"], v=v)
            elif k == "send_append":
                self.emit(ev="send", n=n, i=e["idx"], ep=e["ep"])
            elif k == "recv_append":
                ent = self.entry_of(e["crc"], n, e["idx"])
                mine = self.value(e["v"], e["crc"])
                if mine != ent["v"]:
                    raise SystemExit(f"n{n} classifies record {e['idx']} as {mine}, its creator as {ent['v']}")
                self.emit(ev="recv", n=n, i=e["idx"], ent=ent)
            elif k == "catchup_append":
                self.emit(ev="catchup", n=n, i=e["idx"], ent=self.entry_of(e["crc"], n, e["idx"]))
            elif k == "recv_ack":
                self.emit(ev="ack", n=n, k=e["len"])
            elif k == "durable":
                self.durable[n] = e["len"]
                self.emit(ev="durable", n=n, k=e["len"])
            elif k == "release":
                for i in range(self.release_w[n] + 1, e["w"] + 1):
                    self.emit(ev="release", n=n, i=i)
                self.release_w[n] = max(self.release_w[n], e["w"])
            elif k == "freeze":
                self.emit(ev="freeze", n=n, k=e["last"])
            elif k == "req_promote":
                self.emit(ev="promote", n=n, fe=e["fe"])
            elif k == "req_solo":
                self.emit(ev="solo", n=n, fe=e["fe"])
            elif k == "req_resume":
                self.emit(ev="resume", n=n)
            elif k == "req_join":
                self.last_join_inc[n] = e["jinc"]
                self.abandoned[n] = False
                self.emit(ev="joinreq", n=n, k=e["last"])
                self.last_join_pos[n] = len(self.out)
            elif k == "w_grant":
                to = e["to"]
                rec = dict(ev="grant", type=e["type"], to=to, inc=e["inc"], epoch=e["epoch"])
                self.max_epoch = max(self.max_epoch, e["epoch"])
                if e["type"] == "JOIN":
                    rec["jinc"] = self.last_join_inc[to]
                    rec["heard"] = self.join_heard(pos, 1 - to, e["epoch"])
                if e["type"] == "JOIN" and self.abandoned[to]:
                    if rec["heard"]:
                        raise SystemExit(f"n{1 - to} acts on the grant of a JOIN its primary gave up (epoch {e['epoch']})")
                    self.late[to] = rec
                    self.abandoned[to] = False
                    self.last_join_pos[to] = None
                elif e["type"] == "JOIN" and self.last_join_pos[to] is not None:
                    self.out.insert(self.last_join_pos[to], rec)
                    self.last_join_pos[to] = None
                else:
                    self.emit(**rec)
            elif k == "join_abandoned":
                if self.last_join_pos[n] is not None:
                    self.abandoned[n] = True
            elif k == "grant_applied":
                if e["type"] == "JOIN" and self.late[n] is not None and self.late[n]["epoch"] == e["epoch"]:
                    self.emit_late(n)
                self.entries[e["es_crc"]] = {"e": e["epoch"], "v": "ES"}
                self.emit(ev="applied", n=n, type=e["type"], epoch=e["epoch"], i=e["es_idx"])
            elif k == "rejoined":
                self.emit(ev="rejoined", n=n, epoch=e["epoch"])
            elif k == "truncate":
                self.durable[n] = min(self.durable[n], e["to"])
                self.emit(ev="truncate", n=n, t=e["to"])
            elif k == "rejoin_es":
                ent = {"e": e["epoch"], "v": "ES"}
                self.entries[e["crc"]] = ent
                self.emit(ev="rejoin_es", n=n, i=e["idx"], ent=ent)
            elif k == "adopt_epoch":
                self.emit(ev="adopt", n=n, epoch=e["epoch"])
            elif k == "crash":
                if self.late[n] is not None:
                    self.emit_late(n)
                host = e["kind"] == "host"
                if host:
                    self.host_crashes += 1
                    r = self.next_restart(pos, n)
                    if r is not None and r["len"] > self.durable[n]:
                        # The power loss kept exactly what the next recovery finds.
                        self.emit(ev="durable", n=n, k=r["len"])
                        self.durable[n] = r["len"]
                else:
                    self.proc_crashes += 1
                self.emit(ev="crash", n=n, kind="host" if host else "proc")
            elif k == "restart":
                self.release_w[n] = 0
                self.emit(ev="restart", n=n, k=e["len"], inc=e["inc"])
                self.durable[n] = e["durable"]
                self.emit(ev="durable", n=n, k=e["durable"])
            elif k == "ee_answer":
                self.emit(ev="ee_answer", n=n, jinc=e["jinc"])
            elif k == "catchup_send":
                self.emit(ev="catchup_send", n=n, i=e["idx"])
            elif k == "solo_cancelled":
                pass
            else:
                raise SystemExit(f"unknown event {k}")
        for n in (0, 1):
            if self.late[n] is not None:
                self.emit_late(n)

    def emit_late(self, n: int):
        rec, self.late[n] = self.late[n], None
        self.late_grants += 1
        self.emit(**rec)

    def join_heard(self, pos: int, n: int, epoch: int) -> bool:
        """Whether the joiner's current process ever acts on this JOIN grant (it becomes
        the backup of that epoch before it crashes or joins another epoch)."""
        for e in self.ev[pos + 1:]:
            if e.get("n") != n:
                continue
            if e["ev"] == "rejoined":
                return e["epoch"] == epoch
            if e["ev"] in ("crash", "restart"):
                return False
        return False

    def module(self) -> str:
        lines = ["---- MODULE HotStandbyTraceRun ----", "EXTENDS HotStandbyTrace", "TTrace == <<"]
        lines.append(",\n".join("  " + tla(r) for r in self.out))
        lines.append(">>")
        lines.append("TOrders == {" + ", ".join(tla(o) for o in sorted(self.orders)) + "}")
        lines.append("====")
        return "\n".join(lines) + "\n"

    def cfg(self) -> str:
        mut = ["MutNoOutputRule", "MutNoMemberCheck", "MutNoIncarnation", "MutNoTruncate", "MutNoDedupe",
               "MutAckBeforeAppend", "MutAckWhileCandidate", "MutSoloReleaseFromL2"]
        c = ["INIT TraceInit", "NEXT TraceNext", "CONSTANTS",
             "  Nodes <- TNodes", "  Orders <- TOrders", "  Nops <- NoNops", "  TraceLog <- TTrace",
             f"  MaxEpoch = {self.max_epoch + 1}", f"  MaxLog = {self.max_index + 2}",
             f"  MaxHostCrashes = {self.host_crashes}", f"  MaxProcCrashes = {self.proc_crashes}"]
        c += [f"  {m} = FALSE" for m in mut]
        c += ["INVARIANTS", "  TypeOK", "  TSafety", "  NotDone"]  # TSafety: Safety, computed faster
        return "\n".join(c) + "\n"


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 64
    events = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()]
    c = Converter(events)
    c.run()
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    (out / "HotStandbyTraceRun.tla").write_text(c.module())
    (out / "HotStandbyTraceRun.cfg").write_text(c.cfg())
    print(f"events={len(events)} steps={len(c.out)} records={c.max_index} epochs={c.max_epoch} "
          f"orders={len(c.orders)} host_crashes={c.host_crashes} proc_crashes={c.proc_crashes} "
          f"late_join_grants={c.late_grants}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
