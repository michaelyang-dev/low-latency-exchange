-------------------------- MODULE HotStandbyTrace --------------------------
(***************************************************************************)
(* Trace validation of the implementation (src/repl, run in the sim/ha     *)
(* world) against HotStandby (docs/plan/10 §6, R-08), after Cirstea, Kuppe, *)
(* Merz et al. (2024).                                                     *)
(*                                                                         *)
(* The simulator exports every protocol action as an NDJSON event; the     *)
(* converter verify/tla/trace/ndjson_to_tla.py turns one run into TraceLog, *)
(* a sequence of records, and TraceNext replays it: each event must be     *)
(* matched by one step of the specification, with the event's parameters   *)
(* (indices, entries, epochs, incarnations, lengths) checked against the   *)
(* specification's state. TLC explores only the states consistent with the *)
(* trace and checks HotStandby's Safety invariants in every one of them.   *)
(* The invariant NotDone is violated exactly when the whole trace has been *)
(* matched (success); a deadlock before that is a mismatch at event l.     *)
(*                                                                         *)
(* The implementation refines HotStandby with a few finer-grained steps    *)
(* that the protocol model coarsens. Each is a generalization (a superset  *)
(* of a HotStandby behavior), defined below and justified in its comment;  *)
(* TSpec, HotStandby plus these generalizations, is model-checked against  *)
(* the same invariants with HotStandbyTraceCheck.cfg, so trace validation  *)
(* is against a specification that is itself verified safe.               *)
(*                                                                         *)
(* Refinement mapping (implementation -> HotStandby variables):            *)
(*   role       Replica::role(): P, SP, SC, B, C, R; a dead process: Down   *)
(*   epoch      the epoch of the node's last grant / rejoin. HotStandby    *)
(*              keeps epoch[n] across restarts; a restarted process knows  *)
(*              only its last durable EpochStart, and a solo primary of    *)
(*              record adopts W's epoch from a stale-epoch REJECT of its   *)
(*              RESUME: a stutter when it had received that grant (the     *)
(*              mapped epoch already equals W's), AdoptEpoch when the      *)
(*              GRANT itself was lost                                      *)
(*   log        the node's journal (L2 + L3); one entry per record:        *)
(*              EpochStart -> [e, "ES"]; an order the engine executes      *)
(*              -> [e, "a<account>u<UserRefNum>"]; any other record (a     *)
(*              session event, a duplicate the UserRefNum filter drops)    *)
(*              -> [e, "r<content crc>"], a no-op output                   *)
(*   durLen     JournalWriter::durable_index() (L3)                        *)
(*   ackLen     the primary's backup ACK                                   *)
(*   inc        the process incarnation                                    *)
(*   frozenLast Replica::frozen_last()                                     *)
(*   released   every index a primary's release watermark has covered      *)
(*   w*         the witness core's durable state                           *)
(*   net        the APPEND/ACK/request/GRANT messages, by their content    *)
(***************************************************************************)
EXTENDS HotStandby, TLC

CONSTANTS
    TraceLog,   \* the implementation trace (a sequence of event records)
    Nops        \* model checking only: values for no-op records

VARIABLE l      \* the next trace event to match

tvars == <<vars, l>>

EmptyTrace == << >>
NoNops == {}

NOP(v) == v \notin Orders /\ v # ES
LastIsUndurableES(n) ==
    /\ Len(log[n]) > durLen[n]
    /\ log[n][Len(log[n])].v = ES

---------------------------------------------------------------------------
(* Generalizations. *)

\* L3 durability advances to any point of the log. HotStandby's Flush makes the whole
\* log durable at once; the journal writer group-commits batch by batch.
FlushTo(n, k) ==
    /\ role[n] # "Down"
    /\ durLen[n] < k /\ k <= Len(log[n])
    /\ durLen' = [durLen EXCEPT ![n] = k]
    /\ UNCHANGED <<witnessVars, role, epoch, log, ackLen, inc, frozenLast, net, released,
                   hostCrashes, procCrashes>>

\* A primary takes any length up to that of a cumulative ACK in flight from its backup.
\* HotStandby keeps only the newest ACK per sender and epoch (SupersedeAck); the
\* implementation can receive an older one first. The backup held at least that
\* length when it sent it.
RecvAckUpTo(n, k) ==
    /\ role[n] = "P"
    /\ k > ackLen[n]
    /\ \E msg \in net : msg.type = "ACK" /\ msg.from # n /\ msg.ep = epoch[n] /\ msg.len >= k
    /\ ackLen' = [ackLen EXCEPT ![n] = k]
    /\ UNCHANGED <<witnessVars, role, epoch, log, durLen, inc, frozenLast, net, released,
                   hostCrashes, procCrashes>>

\* The sequencer journals records that are not executed client orders (session events,
\* instance-down, an order the UserRefNum filter drops): outputs no client acts on.
SequenceNoop(n, v) ==
    /\ IsPrimary(n)
    /\ Len(log[n]) < MaxLog
    /\ NOP(v)
    /\ log' = [log EXCEPT ![n] = Append(@, [e |-> epoch[n], v |-> v])]
    /\ UNCHANGED <<witnessVars, role, epoch, durLen, ackLen, inc, frozenLast, net, released,
                   hostCrashes, procCrashes>>

\* Rejoin, unrolled. HotStandby's Rejoin truncates the joiner's divergent tail and copies
\* the primary's log in its single step; the implementation truncates (by epoch, 10 §5)
\* and copies record by record while recovering, and the atomic Rejoin step then finds
\* nothing left to truncate or copy. Both are driven by messages from a node that was a
\* primary when it sent them (the implementation refuses EPOCH_END_QUERY and catch-up
\* in any other role):
\*   EPOCH_END   carries the primary's log; the joiner truncates to a point at or
\*               above the prefix the two logs share (the epoch-based handshake stops
\*               there). Truncating below it would be unsafe: a PROMOTE from the
\*               joiner's previous incarnation can still be granted later, and the node
\*               could then RESUME as the solo primary of record with this log
\*               (HotStandbyTraceCheck finds the loss of a released output).
\*   catch-up    carries a prefix of the primary's log; the joiner appends its next
\*               entry when its own log is the rest of that prefix (the CRC chain).
\* An EPOCH_END answer is addressed to the querying incarnation, which truncates only
\* by an answer to its own query. The recovering node asks the node the witness names as
\* primary (it learned it from a REJECT), and that node answers only in a primary role.
AnswerEpochEnd(p, r) ==
    /\ IsPrimary(p) /\ p = wPrimary /\ r # p /\ role[r] = "R"
    /\ net' = net \cup {[type |-> "EPOCH_END", from |-> p, to |-> r, inc |-> inc[r], log |-> log[p]]}
    /\ UNCHANGED <<witnessVars, nodeVars, released, hostCrashes, procCrashes>>

TruncateR(r, t) ==
    /\ role[r] = "R"
    /\ t < Len(log[r])
    /\ \E msg \in net : msg.type = "EPOCH_END" /\ msg.to = r /\ msg.inc = inc[r] /\ t >= LCP(log[r], msg.log)
    /\ log' = [log EXCEPT ![r] = Prefix(@, t)]
    /\ durLen' = [durLen EXCEPT ![r] = Min(@, t)]
    /\ UNCHANGED <<witnessVars, role, epoch, ackLen, inc, frozenLast, net, released,
                   hostCrashes, procCrashes>>

SendCatchup(p, i) ==
    /\ IsPrimary(p)
    /\ i \in 1..Len(log[p])
    /\ net' = net \cup {[type |-> "CATCHUP", from |-> p, log |-> Prefix(log[p], i)]}
    /\ UNCHANGED <<witnessVars, nodeVars, released, hostCrashes, procCrashes>>

CatchupR(r) ==
    /\ role[r] = "R"
    /\ \E msg \in net :
          /\ msg.type = "CATCHUP" /\ msg.from # r
          /\ Len(msg.log) = Len(log[r]) + 1
          /\ Prefix(msg.log, Len(log[r])) = log[r]
          /\ log' = [log EXCEPT ![r] = msg.log]
    /\ UNCHANGED <<witnessVars, role, epoch, durLen, ackLen, inc, frozenLast, net, released,
                   hostCrashes, procCrashes>>

\* HotStandby's Rejoin appends the new epoch's EpochStart to both logs together with the
\* witness's grant; in the implementation each node appends it when the grant reaches it
\* (the primary by its GRANT, the joiner by W's copy, the primary's relay or a REJECT
\* naming the new configuration; the record is deterministic, so both are identical).
\* A node that dies in between never had it: the record is lost with the process (it
\* was never durable).
LoseES(n) ==
    /\ role[n] = "Down"
    /\ LastIsUndurableES(n)
    /\ log' = [log EXCEPT ![n] = Prefix(@, Len(@) - 1)]
    /\ UNCHANGED <<witnessVars, role, epoch, durLen, ackLen, inc, frozenLast, net, released,
                   hostCrashes, procCrashes>>

\* A restarted solo primary of record adopts the witness's epoch (from a REJECT of its
\* RESUME, 10 §4). HotStandby's node keeps the epoch of its last received grant, which
\* can be older when that grant was lost: the RESUME would then never be granted and no
\* node could lead again. Only the witness's solo primary of record can adopt.
AdoptEpoch(n) ==
    /\ role[n] = "R" /\ n = wPrimary /\ wMembers = {n}
    /\ epoch' = [epoch EXCEPT ![n] = wEpoch]
    /\ UNCHANGED <<witnessVars, role, log, durLen, ackLen, inc, frozenLast, net, released,
                   hostCrashes, procCrashes>>

\* The witness grants a JOIN that the joiner's process never acts on. HotStandby's Rejoin
\* is atomic: the joiner becomes the backup with the grant. Here the named incarnation
\* has crashed since it reached zero lag (it is down, or already restarted as a newer
\* incarnation), or it is alive but learns of its admission from none of W's copy, the
\* primary's relay or a REJECT before the primary gives up on it (it goes solo, and the
\* joiner then re-handshakes with the new epoch). W records the incarnation; the primary
\* becomes paired, appends the new EpochStart and holds only the JOIN's last index as
\* acknowledged (it never receives an ACK in the new epoch, and goes solo). The joiner's
\* state is untouched: a recovering node can neither ACK nor PROMOTE.
RejoinStale(r, k) ==
    /\ (role[r] \in {"Down", "R"} /\ k = inc[r]) \/ k < inc[r]
    /\ r \notin wMembers
    /\ LET p == wPrimary IN
       /\ p # r
       /\ role[p] = "SP" /\ epoch[p] = wEpoch
       /\ wEpoch < MaxEpoch
       /\ Len(log[p]) < MaxLog
       /\ log' = [log EXCEPT ![p] = Append(@, [e |-> wEpoch + 1, v |-> ES])]
       /\ ackLen' = [ackLen EXCEPT ![p] = Len(log[p])]
       /\ epoch' = [epoch EXCEPT ![p] = wEpoch + 1]
       /\ role' = [role EXCEPT ![p] = "P"]
    /\ wEpoch' = wEpoch + 1 /\ wMembers' = Nodes
    /\ wInc' = [wInc EXCEPT ![r] = k]
    /\ UNCHANGED <<wPrimary, durLen, inc, frozenLast, net, released, hostCrashes, procCrashes>>

\* LoseES followed by Restart, as one step of the trace.
RestartLosingES(n) ==
    /\ role[n] = "Down"
    /\ LastIsUndurableES(n)
    /\ log' = [log EXCEPT ![n] = Prefix(@, Len(@) - 1)]
    /\ role' = [role EXCEPT ![n] = "R"]
    /\ inc' = [inc EXCEPT ![n] = @ + 1]
    /\ ackLen' = [ackLen EXCEPT ![n] = 0]
    /\ UNCHANGED <<witnessVars, epoch, durLen, frozenLast, net, released, hostCrashes, procCrashes>>

---------------------------------------------------------------------------
(* The generalized specification, model-checked by HotStandbyTraceCheck.cfg. *)

\* A fresh no-op value: unique among all logs, so that no-op records stay distinct.
FreshNop(v) == \A m \in Nodes : \A i \in 1..Len(log[m]) : log[m][i].v # v

TNext ==
    \/ Next
    \/ \E n \in Nodes :
          \/ \E k \in 1..MaxLog : FlushTo(n, k) \/ RecvAckUpTo(n, k)
          \/ \E v \in Nops : FreshNop(v) /\ SequenceNoop(n, v)
          \/ AnswerEpochEnd(n, Other(n))
          \/ \E t \in 0..MaxLog : TruncateR(n, t)
          \/ \E i \in 1..MaxLog : SendCatchup(n, i)
          \/ CatchupR(n)
          \/ LoseES(n)
          \/ AdoptEpoch(n)
          \/ \E k \in 0..inc[n] : RejoinStale(n, k)

TSpec == Init /\ l = 0 /\ [][TNext /\ UNCHANGED l]_tvars

---------------------------------------------------------------------------
(* Trace matching. *)

TNodes == {0, 1}

Stutter == UNCHANGED vars

Ent(x) == [e |-> x.ent.e, v |-> x.ent.v]

MatchSeq(x) ==
    /\ IF x.v \in Orders THEN SequenceOrder(x.n, x.v) ELSE SequenceNoop(x.n, x.v)
    /\ Len(log'[x.n]) = x.i
    /\ log'[x.n][x.i] = [e |-> x.ep, v |-> x.v]

MatchSend(x) ==
    /\ x.ep = epoch[x.n]
    /\ IF x.i <= ackLen[x.n]
       THEN Stutter  \* an entry the backup already holds (the EpochStart of a Rejoin)
       ELSE /\ x.i <= Len(log[x.n])
            /\ SendAppend(x.n)
            /\ net' = net \cup {[type |-> "APPEND", from |-> x.n, ep |-> epoch[x.n], idx |-> x.i,
                                 ent |-> log[x.n][x.i]]}

MatchRecv(x) ==
    IF x.i <= Len(log[x.n])
    THEN Stutter /\ log[x.n][x.i] = Ent(x)  \* already given by Rejoin
    ELSE RecvAppend(x.n) /\ Len(log'[x.n]) = x.i /\ log'[x.n][x.i] = Ent(x)

MatchAck(x) == IF x.k <= ackLen[x.n] THEN Stutter ELSE RecvAckUpTo(x.n, x.k)

MatchDurable(x) == IF x.k <= durLen[x.n] THEN Stutter ELSE FlushTo(x.n, x.k)

MatchRelease(x) ==
    /\ x.i <= Len(log[x.n])
    /\ IF [idx |-> x.i, ent |-> log[x.n][x.i]] \in {[idx |-> r.idx, ent |-> r.ent] : r \in released}
       THEN Stutter
       ELSE Release(x.n) /\ \E r \in released' \ released : r.idx = x.i

MatchFreeze(x) == Freeze(x.n) /\ frozenLast'[x.n] = x.k

MatchPromote(x) == RequestPromote(x.n) /\ (role[x.n] = "C" => x.fe = epoch[x.n])

MatchSolo(x) == RequestSolo(x.n) /\ x.fe = epoch[x.n]

MatchGrant(x) ==
    CASE x.type = "PROMOTE" ->
            /\ WitnessGrantPromote
            /\ wPrimary' = x.to /\ wEpoch' = x.epoch
            /\ [type |-> "GRANT", to |-> x.to, inc |-> x.inc, ep |-> x.epoch] \in net'
      [] x.type = "SOLO" ->
            /\ WitnessGrantSolo
            /\ wPrimary = x.to /\ wEpoch' = x.epoch
            /\ [type |-> "GRANT", to |-> x.to, inc |-> x.inc, ep |-> x.epoch] \in net'
      [] x.type = "RESUME" ->
            /\ WitnessGrantResume
            /\ wPrimary = x.to /\ wEpoch' = x.epoch /\ wInc'[x.to] = x.inc
            /\ [type |-> "GRANT", to |-> x.to, inc |-> x.inc, ep |-> x.epoch] \in net'
      [] x.type = "JOIN" ->
            /\ IF x.heard /\ role[Other(x.to)] \in {"R", "B", "C", "SC"} /\ inc[Other(x.to)] = x.jinc
               THEN Rejoin(Other(x.to))
               ELSE RejoinStale(Other(x.to), x.jinc)
            /\ wPrimary = x.to /\ wEpoch' = x.epoch /\ wInc'[Other(x.to)] = x.jinc

MatchApplied(x) ==
    IF x.type = "JOIN"
    THEN /\ Stutter  \* Rejoin already appended it, atomically with the grant
         /\ role[x.n] = "P" /\ epoch[x.n] = x.epoch
         /\ log[x.n][x.i] = [e |-> x.epoch, v |-> ES]
    ELSE /\ RecvGrant(x.n)
         /\ epoch'[x.n] = x.epoch
         /\ Len(log'[x.n]) = x.i
         /\ log'[x.n][x.i] = [e |-> x.epoch, v |-> ES]

MatchRejoined(x) == Stutter /\ role[x.n] = "B" /\ epoch[x.n] = x.epoch

MatchTruncate(x) == IF x.t < Len(log[x.n]) THEN TruncateR(x.n, x.t) ELSE Stutter

MatchCatchup(x) ==
    IF x.i <= Len(log[x.n])
    THEN Stutter /\ log[x.n][x.i] = Ent(x)
    ELSE CatchupR(x.n) /\ log'[x.n][x.i] = Ent(x)

MatchCatchupSend(x) == x.i <= Len(log[x.n]) /\ SendCatchup(x.n, x.i)

\* The joiner's own copy of the JOIN epoch's EpochStart: Rejoin already put it there.
MatchRejoinES(x) == Stutter /\ x.i <= Len(log[x.n]) /\ log[x.n][x.i] = Ent(x)

MatchCrash(x) == IF x.kind = "host" THEN HostCrash(x.n) ELSE ProcCrash(x.n)

MatchRestart(x) ==
    /\ IF Len(log[x.n]) = x.k + 1 /\ role[x.n] = "Down" /\ LastIsUndurableES(x.n)
       THEN RestartLosingES(x.n)
       ELSE Restart(x.n)
    /\ inc'[x.n] = x.inc
    /\ Len(log'[x.n]) = x.k

\* An answer to a query the joiner's incarnation is no longer waiting for (it was
\* admitted, or it restarted) is never used: answers are matched to the query id, which
\* carries the incarnation.
MatchEpochEndAnswer(x) ==
    IF role[Other(x.n)] = "R" /\ inc[Other(x.n)] = x.jinc
    THEN AnswerEpochEnd(x.n, Other(x.n))
    ELSE Stutter

\* A joiner probes W with RESUME when its primary falls silent; a probe that the trace's
\* (atomic) Rejoin has overtaken comes from a backup and can never be granted.
MatchResume(x) == IF role[x.n] = "R" THEN RequestResume(x.n) ELSE Stutter

MatchJoinRequest(x) == Stutter /\ role[x.n] = "SP" /\ Len(log[x.n]) = x.k

TraceInit ==
    /\ l = 1
    /\ Init
    /\ wPrimary = TraceLog[1].primary

TraceNext ==
    /\ l <= Len(TraceLog)
    /\ LET x == TraceLog[l] IN
         CASE x.ev = "init" -> Stutter
           [] x.ev = "seq" -> MatchSeq(x)
           [] x.ev = "send" -> MatchSend(x)
           [] x.ev = "recv" -> MatchRecv(x)
           [] x.ev = "ack" -> MatchAck(x)
           [] x.ev = "durable" -> MatchDurable(x)
           [] x.ev = "release" -> MatchRelease(x)
           [] x.ev = "freeze" -> MatchFreeze(x)
           [] x.ev = "promote" -> MatchPromote(x)
           [] x.ev = "solo" -> MatchSolo(x)
           [] x.ev = "resume" -> MatchResume(x)
           [] x.ev = "grant" -> MatchGrant(x)
           [] x.ev = "applied" -> MatchApplied(x)
           [] x.ev = "rejoined" -> MatchRejoined(x)
           [] x.ev = "truncate" -> MatchTruncate(x)
           [] x.ev = "catchup" -> MatchCatchup(x)
           [] x.ev = "catchup_send" -> MatchCatchupSend(x)
           [] x.ev = "ee_answer" -> MatchEpochEndAnswer(x)
           [] x.ev = "rejoin_es" -> MatchRejoinES(x)
           [] x.ev = "crash" -> MatchCrash(x)
           [] x.ev = "restart" -> MatchRestart(x)
           [] x.ev = "joinreq" -> MatchJoinRequest(x)
           [] x.ev = "adopt" -> IF epoch[x.n] = x.epoch THEN Stutter ELSE AdoptEpoch(x.n) /\ epoch'[x.n] = x.epoch
           [] OTHER -> Stutter
    /\ l' = l + 1

\* Violated exactly when every event of the trace has been matched.
NotDone == l <= Len(TraceLog)

\* HotStandby's Safety, re-expressed for long traces: the same predicates, with the
\* client stream (RecvLen, Recv) computed once per state. HotStandby's Recv is an
\* operator that TLC re-evaluates at every reference, so Safety costs O(n^4) in the log
\* length (a 549-step trace took 15 minutes with Safety and 15 seconds with TSafety).
TRecv ==
    LET idx == {r.idx : r \in released}
        len == IF \A i \in 1..MaxLog : i \in idx THEN MaxLog
               ELSE (CHOOSE k \in 1..MaxLog : k \notin idx /\ \A j \in 1..(k - 1) : j \in idx) - 1
    IN  [i \in 1..len |-> (CHOOSE r \in released : r.idx = i).ent]

TSafety ==
    LET R == TRecv IN
    /\ OnePrimaryPerEpoch /\ WitnessAuthority /\ LeaderCompleteness /\ ReleasedConsistent
    /\ \A n \in Nodes : IsPrimary(n) /\ epoch[n] = wEpoch => Len(log[n]) >= Len(R) /\ Prefix(log[n], Len(R)) = R
    /\ NoDuplicateExecution
    /\ \A i, j \in DOMAIN R : i # j /\ R[i].v # ES => R[i].v # R[j].v

=============================================================================
