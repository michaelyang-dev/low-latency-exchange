---------------------------- MODULE HotStandby ----------------------------
(***************************************************************************)
(* Hot-standby state machine replication with a durable witness           *)
(* (docs/plan/10-replication-failover.md).                                 *)
(*                                                                         *)
(* Two data nodes replicate a sequenced log. A witness W alone decrees     *)
(* epochs and membership (Vertical-Paxos-II style). Outputs are released   *)
(* to clients only under the Output Rule: in paired mode an index is       *)
(* released only once it is held (L2) by both members; in solo mode only   *)
(* once it is durable (L3) on the primary.                                 *)
(*                                                                         *)
(* Every log entry produces one client-visible output record (an epoch-   *)
(* start marker is an output that clients ignore), so a client's stream   *)
(* is a prefix of the log of the node that produced it.                    *)
(*                                                                         *)
(* Mutant switches (all FALSE in the correct model) re-introduce one bug   *)
(* each; every mutant configuration must yield a counterexample.          *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    Nodes,            \* the two data nodes
    Orders,           \* client orders (each carries a unique UserRefNum)
    MaxEpoch,         \* bound on witness epochs
    MaxLog,           \* bound on log length
    MaxHostCrashes,   \* host crash: loses the node's L2 (in-memory) tail
    MaxProcCrashes,   \* process crash: L2 survives (hugetlbfs/shm ring)
    MutNoOutputRule, MutNoMemberCheck, MutNoIncarnation, MutNoTruncate,
    MutNoDedupe, MutAckBeforeAppend, MutAckWhileCandidate, MutSoloReleaseFromL2

ASSUME Cardinality(Nodes) = 2

ES == "ES"                                  \* epoch-start marker value
Entry == [e : 1..MaxEpoch, v : Orders \cup {ES}]
Roles == {"P", "SP", "SC", "B", "C", "R", "Down"}
                                            \* paired primary, solo primary,
                                            \* solo candidate (frozen, awaiting
                                            \* a SOLO grant), backup, candidate
                                            \* (frozen), recovering, down

VARIABLES
    wEpoch, wPrimary, wMembers, wInc,       \* witness state (durable)
    role, epoch, log, durLen, ackLen, inc, frozenLast,
    net,                                    \* in-flight messages: a set, so
                                            \* loss, reordering and duplication
                                            \* are all possible
    released,                               \* outputs released to clients
    hostCrashes, procCrashes

witnessVars == <<wEpoch, wPrimary, wMembers, wInc>>
nodeVars == <<role, epoch, log, durLen, ackLen, inc, frozenLast>>
vars == <<witnessVars, nodeVars, net, released, hostCrashes, procCrashes>>

Other(n) == CHOOSE m \in Nodes : m # n
Min(x, y) == IF x < y THEN x ELSE y
Max(x, y) == IF x > y THEN x ELSE y
IsPrimary(n) == role[n] \in {"P", "SP"}
InLog(l, o) == \E i \in 1..Len(l) : l[i].v = o
Prefix(s, n) == SubSeq(s, 1, n)

\* Longest common prefix length of two sequences.
LCP(s, t) == LET k == Min(Len(s), Len(t))
             IN  IF \A i \in 1..k : s[i] = t[i] THEN k
                 ELSE CHOOSE j \in 0..k : (\A i \in 1..j : s[i] = t[i]) /\ s[j+1] # t[j+1]

\* A cumulative ACK replaces older ACKs from the same sender and epoch: an
\* older cumulative ACK delivered late can only be a no-op (RecvAck requires
\* an increase), so dropping it loses no behavior.
SupersedeAck(N, m, ep, len) ==
    {x \in N : ~(x.type = "ACK" /\ x.from = m /\ x.ep = ep)}
        \cup {[type |-> "ACK", from |-> m, ep |-> ep, len |-> len]}

ReleasedIdx == {r.idx : r \in released}

\* The client's stream: outputs are consumed in sequence order (MoldUDP64 /
\* SoupBinTCP sequence numbers), so the client holds exactly the gap-free
\* prefix of released indices. (Conflicting releases of one index are caught
\* by ReleasedConsistent; the stream then takes any one of them.)
RecvLen == IF \A i \in 1..MaxLog : i \in ReleasedIdx THEN MaxLog
           ELSE (CHOOSE k \in 1..MaxLog : k \notin ReleasedIdx /\ \A j \in 1..(k - 1) : j \in ReleasedIdx) - 1
Recv == [i \in 1..RecvLen |-> (CHOOSE r \in released : r.idx = i).ent]

\* Output Rule: highest index node n may release.
ReleaseLimit(n) ==
    CASE role[n] = "P"  -> IF MutNoOutputRule THEN Len(log[n]) ELSE Min(Len(log[n]), ackLen[n])
      [] role[n] = "SP" -> IF MutSoloReleaseFromL2 THEN Len(log[n]) ELSE durLen[n]
      [] OTHER          -> 0

---------------------------------------------------------------------------
Init ==
    \E p \in Nodes :                       \* symmetric: no node is special
        /\ wEpoch = 1 /\ wPrimary = p /\ wMembers = Nodes
        /\ wInc = [n \in Nodes |-> 0]
        /\ role = [n \in Nodes |-> IF n = p THEN "P" ELSE "B"]
        /\ epoch = [n \in Nodes |-> 1]
        /\ log = [n \in Nodes |-> << [e |-> 1, v |-> ES] >>]
        /\ durLen = [n \in Nodes |-> 1]
        /\ ackLen = [n \in Nodes |-> 1]
        /\ inc = [n \in Nodes |-> 0]
        /\ frozenLast = [n \in Nodes |-> 0]
        /\ net = {}
        /\ released = {}
        /\ hostCrashes = 0 /\ procCrashes = 0

---------------------------------------------------------------------------
(* Sequencing. Clients may (re)send any order at any time; the UserRefNum  *)
(* filter, derived from the replicated log, prevents a second append.     *)
SequenceOrder(n, o) ==
    /\ IsPrimary(n)
    /\ Len(log[n]) < MaxLog
    /\ MutNoDedupe \/ ~InLog(log[n], o)
    /\ log' = [log EXCEPT ![n] = Append(@, [e |-> epoch[n], v |-> o])]
    /\ UNCHANGED <<witnessVars, role, epoch, durLen, ackLen, inc, frozenLast,
                   net, released, hostCrashes, procCrashes>>

(* Primary (re)transmits any entry of its log to the backup. *)
SendAppend(n) ==
    /\ role[n] = "P"
    /\ \E i \in (ackLen[n] + 1)..Len(log[n]) :      \* (re)transmit unacknowledged entries
          net' = net \cup {[type |-> "APPEND", from |-> n, ep |-> epoch[n],
                            idx |-> i, ent |-> log[n][i]]}
    /\ UNCHANGED <<witnessVars, nodeVars, released, hostCrashes, procCrashes>>

AcceptsAppends(m) == role[m] = "B" \/ (MutAckWhileCandidate /\ role[m] = "C")

(* Backup appends the next entry to its L2 and acknowledges (cumulative). *)
RecvAppend(m) ==
    /\ AcceptsAppends(m)
    /\ \E msg \in net :
          /\ msg.type = "APPEND" /\ msg.from # m /\ msg.ep = epoch[m]
          /\ msg.idx = Len(log[m]) + 1 /\ Len(log[m]) < MaxLog
          /\ log' = [log EXCEPT ![m] = Append(@, msg.ent)]
          /\ net' = SupersedeAck(net, m, epoch[m], Len(log[m]) + 1)
    /\ UNCHANGED <<witnessVars, role, epoch, durLen, ackLen, inc, frozenLast,
                   released, hostCrashes, procCrashes>>

(* Mutant: acknowledge before the L2 append (then never append). *)
RecvAppendAckFirst(m) ==
    /\ MutAckBeforeAppend
    /\ AcceptsAppends(m)
    /\ \E msg \in net :
          /\ msg.type = "APPEND" /\ msg.from # m /\ msg.ep = epoch[m]
          /\ msg.idx = Len(log[m]) + 1
          /\ net' = SupersedeAck(net, m, epoch[m], msg.idx)
    /\ UNCHANGED <<witnessVars, nodeVars, released, hostCrashes, procCrashes>>

RecvAck(n) ==
    /\ role[n] = "P"
    /\ \E msg \in net :
          /\ msg.type = "ACK" /\ msg.from # n /\ msg.ep = epoch[n] /\ msg.len > ackLen[n]
          /\ ackLen' = [ackLen EXCEPT ![n] = msg.len]
    /\ UNCHANGED <<witnessVars, role, epoch, log, durLen, inc, frozenLast,
                   net, released, hostCrashes, procCrashes>>

(* L3: the journal writer makes the local log durable. *)
Flush(n) ==
    /\ role[n] # "Down"
    /\ durLen[n] < Len(log[n])
    /\ durLen' = [durLen EXCEPT ![n] = Len(log[n])]
    /\ UNCHANGED <<witnessVars, role, epoch, log, ackLen, inc, frozenLast,
                   net, released, hostCrashes, procCrashes>>

(* Release one output under the Output Rule. *)
Release(n) ==
    /\ IsPrimary(n)
    /\ LET unreleased == {i \in 1..ReleaseLimit(n) :
                             [idx |-> i, ent |-> log[n][i]] \notin {[idx |-> r.idx, ent |-> r.ent] : r \in released}}
       IN  /\ unreleased # {}
           /\ LET i == CHOOSE j \in unreleased : \A k \in unreleased : j <= k   \* in index order
              IN  released' = released \cup {[idx |-> i, ent |-> log[n][i], ep |-> epoch[n]]}
    /\ UNCHANGED <<witnessVars, nodeVars, net, hostCrashes, procCrashes>>

---------------------------------------------------------------------------
(* Failures. *)
ProcCrash(n) ==
    /\ role[n] # "Down" /\ procCrashes < MaxProcCrashes
    /\ role' = [role EXCEPT ![n] = "Down"]
    /\ procCrashes' = procCrashes + 1
    /\ UNCHANGED <<witnessVars, epoch, log, durLen, ackLen, inc, frozenLast,
                   net, released, hostCrashes>>

HostCrash(n) ==
    /\ hostCrashes < MaxHostCrashes
    /\ role' = [role EXCEPT ![n] = "Down"]
    /\ log' = [log EXCEPT ![n] = Prefix(@, durLen[n])]
    /\ hostCrashes' = hostCrashes + 1
    /\ UNCHANGED <<witnessVars, epoch, durLen, ackLen, inc, frozenLast,
                   net, released, procCrashes>>

Restart(n) ==
    /\ role[n] = "Down"
    /\ role' = [role EXCEPT ![n] = "R"]
    /\ inc' = [inc EXCEPT ![n] = @ + 1]
    /\ ackLen' = [ackLen EXCEPT ![n] = 0]
    /\ UNCHANGED <<witnessVars, epoch, log, durLen, frozenLast,
                   net, released, hostCrashes, procCrashes>>

---------------------------------------------------------------------------
(* Takeover. Suspicion may be true or false (no timing assumptions).     *)
Freeze(m) ==
    /\ role[m] = "B"
    /\ role' = [role EXCEPT ![m] = "C"]
    /\ frozenLast' = [frozenLast EXCEPT ![m] = Len(log[m])]
    /\ UNCHANGED <<witnessVars, epoch, log, durLen, ackLen, inc,
                   net, released, hostCrashes, procCrashes>>

(* Candidates request promotion. Recovering nodes may also (mistakenly)   *)
(* ask: the witness's incarnation check must reject them.                 *)
RequestPromote(m) ==
    /\ role[m] \in {"C", "R"}
    \* A candidate makes its whole log durable (L3) before asking: everything
    \* the old primary may have released is then on disk before m can lead.
    /\ role[m] = "C" => durLen[m] = Len(log[m])
    /\ net' = net \cup {[type |-> "PROMOTE", from |-> m, fe |-> epoch[m], inc |-> inc[m]]}
    /\ UNCHANGED <<witnessVars, nodeVars, released, hostCrashes, procCrashes>>

\* A paired primary that lost its backup stops releasing (SC) and makes its
\* log durable before asking for solo mode.
RequestSolo(n) ==
    /\ role[n] = "P"
    /\ durLen[n] = Len(log[n])
    /\ role' = [role EXCEPT ![n] = "SC"]
    /\ net' = net \cup {[type |-> "SOLO", from |-> n, fe |-> epoch[n], inc |-> inc[n]]}
    /\ UNCHANGED <<witnessVars, epoch, log, durLen, ackLen, inc, frozenLast,
                   released, hostCrashes, procCrashes>>

\* A restarted solo primary of record asks to resume from its durable log.
RequestResume(n) ==
    /\ role[n] = "R"
    /\ net' = net \cup {[type |-> "RESUME", from |-> n, fe |-> epoch[n], inc |-> inc[n]]}
    /\ UNCHANGED <<witnessVars, nodeVars, released, hostCrashes, procCrashes>>

WitnessGrantResume ==
    /\ wEpoch < MaxEpoch
    /\ \E msg \in net :
          /\ msg.type = "RESUME" /\ msg.fe = wEpoch
          /\ msg.from = wPrimary /\ wMembers = {msg.from}
          /\ wEpoch' = wEpoch + 1
          /\ wInc' = [wInc EXCEPT ![msg.from] = msg.inc]
          /\ net' = net \cup {[type |-> "GRANT", to |-> msg.from, inc |-> msg.inc, ep |-> wEpoch + 1]}
    /\ UNCHANGED <<wPrimary, wMembers, nodeVars, released, hostCrashes, procCrashes>>

WitnessGrantPromote ==
    /\ wEpoch < MaxEpoch
    /\ \E msg \in net :
          /\ msg.type = "PROMOTE"
          /\ MutNoMemberCheck \/ (msg.fe = wEpoch /\ msg.from \in wMembers /\ msg.from # wPrimary)
          /\ MutNoIncarnation \/ MutNoMemberCheck \/ msg.inc = wInc[msg.from]
          /\ wEpoch' = wEpoch + 1 /\ wPrimary' = msg.from /\ wMembers' = {msg.from}
          /\ net' = net \cup {[type |-> "GRANT", to |-> msg.from, inc |-> msg.inc, ep |-> wEpoch + 1]}
    /\ UNCHANGED <<wInc, nodeVars, released, hostCrashes, procCrashes>>

WitnessGrantSolo ==
    /\ wEpoch < MaxEpoch
    /\ \E msg \in net :
          /\ msg.type = "SOLO" /\ msg.fe = wEpoch /\ msg.from = wPrimary
          /\ msg.inc = wInc[msg.from]
          /\ wEpoch' = wEpoch + 1 /\ wMembers' = {msg.from}
          /\ net' = net \cup {[type |-> "GRANT", to |-> msg.from, inc |-> msg.inc, ep |-> wEpoch + 1]}
    /\ UNCHANGED <<wPrimary, wInc, nodeVars, released, hostCrashes, procCrashes>>

(* A grant makes the receiver a solo primary in the new epoch. A candidate *)
(* writes the epoch-start marker right after its frozen last index.        *)
RecvGrant(m) ==
    /\ role[m] \in {"C", "R", "SC"}
    /\ \E msg \in net :
          /\ msg.type = "GRANT" /\ msg.to = m /\ msg.ep > epoch[m]
          \* A grant is valid only for the incarnation that requested it.
          /\ MutNoIncarnation \/ msg.inc = inc[m]
          /\ LET keep == IF role[m] = "C" THEN frozenLast[m] ELSE Len(log[m])
             IN  /\ keep < MaxLog
                 /\ log' = [log EXCEPT ![m] = Append(Prefix(@, keep), [e |-> msg.ep, v |-> ES])]
                 /\ durLen' = [durLen EXCEPT ![m] = Min(@, keep)]
          /\ epoch' = [epoch EXCEPT ![m] = msg.ep]
          /\ role' = [role EXCEPT ![m] = "SP"]
    /\ UNCHANGED <<witnessVars, ackLen, inc, frozenLast, net, released,
                   hostCrashes, procCrashes>>

(* Rejoin (abstracted atomically: the primary pauses releasing during the *)
(* handshake). The joiner truncates its divergent tail (epoch-based in the *)
(* implementation), catches up to the primary, and the witness grants a    *)
(* new paired epoch. Both logs receive the new epoch-start marker.        *)
Rejoin(r) ==
    /\ role[r] \in {"R", "B", "C", "SC"}
    /\ r \notin wMembers
    /\ LET p == wPrimary IN
       /\ role[p] = "SP" /\ epoch[p] = wEpoch
       /\ wEpoch < MaxEpoch
       /\ Len(log[p]) < MaxLog
       /\ LET common == LCP(log[r], log[p])
              base   == IF MutNoTruncate THEN log[r] ELSE Prefix(log[r], common)
              caught == base \o SubSeq(log[p], Len(base) + 1, Len(log[p]))
              es     == [e |-> wEpoch + 1, v |-> ES]
          IN  /\ Len(caught) < MaxLog
              /\ log' = [log EXCEPT ![p] = Append(@, es), ![r] = Append(caught, es)]
              /\ durLen' = [durLen EXCEPT ![r] = Min(@, common)]
              /\ ackLen' = [ackLen EXCEPT ![p] = Len(log[p]) + 1]
       /\ wEpoch' = wEpoch + 1 /\ wMembers' = Nodes
       /\ wInc' = [wInc EXCEPT ![r] = inc[r]]
       /\ epoch' = [n \in Nodes |-> wEpoch + 1]
       /\ role' = [role EXCEPT ![p] = "P", ![r] = "B"]
    /\ UNCHANGED <<wPrimary, inc, frozenLast, net, released, hostCrashes, procCrashes>>

---------------------------------------------------------------------------
Next ==
    \/ \E n \in Nodes, o \in Orders : SequenceOrder(n, o)
    \/ \E n \in Nodes :
          \/ SendAppend(n) \/ RecvAppend(n) \/ RecvAppendAckFirst(n) \/ RecvAck(n)
          \/ Flush(n) \/ Release(n)
          \/ ProcCrash(n) \/ HostCrash(n) \/ Restart(n)
          \/ Freeze(n) \/ RequestPromote(n) \/ RequestSolo(n) \/ RequestResume(n) \/ RecvGrant(n)
          \/ Rejoin(n)
    \/ WitnessGrantPromote \/ WitnessGrantSolo \/ WitnessGrantResume

Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
(* Invariants (names shared with the simulator oracles, docs/plan/09). *)
TypeOK ==
    /\ role \in [Nodes -> Roles]
    /\ epoch \in [Nodes -> 1..MaxEpoch]
    /\ \A n \in Nodes : Len(log[n]) <= MaxLog
    /\ wEpoch \in 1..MaxEpoch /\ wPrimary \in Nodes /\ wMembers \subseteq Nodes

\* At most one primary per epoch.
OnePrimaryPerEpoch ==
    \A m, n \in Nodes : IsPrimary(m) /\ IsPrimary(n) /\ epoch[m] = epoch[n] => m = n

\* No primary is ahead of the witness, and in the witness epoch only the
\* witness-designated node may be primary.
WitnessAuthority ==
    \A n \in Nodes : IsPrimary(n) => epoch[n] <= wEpoch /\ (epoch[n] = wEpoch => wPrimary = n)

\* Every released output is in the log of any primary of the same or a later epoch.
LeaderCompleteness ==
    \A r \in released : \A n \in Nodes :
        IsPrimary(n) /\ epoch[n] >= r.ep => Len(log[n]) >= r.idx /\ log[n][r.idx] = r.ent

\* Two releases of one index always carry the same output.
ReleasedConsistent ==
    \A r1, r2 \in released : r1.idx = r2.idx => r1.ent = r2.ent

\* The client's stream is a prefix of the current primary's log
\* (O-PREFIX / O-NO-LOST-FILL).
ClientStreamPrefix ==
    \A n \in Nodes :
        IsPrimary(n) /\ epoch[n] = wEpoch =>
            Len(log[n]) >= RecvLen /\ Prefix(log[n], RecvLen) = Recv

\* No order executes twice in any log (O-EXACTLY-ONCE).
NoDuplicateExecution ==
    \A n \in Nodes, o \in Orders :
        Cardinality({i \in 1..Len(log[n]) : log[n][i].v = o}) <= 1

\* No client ever receives the same order twice.
ClientNoDuplicate ==
    \A i, j \in 1..RecvLen : i # j /\ Recv[i].v # ES => Recv[i].v # Recv[j].v

Safety ==
    /\ OnePrimaryPerEpoch /\ WitnessAuthority /\ LeaderCompleteness
    /\ ReleasedConsistent /\ ClientStreamPrefix /\ NoDuplicateExecution /\ ClientNoDuplicate

---------------------------------------------------------------------------
(* Symmetry for safety checking only (unsound with liveness in TLC). *)
NodeSymmetry == Permutations(Nodes)

=============================================================================
