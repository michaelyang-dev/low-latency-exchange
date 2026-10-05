-------------------------- MODULE HotStandbyLive --------------------------
(***************************************************************************)
(* Liveness of the hot-standby protocol (docs/plan/10 §6, "Liveness").    *)
(*                                                                         *)
(* The behaviors are a subset of HotStandby's, so every safety result      *)
(* carries over. Three assumptions are added, none of which affects        *)
(* safety:                                                                 *)
(*  - The failure detectors are accurate in this model. A backup suspects  *)
(*    the primary (Freeze) only when it cannot hear it: the primary is     *)
(*    down or restarting, or the A-B link is cut. A primary suspects its   *)
(*    backup (RequestSolo) only under the same conditions for the backup.  *)
(*  - The witness tie-break (plan 10 §2) grants PROMOTE only after it      *)
(*    stops hearing W.primary. A restarted primary has a new incarnation,  *)
(*    so its heartbeats do not count: W hears "the primary" only while     *)
(*    the node is up in the incarnation W recorded.                        *)
(*  - Weak fairness on every protocol step; crashes are never forced.     *)
(*                                                                         *)
(* LinkCut models a permanent cut of the A-B data link with both nodes    *)
(* alive (fault class F6). The witness links stay up.                      *)
(***************************************************************************)
EXTENDS HotStandby

CONSTANTS
    LinkCut,
    \* Liveness mutants (FALSE in the correct model): each must violate a property.
    LMutLiteralTieBreak,  \* W also counts heartbeats from a restarted primary
    LMutNoTieBreak        \* W grants PROMOTE whether or not it hears the primary

P0 == CHOOSE p \in Nodes : TRUE     \* the initial primary (no symmetry here)

LInit == Init /\ wPrimary = P0

\* What the data link lets a node hear from its peer.
HearsPeerAs(n, roles) == ~LinkCut /\ role[Other(n)] \in roles

\* The witness hears its primary's current incarnation.
WHearsPrimary ==
    /\ role[wPrimary] # "Down"
    /\ LMutLiteralTieBreak \/ inc[wPrimary] = wInc[wPrimary]

LFreeze(m)        == Freeze(m) /\ ~HearsPeerAs(m, {"P"})
LRequestSolo(n)   == RequestSolo(n) /\ ~HearsPeerAs(n, {"B"})
LRecvAppend(m)    == RecvAppend(m) /\ ~LinkCut
LRecvAck(n)       == RecvAck(n) /\ ~LinkCut
LRejoin(r)        == Rejoin(r) /\ ~LinkCut
LGrantPromote     == WitnessGrantPromote /\ (LMutNoTieBreak \/ ~WHearsPrimary)

LNext ==
    \/ \E n \in Nodes, o \in Orders : SequenceOrder(n, o)
    \/ \E n \in Nodes :
          \/ SendAppend(n) \/ LRecvAppend(n) \/ LRecvAck(n)
          \/ Flush(n) \/ Release(n)
          \/ ProcCrash(n) \/ HostCrash(n) \/ Restart(n)
          \/ LFreeze(n) \/ RequestPromote(n) \/ LRequestSolo(n) \/ RequestResume(n) \/ RecvGrant(n)
          \/ LRejoin(n)
    \/ LGrantPromote \/ WitnessGrantSolo \/ WitnessGrantResume

Fairness ==
    /\ \A n \in Nodes, o \in Orders : WF_vars(SequenceOrder(n, o))
    /\ \A n \in Nodes :
          /\ WF_vars(SendAppend(n)) /\ WF_vars(LRecvAppend(n)) /\ WF_vars(LRecvAck(n))
          /\ WF_vars(Flush(n)) /\ WF_vars(Release(n)) /\ WF_vars(Restart(n))
          /\ WF_vars(LFreeze(n)) /\ WF_vars(RequestPromote(n)) /\ WF_vars(LRequestSolo(n))
          /\ WF_vars(RequestResume(n)) /\ WF_vars(RecvGrant(n)) /\ WF_vars(LRejoin(n))
    /\ WF_vars(LGrantPromote) /\ WF_vars(WitnessGrantSolo) /\ WF_vars(WitnessGrantResume)

LiveSpec == LInit /\ [][LNext]_vars /\ Fairness

---------------------------------------------------------------------------
(* Properties. *)

\* Eventually there is, forever, a primary of the witness's current epoch.
EventuallyStablePrimary == <>[](\E n \in Nodes : IsPrimary(n) /\ epoch[n] = wEpoch)

\* Every client order is eventually delivered to the client (clients resend
\* until acknowledged; the sequencer deduplicates).
EventualDelivery == \A o \in Orders : <>(\E i \in 1..RecvLen : Recv[i].v = o)

\* With the A-B link cut and both nodes alive, the existing primary ends up
\* in solo mode, and there is never a takeover.
CutLinkLeadsToSolo == LinkCut => <>[](role[P0] = "SP" /\ wPrimary = P0)
NoTakeoverOnCut == LinkCut => wPrimary = P0

=============================================================================
