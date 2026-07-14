---------------------------- MODULE QorusBFT ----------------------------
(***************************************************************************)
(* Formal model of the QORUS byzantine fault tolerant core, stage one.     *)
(* It follows SPEC-consensus-qorus.md. A committee of validators decides    *)
(* one block per height. A deterministic leader proposes, committee         *)
(* members attest, and a supermajority of two thirds plus one aggregates    *)
(* into a single certificate that finalizes the block. Signatures are       *)
(* abstracted as an authenticated fact, meaning an attestation is a record  *)
(* that a named validator attested a named block. Timeouts drive view       *)
(* changes under partial synchrony. Offline validators are skipped and are  *)
(* never slashed. Provers hold no vote and never enter a quorum.            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    N,             \* number of validators, the committee is Validators
    Byzantine,     \* the byzantine subset, at most one third minus one
    Offline,       \* validators that are absent this run, skipped not slashed
    Provers,       \* provers, disjoint from validators, zero vote
    Vals,          \* the block payload values available at a height
    Genesis,       \* the parent tag of the first finalized block
    ResourceBound, \* the validator resource budget, an abstract bound
    MaxHeight,     \* highest height the finite model explores
    MaxView        \* highest view a height may reach before the run ends

Validators == 1 .. N
Honest == Validators \ Byzantine
Heights == 1 .. MaxHeight
MinHeight == 1

ASSUME NIsPositive == N \in Nat \ {0}
ASSUME ByzantineSubset == Byzantine \subseteq Validators
ASSUME OfflineSubset == Offline \subseteq Validators
ASSUME ProversDisjoint == Provers \cap Validators = {}
ASSUME BudgetPositive == ResourceBound \in Nat \ {0}
ASSUME HeightBound == MaxHeight \in Nat \ {0}
ASSUME ViewBound == MaxView \in Nat
\* The safety hypothesis of the protocol, fewer than one third byzantine.
ASSUME FaultBound == Cardinality(Byzantine) * 3 < Cardinality(Validators)

-----------------------------------------------------------------------------
(* A quorum is any set of validators whose size exceeds two thirds of the   *)
(* committee, which is the two thirds plus one supermajority. Provers are   *)
(* not validators so they never contribute to a quorum.                     *)
Quorums == { Q \in SUBSET Validators : Cardinality(Q) * 3 > 2 * Cardinality(Validators) }

(* A block records its height, its payload value, and the value of the      *)
(* block it descends from. Parents outside Vals are only the Genesis tag.   *)
Parents == Vals \cup {Genesis}
BlocksAt(h) == [ height : {h}, val : Vals, parent : Parents ]
AllBlocks == [ height : Heights, val : Vals, parent : Parents ]

(* The resource budget is an abstract bound. Every block carries a cost and *)
(* a block is only valid when its cost is within the budget. Raising a      *)
(* cost above ResourceBound would make the block invalid and unattestable.  *)
Cost(b) == 1
WithinBudget(b) == Cost(b) <= ResourceBound

(* Deterministic leader rotation inside the committee, seeded by height and *)
(* view. Every validator appears as leader as the view advances.            *)
Leader(h, v) == ((h + v) % N) + 1

-----------------------------------------------------------------------------
VARIABLES
    msgs,   \* the growing set of authenticated proposals and attestations
    certs,  \* the set of finality certificates, one intended per height
    view,   \* the current view per height, advanced by a timeout
    stable  \* partial synchrony, TRUE once the network has stabilized

vars == << msgs, certs, view, stable >>

Decided(h) == \E c \in certs : c.height = h
FinalBlockOf(h) == (CHOOSE c \in certs : c.height = h).block
ParentVal(h) == IF h = MinHeight THEN Genesis ELSE FinalBlockOf(h - 1).val

(* A height is being worked when it is undecided and every earlier height   *)
(* is already decided, so the chain grows in order.                         *)
Working(h) == /\ ~ Decided(h)
              /\ \A g \in Heights : (g < h) => Decided(g)

(* A block is valid at a height when it is shaped for that height, carries  *)
(* a known value, descends from the previous finalized value, and respects  *)
(* the resource budget.                                                     *)
ValidBlock(b, h) == /\ b.height = h
                    /\ b.val \in Vals
                    /\ b.parent = ParentVal(h)
                    /\ WithinBudget(b)

HonestProposal(h) == [ height |-> h,
                       val |-> CHOOSE x \in Vals : TRUE,
                       parent |-> ParentVal(h) ]

VotedFor(x, h, b) == \E m \in msgs : /\ m.kind = "vote"
                                     /\ m.from = x
                                     /\ m.height = h
                                     /\ m.block = b

VotedOther(x, h, b) == \E m \in msgs : /\ m.kind = "vote"
                                       /\ m.from = x
                                       /\ m.height = h
                                       /\ m.block # b

SawProposal(h, b) == \E m \in msgs : /\ m.kind = "propose"
                                     /\ m.height = h
                                     /\ m.block = b
                                     /\ m.view <= view[h]
                                     /\ m.from = Leader(h, m.view)

-----------------------------------------------------------------------------
Init == /\ msgs = {}
        /\ certs = {}
        /\ view = [ h \in Heights |-> 0 ]
        /\ stable = FALSE

(* The honest leader of the current view proposes its single valid block.   *)
HonestPropose(h) ==
    LET l == Leader(h, view[h])
        b == HonestProposal(h)
        m == [ kind |-> "propose", from |-> l, height |-> h, view |-> view[h], block |-> b ]
    IN /\ Working(h)
       /\ l \in Honest
       /\ l \notin Offline
       /\ m \notin msgs
       /\ msgs' = msgs \cup {m}
       /\ UNCHANGED << certs, view, stable >>

(* A byzantine leader may propose any block, including an invalid one or a   *)
(* second block in the same view, which is an equivocating proposal.         *)
ByzPropose(h, b) ==
    LET l == Leader(h, view[h])
        m == [ kind |-> "propose", from |-> l, height |-> h, view |-> view[h], block |-> b ]
    IN /\ Working(h)
       /\ l \in Byzantine
       /\ l \notin Offline
       /\ b \in BlocksAt(h)
       /\ m \notin msgs
       /\ msgs' = msgs \cup {m}
       /\ UNCHANGED << certs, view, stable >>

(* An honest validator attests a validly proposed block from the legitimate  *)
(* leader of a view it has reached, and only when it has not already         *)
(* attested a different block at this height, so an honest validator never   *)
(* equivocates.                                                              *)
Vote(x, h, b) ==
    LET m == [ kind |-> "vote", from |-> x, height |-> h, block |-> b ]
    IN /\ Working(h)
       /\ x \in Honest
       /\ x \notin Offline
       /\ ValidBlock(b, h)
       /\ SawProposal(h, b)
       /\ ~ VotedOther(x, h, b)
       /\ m \notin msgs
       /\ msgs' = msgs \cup {m}
       /\ UNCHANGED << certs, view, stable >>

(* A byzantine validator may attest any block and may attest two different   *)
(* blocks at one height, which is equivocation.                              *)
ByzVote(x, h, b) ==
    LET m == [ kind |-> "vote", from |-> x, height |-> h, block |-> b ]
    IN /\ Working(h)
       /\ x \in Byzantine
       /\ b \in BlocksAt(h)
       /\ m \notin msgs
       /\ msgs' = msgs \cup {m}
       /\ UNCHANGED << certs, view, stable >>

(* When a quorum has attested one block, the attestations aggregate into a   *)
(* single certificate and the block is finalized. The rule does not forbid   *)
(* a second certificate at the same height, so the model would expose a      *)
(* conflicting finalization if the quorum arithmetic allowed one.            *)
Finalize(h, b) ==
    LET c == [ height |-> h, block |-> b ]
    IN /\ h \in Heights
       /\ \A g \in Heights : (g < h) => Decided(g)
       /\ \E Q \in Quorums : \A x \in Q : VotedFor(x, h, b)
       /\ c \notin certs
       /\ certs' = certs \cup {c}
       /\ UNCHANGED << msgs, view, stable >>

(* A timeout advances the view of an undecided height, rotating the leader.  *)
(* Before stabilization the network may time out at any point. After         *)
(* stabilization it only rotates past a leader that is offline or byzantine. *)
Timeout(h) ==
    /\ Working(h)
    /\ view[h] < MaxView
    /\ \/ ~ stable
       \/ /\ stable
          /\ \/ Leader(h, view[h]) \in Offline
             \/ Leader(h, view[h]) \in Byzantine
    /\ view' = [ view EXCEPT ![h] = view[h] + 1 ]
    /\ UNCHANGED << msgs, certs, stable >>

Stabilize ==
    /\ ~ stable
    /\ stable' = TRUE
    /\ UNCHANGED << msgs, certs, view >>

Next ==
    \/ \E h \in Heights : HonestPropose(h)
    \/ \E h \in Heights, b \in AllBlocks : ByzPropose(h, b)
    \/ \E x \in Validators, h \in Heights, b \in AllBlocks : Vote(x, h, b)
    \/ \E x \in Validators, h \in Heights, b \in AllBlocks : ByzVote(x, h, b)
    \/ \E h \in Heights, b \in AllBlocks : Finalize(h, b)
    \/ \E h \in Heights : Timeout(h)
    \/ Stabilize

Fairness ==
    /\ WF_vars(Stabilize)
    /\ \A h \in Heights : WF_vars(HonestPropose(h))
    /\ \A h \in Heights : WF_vars(Timeout(h))
    /\ \A x \in Validators : \A h \in Heights : \A b \in BlocksAt(h) : WF_vars(Vote(x, h, b))
    /\ \A h \in Heights : \A b \in BlocksAt(h) : WF_vars(Finalize(h, b))

SafeSpec == Init /\ [][Next]_vars
Spec == Init /\ [][Next]_vars /\ Fairness

=============================================================================
