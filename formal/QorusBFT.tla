---------------------------- MODULE QorusBFT ----------------------------
EXTENDS Naturals, FiniteSets

CONSTANTS
    N,
    Byzantine,
    Offline,
    Provers,
    Vals,
    Genesis,
    ResourceBound,
    MaxHeight,
    MaxView

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
ASSUME FaultBound == Cardinality(Byzantine) * 3 < Cardinality(Validators)

-----------------------------------------------------------------------------
Quorums == { Q \in SUBSET Validators : Cardinality(Q) * 3 > 2 * Cardinality(Validators) }

Parents == Vals \cup {Genesis}
BlocksAt(h) == [ height : {h}, val : Vals, parent : Parents ]
AllBlocks == [ height : Heights, val : Vals, parent : Parents ]

Cost(b) == 1
WithinBudget(b) == Cost(b) <= ResourceBound

Leader(h, v) == ((h + v) % N) + 1

-----------------------------------------------------------------------------
VARIABLES
    msgs,
    certs,
    view,
    stable

vars == << msgs, certs, view, stable >>

Decided(h) == \E c \in certs : c.height = h
FinalBlockOf(h) == (CHOOSE c \in certs : c.height = h).block
ParentVal(h) == IF h = MinHeight THEN Genesis ELSE FinalBlockOf(h - 1).val

Working(h) == /\ ~ Decided(h)
              /\ \A g \in Heights : (g < h) => Decided(g)

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

ByzVote(x, h, b) ==
    LET m == [ kind |-> "vote", from |-> x, height |-> h, block |-> b ]
    IN /\ Working(h)
       /\ x \in Byzantine
       /\ b \in BlocksAt(h)
       /\ m \notin msgs
       /\ msgs' = msgs \cup {m}
       /\ UNCHANGED << certs, view, stable >>

Finalize(h, b) ==
    LET c == [ height |-> h, block |-> b ]
    IN /\ h \in Heights
       /\ \A g \in Heights : (g < h) => Decided(g)
       /\ \E Q \in Quorums : \A x \in Q : VotedFor(x, h, b)
       /\ c \notin certs
       /\ certs' = certs \cup {c}
       /\ UNCHANGED << msgs, view, stable >>

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

-----------------------------------------------------------------------------

TypeOK ==
    /\ msgs \subseteq ( [ kind : {"propose"}, from : Validators, height : Heights, view : 0 .. MaxView, block : AllBlocks ]
                        \cup [ kind : {"vote"}, from : Validators, height : Heights, block : AllBlocks ] )
    /\ certs \subseteq [ height : Heights, block : AllBlocks ]
    /\ view \in [ Heights -> 0 .. MaxView ]
    /\ stable \in BOOLEAN

Agreement == \A c1, c2 \in certs : (c1.height = c2.height) => (c1.block = c2.block)

ValidFinalized == \A c \in certs : ValidBlock(c.block, c.height)

ChainDescends ==
    \A c \in certs :
        IF c.height = MinHeight
          THEN c.block.parent = Genesis
          ELSE /\ Decided(c.height - 1)
               /\ c.block.parent = FinalBlockOf(c.height - 1).val

Equivocators ==
    { x \in Validators :
        \E m1, m2 \in msgs :
            /\ m1.kind = "vote" /\ m2.kind = "vote"
            /\ m1.from = x /\ m2.from = x
            /\ m1.height = m2.height
            /\ m1.block # m2.block }

OnlyByzantineSlashed == Equivocators \subseteq Byzantine

OfflineNeverSlashed == Offline \cap Equivocators = {}

ProversHaveNoVote == \A m \in msgs : m.from \in Validators

-----------------------------------------------------------------------------
AllFinalized == \A h \in Heights : Decided(h)
Liveness == stable ~> AllFinalized

=============================================================================
