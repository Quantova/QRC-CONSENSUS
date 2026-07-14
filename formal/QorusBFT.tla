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

=============================================================================
