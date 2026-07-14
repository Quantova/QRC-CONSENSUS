# QORUS formal model

This directory holds the formal model of the QORUS byzantine fault tolerant core, stage one, written in TLA+. It follows SPEC-consensus-qorus.md in the Quantova Specs repository. The build order places a formal model before stage one activates and before the protocol crate, so the model is written now. It states the safety and liveness properties of the consensus core and checks them with the TLC model checker over a small finite committee.

## What is modeled

A committee of validators decides one block per height. A deterministic leader rotates within the committee and proposes a block for the current view. Committee members attest to a proposed block, and a signature is abstracted as an authenticated fact, meaning an attestation is a record that a named validator attested a named block. When a supermajority of two thirds plus one has attested one block, the attestations aggregate into a single finality certificate and the block is final. The certificate is the only artifact the model keeps, which matches the design where consensus votes never become a stored list. A timeout advances the view of an undecided height, which rotates the leader and models a view change under partial synchrony. A byzantine validator may propose two different blocks in one view and may attest two different blocks at one height, which is equivocation. An offline validator casts no attestation and is skipped. Provers hold no vote and never enter a quorum.

## What is abstracted

Cryptography is abstracted. Module lattice signatures and the STARK certificate become an authenticated fact and a single certificate value, so the model reasons about who attested what rather than about signature bytes. Real time is abstracted. The 150 millisecond slot is a real time parameter that the untimed model replaces with logical views and a stabilization flag, so a timeout is a view change rather than a clock reading. Committee sampling from the beacon is abstracted to a fixed committee, since the safety and liveness of one decision do not depend on how the committee was drawn. The validator resource budget is an abstract bound named ResourceBound rather than a fixed number, and a block is valid only when its cost is within that bound, so a block that exceeded the budget would be rejected and could never finalize. Execution and the account state are out of scope, the model concerns the consensus core only.

## The properties

Agreement states that no two conflicting blocks are ever finalized at one height. ValidFinalized states that a finalized block is well shaped, within the resource budget, and descends from the previous finalized value. ChainDescends states the descendancy directly, a finalized block at the first height descends from Genesis and a finalized block at a later height descends from the block finalized at the height below it. OnlyByzantineSlashed states that only a byzantine validator is ever slashable, since an honest validator never equivocates. OfflineNeverSlashed states that an absent validator is never slashable, which honors the rule that an offline validator is skipped and never punished. ProversHaveNoVote states that no attestation ever originates from a prover. Liveness is a temporal property. It states that once the network stabilizes, and with an honest online supermajority, every pending height eventually finalizes.

## How the finite check is configured

MC_Safety.cfg runs four validators with one byzantine and none offline, over one height with views zero and one, so the quorum is three of four. The byzantine validator leads view zero and may equivocate both its proposal and its attestations, and an honest leader takes view one. The finalization rule does not forbid a second certificate at one height, so a conflicting finalization would appear if the quorum arithmetic allowed one. The check confirms that it never does and that every finalized block is valid. Finalization does occur in this run, because the three honest validators on their own form a quorum, so the safety invariants are not vacuous. MC_Liveness.cfg runs four validators with none byzantine and one offline, over two heights with views zero through three, so the online honest set is exactly a quorum of three. It confirms that after stabilization the two heights finalize in order, that each finalized block descends from the one below it, and that the offline validator is tolerated and never slashed.

## Running the check

Install a Java runtime and the TLA+ tools jar named tla2tools.jar. From this directory run the safety check with

    java -cp tla2tools.jar tlc2.TLC -deadlock -config MC_Safety.cfg QorusBFT.tla

and run the liveness check with

    java -cp tla2tools.jar tlc2.TLC -deadlock -config MC_Liveness.cfg QorusBFT.tla

The deadlock flag is set because a byzantine run may legitimately stall a height without finalizing, which is a permitted outcome for safety rather than an error, and because a finished liveness run rests in a terminal state once every height is final.

## The recorded result

Both checks were run on this machine with TLC version 2.19. The safety check explored 419,840 distinct states to a search depth of 20 and reported that no error was found, with all seven invariants holding under a byzantine leader that equivocates. The liveness check explored 3,368 distinct states to a search depth of 22 and reported that no error was found, with the temporal property holding and all seven invariants holding while one validator stayed offline. Neither run found a violation.
