# QRC-CONSENSUS

QRC-CONSENSUS is QORUS, the consensus of Quantova, a sovereign post quantum Layer 1 built from scratch with no classical escape hatch anywhere. It is a committee based byzantine fault tolerant protocol that finalizes one block per height with a supermajority of post quantum attestations. Its committees are drawn by a grinding resistant, stake weighted, one time sortition, and its finality certificate is a set of ML-DSA signatures a light client can check from public inputs alone. The one cryptographic dependency is Q-Crypto.

## What it is

Deterministic BFT finality. A block at a height is final when more than two thirds of the sampled committee attests to it, and once final it never reverts. The protocol is one block per height with a single propose, vote, and finalize flow, and views drive leader rotation under partial synchrony rather than a separate prepare and commit ladder. Every attestation is a real ML-DSA-65 signature, and every hash is SHA-3 or SHAKE from the single crypto crate. There is no elliptic curve and no classical signature anywhere in the path.

## The crates

- **qtv-bft** is the stage one BFT core, a deterministic state machine whose transitions mirror the formal model action for action. A committee decides one block per height. The leader for a height and view is a deterministic rotation over the committee, an honest member attests with a signature and never signs two blocks at one height, and a certificate forms only when distinct verified attesters clear the two thirds plus one quorum. Equivocation, one signer over two blocks at one height, is detected and exposed as a slashable set, while an offline validator simply never attests and is never slashed. The economic burn and ban are applied by the chain, not here.
- **qtv-sampler** draws the committee and the leader. Each bonded account commits, at registration and bound to its stake, the Merkle root of a tree of one time preimages, one leaf per slot. A draw for a slot is a deterministic SHAKE256 hash of the committed preimage, the beacon seed, and the slot, with no randomizer, so there is exactly one valid draw per account per slot and a second draw costs a second full bond at slashing risk. Selection is stake weighted against a committee budget, the target committee size, so the expected committee size tracks the budget rather than the validator count. The beacon is a hash of the previous committee's revealed one time preimages, each preimage fixed by the revealer's committed tree, so no block a proposer chooses ever enters the seed and no single validator can steer the draw. The one residual is a committee member that withholds its reveal, which moves the seed by at most one bit per seat it controls and stays bounded below the byzantine threshold, and closing it fully would need a verifiable delay function the sub second finality budget rules out. Leadership is a stake neutral exponential race, proven neutral under stake splitting rather than measured, and two attributable faults, a reused leaf position and a double draw, are provable from the committed root alone.
- **qtv-attest** is the attestation and finality certificate layer a light client verifies. An attestation binds the height, the slot, the full block, the sampler membership credential, and an ML-DSA signature, so the same key must both prove its sortition entitlement and sign. Aggregation admits a signature only when it matches the subject, comes from a committee member, verifies, and is entitled, and forms a certificate when distinct signers clear quorum. Verification runs from public inputs with a closed set of typed rejection reasons.
- **qtv-sim** is a deterministic multi round simulator with the cryptography abstracted away, a bitmap of voters and a fault mode per validator, used to exercise the round structure and the fault handling in isolation from the signing cost.

## Formal model

The stage one core has a machine checked TLA+ specification under `formal/`. `QorusBFT.tla` sets the quorum at more than two thirds and assumes fewer than one third byzantine, and the state machine in `qtv-bft` follows it transition for transition. TLC checks agreement, that no two conflicting blocks finalize at one height, along with validity, chain descent, that only byzantine validators are slashed, that offline validators are never slashed, and a temporal liveness property, that a stabilized network finalizes. The recorded safety run explored 419,840 distinct states to depth 20 under an equivocating byzantine leader with every invariant holding, and the liveness run explored 3,368 states with the temporal property holding.

## Finality is flat in the validator count

Because the committee is a budget bounded sortition sample rather than the whole validator set, the work to finalize a block does not grow as validators join. The sampler tests assert this directly. A set grown a thousandfold, from five hundred to five hundred thousand accounts, finalizes with the same size committee, and a ten thousand account draw against a budget stays close to the budget and well below a tenth of the set. The finality benchmark sweeps committee sizes and shows aggregate and verify cost bounded by the budget, so the worst case finality cost is the budget row at any validator count.

A hash based folding certificate lives in `qtv-attest` as `fold.rs`, an experiment in shrinking the certificate by re folding a root derived sample of the committee rather than carrying every signature. It is implemented and tested but it is not on the finality path. The finality certificate that the chain checks today carries the signatures directly, which trades bandwidth for full soundness on purpose. Moving finality onto the folding certificate is a deliberate protocol decision that has not been taken.

## Cryptography and dependencies

The only cryptographic dependency is `qtv-crypto` from Q-Crypto, pinned by git tag, and the crates use its ML-DSA signatures and its SHA-3 and SHAKE functions and nothing else. `deny.toml` bans classical cryptography from the whole dependency tree and restricts git sources to the Quantova organization. There is no STARK prover in the build. An earlier stage two STARK certificate was removed in favor of the single signature certificate, and the `NOTES-stage-two.md` file records that removed design for history.

## Build and test

```
cargo test
cargo run --release --example finality_bench -p qtv-attest
cargo deny check
```

The suites cover safety, liveness, offline tolerance, attestation, and determinism in the core, the budget, the budget of one draw, scaling, leadership and its neutrality proof, eligibility, exclusion, and the attributable faults in the sampler, and membership, rejection, and conformance against the old grindable draw in the attestation layer. The formal model checks with TLC against the committed configurations under `formal/`.

## Where it sits in the stack

QORUS is a consensus library. Quantova-Chain composes qtv-bft, qtv-sampler, and qtv-attest into its node, pinned by git tag, and supplies the networking, the state, and the economics that this repository defers to the chain. The signatures and hashes come from Q-Crypto.

## Status

At testnet. The stage one core, the one time sortition sampler, and the single signature finality certificate are complete and wired into the chain. The folding certificate is an unintegrated experiment, and the removed STARK stage is history.

## License

Dual licensed under Apache 2.0 and MIT. See `LICENSE-APACHE` and `LICENSE-MIT`.
