# Sortition on the one time key construction

## What changed

The sampler drew its committee and leader with the module lattice random
function on the beacon and the validator key. A module lattice signature is not
unique, a signature made with a different randomizer over the same key and input
verifies equally and gives a different output, and a verifier cannot tell them
apart from the encoding, so the draw was grindable. The sampler now draws with
the one time key construction of SPEC-sortition-onetime.md, which removes the re
sign entirely by making the output a deterministic hash of a committed value.

## The mechanism

Each staking account commits, at registration and bonded to its stake, the
Merkle root of a tree of one time preimages, one leaf per slot. The root is the
account identity in the stake registry. For slot N the account output is the
hash, over SHA3 and SHAKE from the crypto crate, of its preimage at position N
and the beacon of slot N. The preimage is derived with SHAKE256, the tree leaves
and nodes are hashed with SHA3-256, each under its own domain tag. The credential
the account presents is that preimage with its Merkle path to the registered
root. The account is a committee member when the output falls below a stake
weighted threshold, the same threshold as before.

Verification accepts the credential only when the revealed preimage sits at
position N in the account registered root, the Merkle path checks, and the
recomputed output falls below the threshold. A preimage at another position, or
against any root that is not the account registered one, is rejected.

## The budget as a number

The output for a slot is a deterministic hash of one fixed preimage and the
beacon, so there is no randomizer to vary and nothing to re roll. The preimage
for slot N is fixed by position and the whole tree is committed before the beacon
of any of its slots is known. So the account has exactly one valid draw per slot.
The grinding budget is one draw per bonded account per slot, and the cost of a
second draw is a second full stake bond at slashing risk.

This is pinned by the conformance vectors in tests/budget_of_one.rs. A second
draw revealed for one slot from one account is rejected, a preimage used out of
its position is rejected, and a draw against a root not in the registry is
rejected. The committed leaf is shown to be the only preimage that authenticates
at a slot position, so the budget of one is a tested fact and not an assertion.

## Leadership is stake neutral by construction

Committee membership is stake neutral under splitting because the threshold
scales with stake. Leadership is the one soft spot the design names, more
accounts give more chances at a winning output, so the leader rule is made stake
neutral rather than assumed to be. The leader score is the sub weight exponential
race, s equals minus the natural log of the normalized output over the stake
weight, and the lowest score leads. The score is an exponential random variable
with rate equal to the weight, and the minimum of independent exponentials has
rate equal to the sum of their rates, so a stake held as one account and the same
stake split into many accounts have the same lowest score distribution. Splitting
cannot raise the leadership chance, and this is a theorem rather than a property
measured at a few split sizes.

The conformance vector in tests/leadership.rs confirms the proven property end to
end. Holding stake as one account and split across ten and forty accounts each
lead near the stake share and splitting does not raise the measured probability.
The same vector shows the naive lowest output rule, with no weighting, is beaten
by splitting, which is why the weighting is there.

## The attributable faults are provable

Two draws revealed for one slot from one account, and a preimage used out of its
position, leave evidence any node checks from the account registered root alone.
The evidence types and the checks are in evidence.rs, and the vectors in
tests/faults.rs exercise them. An honest account triggers neither. The slash, a
full burn of the bond and a permanent ban, is applied by the consensus and
economics layer, here the fault is made provable.

## Frozen decisions held

Only native stake weights the draw, a bridged holding weighs zero, and a prover
is never selected. The same beacon and roots give the same committee and the same
leader. The construction is hash based over SHA3 and SHAKE from the single crypto
crate, with no other cryptographic dependency.

## The residual, stated plainly

An account can draw its one output for a slot, see that it is unfavourable, and
reveal nothing. This is invisible and unpunishable, but it forfeits a seat the
account could have taken rather than stealing one, and it does not bias the
committee toward the withholder. It is recorded as an accepted residual of the
design, not a hole to be closed.
