# Sortition on the ML DSA random function

## What changed

The sampler sortition drew its committee and leader credentials with the hash
based verifiable random function on SLH DSA. It now draws them with the lattice
based verifiable random function on ML DSA, qtv_crypto::vrf_mldsa, on the same
interface. The draw and the verify both use it. Committee membership, proposer
eligibility, and the checks a node runs against a public key all move to the ML
DSA construction. The beacon and the stake weighted threshold are unchanged.

## Derandomized signing is the rule in the sortition path

The draw signs only with the derandomized function, the all zero randomizer of
FIPS 204. The proving path in qtv_crypto::vrf_mldsa exposes no way to pass a
caller chosen randomizer, so the sampler cannot hedge a draw. The same key and
the same input therefore produce one signature, one proof, and one output. This
is what makes a draw a fixed function of the key and the input, and it is why a
validator cannot sign the same input many times under different randomizers and
keep the lowest output, which would be grinding.

The conformance vector in crates/qtv-sampler/tests/sortition_conformance.rs pins
both halves of this. It pins that a draw is deterministic for a fixed key and
input, and it pins that the same key and input signed with a different randomizer
gives a different sortition output. The second half is the honest demonstration
of why derandomization is the rule.

## The deferred boundary, stated plainly

A light client cannot yet reject a hedged signature at verification. A signature
made with any randomizer, the all zero one or another, verifies as a valid ML DSA
signature over the input. Verification checks that the signature is valid and that
the output is the SHAKE256 digest of that signature. It does not and cannot see
which randomizer produced the signature, so it accepts a hedged signature the same
as a derandomized one. The sortition path enforces derandomization at signing
time by construction, but a verifier on its own cannot prove that the signature it
was handed is the derandomized one.

Grinding resistance that a verifier can check therefore needs the derivation
proof, a proof that the signature is the derandomized signature for this key and
input. That proof is the STARK wrapper the vrf specification describes for this
construction, and it is deferred. Until it ships, grinding resistance in the
sortition rests on the derandomized signing rule in the honest node and on the
beacon deriving from the aggregated certificate rather than any single validator,
not on a verifier rejecting a hedged signature.

## Why this is not a regression

The SLH DSA construction that the sortition used before had the same gap. Its
verification also accepted a valid signature without proving which additional
randomness produced it, so a light client could not reject a hedged SLH DSA
signature either. Moving to ML DSA carries the same open boundary forward and
adds nothing new to it. The switch is a change of the underlying signature and a
faster draw, and it leaves the grinding resistance argument exactly where it was.

We do not claim that the verifier rejects a hedged signature. We claim that the
sortition signs only with the derandomized function and that the verifiable check
a light client can run is deferred to the derivation proof.
