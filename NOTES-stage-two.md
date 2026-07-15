# Stage two succinctness notes

## What this is

Stage one packages a finality certificate as the aggregated module lattice
attestations of the committee. At about 500 members that certificate measured
about 9.8 megabytes and about 630 milliseconds to verify, and both grow linearly
with the committee. Stage two replaces the attestation list with one small
constant proof from the prover, verified through the same light client path.

## The prover entry point

q-prover exposes a high level entry point in the qtv-stark crate, the entry
module. prove_batch takes a public single block message and proves the fused
certificate over it, then returns a self contained BatchProof. verify_batch
checks that BatchProof against the same message. The codec module serializes a
proof to bytes and reads it back, so the proof travels as the opaque body of a
certificate. A caller wires neither the arithmetization nor the proof protocol by
hand. The prover is pinned by tag v0.7.0.

## The seam wiring

qtv-attest gains a succinct module. prove_stage_two folds the committee
attestation set into a 32 byte digest, builds the decision preimage, calls
prove_batch, and returns a stage two Certificate over the same envelope as the
stage one certificate. ProverVerifier implements the SuccinctVerifier trait
already defined in the certificate module. A light client calls
Certificate.verify_with, which checks the envelope committee digest against the
commitment and then hands the body to ProverVerifier. ProverVerifier rebuilds the
decision preimage from the public envelope, the committee commitment digest, and
the count and set digest carried in the body, checks the prover certificate, and
requires the count to be a supermajority of the committee.

## The decision preimage

The message the fused certificate hashes is a single block preimage that binds

- the height and the slot from the envelope,
- a digest of the block bytes,
- the committee commitment digest,
- the supermajority count,
- a digest of the committee attestation set.

The preimage is 132 bytes and fits one SHAKE256 rate block, which is why the
fused certificate absorbs it in a single block.

## What the proof binds

The stage two certificate is one real hash based STARK proof. Verified through the
light client path it establishes the following.

- The proof is a valid fused certificate over the exact preimage that binds this
  decision. A light client rebuilds that preimage from the parts it holds, the
  envelope and the committee commitment, so a proof made for a different block, a
  different committee, or a different count is rejected.
- In circuit, SHAKE256 of the preimage was computed with the genuine FIPS 202
  permutation. The prover sponge matches the crypto crate on known inputs.
- In circuit, the per coefficient module lattice arithmetic was carried out over
  the coefficients the hash produces. This is the canonical reduction into the
  signature modulus, the commitment decomposition, and the hint recovery, fused
  so the hashing and the arithmetic cannot be split.
- The count the certificate claims is a supermajority of the committee.

## What the proof does not bind yet

This is the honest gap. The certificate does not by itself prove that a
supermajority of entitled members produced valid module lattice signatures over
the block.

- The attestation set digest binds the real signatures only as a hash the
  aggregator supplies. The SHAKE256 of the full multi block attestation transcript
  is not re derived in circuit. The fused certificate absorbs a single rate block.
  The multi block absorb is arithmetized in the prover sponge module but is not
  yet fused with the arithmetic band.
- The per signature verify equation over each member key, the transform domain
  matrix vector product, the challenge ball sampling, and the response norm over
  the real response, is arithmetized in the prover lattice, norm, sample, and
  challenge ball modules but is not yet wired to per member witness data nor fused
  into this certificate.
- Because the count and the attestation set digest are supplied by the aggregator
  and not reconstructed by the light client from the signatures, a stage two
  certificate is not yet a security replacement for a stage one certificate. Stage
  one still checks every signature. Stage two wires the seam with a real constant
  size proof over a faithful subset of the relation, and the remaining binding is
  the work above.

## Measured

The stage two figures below are measured directly by the stage_two benchmark in
the qtv-attest crate, run with cargo bench on a real Apple Silicon host in the
release profile. The proving and the verifying are real. The certificate size and
the verify time do not depend on the committee size, so the benchmark produces one
certificate over a small committee and measures it directly. Verify time is the
mean of twenty runs of the light client path, which rebuilds the decision preimage,
reconstructs the certificate description, and checks the proof.

Measured stage two certificate at 16 segments.

- size 2651960 bytes, about 2.65 megabytes.
- verify about 127 milliseconds.
- prove about 41 seconds, the one time prover cost, not on the light client path.

The stage one certificate at 500 members is the given baseline of about 9.8
megabytes and about 630 milliseconds, both growing linearly with the committee. It
is not re measured here. Against that baseline the measured stage two certificate
is about a quarter of the size and verifies in about a fifth of the time, and
unlike stage one neither figure grows with the committee, so the gap widens as the
committee grows.
