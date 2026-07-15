# Stage two succinctness notes

## What this is

Stage one packages a finality certificate as the aggregated module lattice
attestations of the committee. At about 500 members that certificate measured
about 9.8 megabytes and about 630 milliseconds to verify, and both grow linearly
with the committee. Stage two replaces the attestation list with one small
constant proof from the prover, verified through the same light client path.

## The prover entry point

q-prover exposes a high level entry point in the qtv-stark crate, the entry
module. prove_batch takes a public single block message and the member response
coefficients, one per segment, and proves the fused certificate over them, then
returns a self contained BatchProof. verify_batch checks that BatchProof against
the same message. The responses are witness and never reach the verifier. The
codec module serializes a proof to bytes and reads it back, so the proof travels
as the opaque body of a certificate. A caller wires neither the arithmetization
nor the proof protocol by hand. The prover is pinned by tag v0.8.0.

## The seam wiring

qtv-attest gains a succinct module. prove_stage_two folds the committee
attestation set into a 32 byte digest, builds the decision preimage, decodes the
member response coefficients from the real committee signatures, calls prove_batch
with the preimage and those responses, and returns a stage two Certificate over
the same envelope as the stage one certificate. ProverVerifier implements the
SuccinctVerifier trait
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
- In circuit, the per coefficient module lattice verify arithmetic was carried
  out over the coefficients the hash produces. This is the canonical reduction
  into the signature modulus, the transform domain matrix vector product of the
  coefficient with the member response, the response infinity norm over that
  response, the commitment decomposition, and the hint recovery, fused so the
  hashing and the arithmetic cannot be split. On each squeeze row a gated equality
  pins the reduction input to the squeeze word, and one permutation binds the
  reduced coefficient to the decomposition input, the hint recovery input, and the
  first factor of the matrix vector product, so the same hash derived value flows
  through all three. A further permutation binds the product's second factor to
  the coefficient the norm band bounds. The chain, hash to matrix coefficient to
  product to response to norm, is unsplittable. A prover cannot multiply a matrix
  coefficient other than the hash output, nor bound a response other than the one
  the product used.
- The responses the norm and the matrix vector product bands consume are decoded
  from the real committee signatures, so the fused relation runs over genuine
  signature witness. The norm band admits only responses inside the ML DSA 65
  response bound, so an out of bound response has no satisfying trace.
- The count the certificate claims is a supermajority of the committee.

## What the proof does not bind yet

This is the honest gap. The certificate does not by itself prove that a
supermajority of entitled members produced valid module lattice signatures over
the block. What is now fused is the per coefficient verify arithmetic, including
the matrix vector product and the response norm, bound unsplittably to the hash.
What remains is the reconstruction that ties those coefficients to each specific
member and closes the whole equation.

- The hash derived coefficient the arithmetic consumes is not reconstructed in
  circuit to each member's expanded matrix, decoded response, and public key t1.
  The matrix vector product multiplies the hash derived coefficient by a witness
  response, and the norm bounds that response, but the certificate does not prove
  the coefficient is the member's ExpandA matrix entry nor that the response is the
  one paired with it in the member's own signature. That identification still rests
  on the attestation set digest, a hash the aggregator supplies.
- The full verify equation closure, w equals A z minus c t1 times two to the d
  followed by UseHint and the challenge hash recompute, is not carried across all
  two hundred fifty six coefficients and every member in one trace. The ExpandA
  rejection sampling to transform chain, the SampleInBall challenge placement, and
  the multi block absorb of the full attestation transcript stay arithmetized in
  the prover sample, ntt, challenge ball, and sponge modules but are not fused into
  this certificate. The challenge's transform domain pointwise product uses the
  same fused modular multiply gadget. Its time domain SampleInBall placement is
  the piece named here as arithmetized and not fused.
- Because the count and the attestation set digest are supplied by the aggregator
  and not reconstructed by the light client from the signatures, a stage two
  certificate is not yet a full security replacement for a stage one certificate.
  Stage one still checks every signature. Stage two now binds a real constant size
  proof over a larger faithful subset of the relation, the hashing fused with the
  matrix vector product, the response norm, the reduction, the decomposition, and
  the hint recovery over real response witness, and the remaining binding is the
  reconstruction work above.

## Measured

The stage two figures below are measured directly by the stage_two benchmark in
the qtv-attest crate, run with cargo bench on a real Apple Silicon host in the
release profile. The proving and the verifying are real. The certificate size and
the verify time do not depend on the committee size, so the benchmark produces one
certificate over a small committee and measures it directly. Verify time is the
mean of twenty runs of the light client path, which rebuilds the decision preimage,
reconstructs the certificate description, and checks the proof.

Measured stage two certificate at 16 segments, with the matrix vector product and
the response norm bands fused over real committee response witness.

- size 2749240 bytes, about 2.75 megabytes.
- verify about 82 milliseconds, the mean of twenty light client runs.
- prove about 31 seconds, the one time prover cost, not on the light client path.

The size grew about 97 kilobytes, about 3.7 percent, from the 2651960 bytes before
the matrix vector product and the norm bands were added. The byte count is host
independent, so this delta is the exact cost of the fusion. The verify figure is
measured fresh on this host and is dominated by the FRI low degree test and the
Merkle path checks, whose query count and path depth do not change with the added
bands, so the fusion adds only a few percent to the verify cost. The figure is not
comparable to the earlier session's 127 millisecond host measurement and the
change from it is not attributed to the fusion.

The stage one certificate at 500 members is the given baseline of about 9.8
megabytes and about 630 milliseconds, both growing linearly with the committee. It
is not re measured here. Against that baseline the measured stage two certificate
is about 28 percent of the size and verifies in about an eighth of the time, and
unlike stage one neither figure grows with the committee, so the gap widens as the
committee grows. On the finality path this replaces the stage one certificate
verification of about 630 milliseconds with a constant 82 milliseconds, and, since
dissemination is bandwidth bound and linear in the byte count, cuts the on the
wire certificate from 9.8 megabytes to a constant 2.75 megabytes, about a 72
percent smaller payload to disseminate.
