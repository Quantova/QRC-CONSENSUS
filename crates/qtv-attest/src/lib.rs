//! qtv-attest is the QORUS attestation and finality certificate layer. It ties
//! the stage one core, the committee sampler, and the module lattice signatures
//! into the single certificate a light client verifies, following
//! SPEC-consensus-qorus.md.
//!
//! A canonical attestation binds a height, a slot, a block, the sampler
//! membership proof, and a module lattice signature. An attestation counts only
//! when the same key both proved committee entitlement through the sampler and
//! signed the block with ML-DSA. A supermajority of entitled attestations for a
//! height aggregates into one certificate.
//!
//! The certificate is a wrapper with a staged body over a shared envelope. A
//! stage one body carries the aggregated module lattice attestations. A stage
//! two body carries a single succinct proof in their place, behind a typed seam
//! the prover fills once recursive succinctness activates. Both bodies share the
//! same envelope, height, block, and committee commitment. Governance tallies
//! travel this same wrapper, carried as a succinct body over their own subject.
//!
//! The certificate is module lattice only, per the frozen consensus decision. A
//! prover holds no vote and contributes nothing, and an offline absentee simply
//! lowers the count without penalty.

pub mod aggregate;
pub mod attestation;
pub mod attester;
pub mod certificate;
pub mod committee;
pub mod params;
pub mod succinct;
pub mod verify;

pub use attestation::Attestation;
pub use attester::{Attester, ValidatorId};
pub use certificate::{
    Body, Certificate, Envelope, Stage, Stage1Body, Stage2Body, SuccinctProof, SuccinctVerifier,
};
pub use committee::{CommitteeCommitment, CommitteeDigest, MemberKey};
pub use succinct::{prove_stage_two, ProverVerifier};
pub use verify::{RejectReason, Verdict};

// The block and beacon are part of this layer's public surface: an attestation
// carries a block and verification reads a beacon. Re-export them so a light
// client depends on qtv-attest alone.
pub use qtv_bft::block::{Block, Height, Parent};
pub use qtv_sampler::beacon::Beacon;
