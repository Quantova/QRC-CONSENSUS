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
//! The certificate is an envelope and the aggregated module lattice attestations
//! of the entitled supermajority, held in ascending signer id order. It carries
//! the signatures directly and has no succinct or proof based stage.
//!
//! The certificate is module lattice only, per the frozen consensus decision. It
//! carries no classical or non finalised cryptography, and an offline absentee
//! simply lowers the count without penalty.

pub mod aggregate;
pub mod attestation;
pub mod attester;
pub mod certificate;
pub mod committee;
pub mod fold;
pub mod params;
pub mod verify;

pub use attestation::Attestation;
pub use attester::{Attester, ValidatorId};
pub use certificate::{Certificate, Envelope};
pub use committee::{CommitteeCommitment, CommitteeDigest, MemberKey};
pub use verify::{RejectReason, Verdict};

// The block and beacon are part of this layer's public surface: an attestation
// carries a block and verification reads a beacon. Re-export them so a light
// client depends on qtv-attest alone.
pub use qtv_bft::block::{Block, Height, Parent};
pub use qtv_sampler::beacon::Beacon;
