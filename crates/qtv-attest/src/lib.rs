//! qtv-attest is the QORUS attestation and finality certificate layer. It ties

pub mod aggregate;
pub mod attestation;
pub mod attester;
pub mod certificate;
pub mod committee;
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
