//! Certificate parameters. The supermajority rule is reused from the stage one
//! core so the finality certificate and the core agree on the quorum, and the
//! committee sortition domain and budget are reused from the sampler so an
//! entitlement proof is checked under the same tag it was drawn with.

pub use qtv_bft::params::{is_quorum, supermajority};
pub use qtv_sampler::params::{COMMITTEE_BUDGET, DOMAIN_COMMITTEE};

/// Domain separation context for a canonical certificate attestation signature.
/// It differs from the stage one core attestation context, so a core vote and a
/// certificate attestation can never be mistaken for one another.
pub const ATTEST_CONTEXT: &[u8] = b"QORUS-ATTEST-CERT";
