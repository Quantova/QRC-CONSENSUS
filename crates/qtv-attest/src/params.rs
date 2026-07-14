//! Certificate parameters. The supermajority rule is reused from the stage one

pub use qtv_bft::params::{is_quorum, supermajority};
pub use qtv_sampler::params::{COMMITTEE_BUDGET, DOMAIN_COMMITTEE};

/// Domain separation context for a canonical certificate attestation signature.
pub const ATTEST_CONTEXT: &[u8] = b"QORUS-ATTEST-CERT";
