//! Sampler parameters. The committee budget is a consensus parameter that bounds
//! the target committee size, which keeps the certificate cheap for a server class
//! validator. The domain tags separate the verifiable random inputs of the two
//! draws so a committee proof can never be replayed as a leader proof.

/// Target committee size per slot, the resource budget bound on committee size.
/// The stage one core samples a committee of about this many voting validators.
/// Raised only by governance, kept here as a named constant.
pub const COMMITTEE_BUDGET: u64 = 500;

/// The minimum native self stake for an account to be eligible for the committee,
/// two thousand QTOV, the economics floor. It is load bearing for the leadership
/// neutrality proof, not only for the break even economics. The proof is exact only
/// because every account's stake fraction sits above the floating point cliff near
/// u equal to one, and the floor is what holds it there, about two to the forty two
/// above the cliff at full supply. Lowering it silently weakens the neutrality
/// proof, so it must not be lowered without re checking PROOF-leadership-neutrality.md
/// in this crate. An account below it is not eligible and is rejected from the
/// committee, which is the conformance vector in eligibility.rs.
pub const MIN_SELF_STAKE: u64 = 2_000;

/// Domain tag mixed into the verifiable random input for committee sortition.
pub const DOMAIN_COMMITTEE: &[u8] = b"QORUS/sampler/committee";

/// Domain tag mixed into the verifiable random input for leader sortition.
pub const DOMAIN_LEADER: &[u8] = b"QORUS/sampler/leader";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_distinct() {
        assert_ne!(DOMAIN_COMMITTEE, DOMAIN_LEADER);
    }

    #[test]
    fn neither_domain_prefixes_the_other() {
        assert!(!DOMAIN_COMMITTEE.starts_with(DOMAIN_LEADER));
        assert!(!DOMAIN_LEADER.starts_with(DOMAIN_COMMITTEE));
    }
}
