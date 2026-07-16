//! Sampler parameters. The committee budget is a consensus parameter that bounds

/// Target committee size per slot, the resource budget bound on committee size.
pub const COMMITTEE_BUDGET: u64 = 500;

/// The minimum native self stake for an account to be eligible for the committee,
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
