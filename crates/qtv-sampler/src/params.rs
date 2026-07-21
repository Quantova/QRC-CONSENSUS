pub const COMMITTEE_BUDGET: u64 = 500;

pub const MIN_SELF_STAKE: u64 = 2_000;

pub const DOMAIN_COMMITTEE: &[u8] = b"QORUS/sampler/committee";

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
