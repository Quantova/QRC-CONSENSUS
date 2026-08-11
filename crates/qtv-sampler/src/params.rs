// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub const COMMITTEE_BUDGET: u64 = 500;

pub const MIN_SELF_STAKE: u64 = 2_000;

pub const ADVERSARY_STAKE_NUM: u64 = 1;

pub const ADVERSARY_STAKE_DEN: u64 = 3;

pub const DOMAIN_COMMITTEE: &[u8] = b"QORUS/sampler/committee";

pub const DOMAIN_LEADER: &[u8] = b"QORUS/sampler/leader";

pub fn finality_threshold(expected_committee: u64) -> u64 {
    let honest_num = ADVERSARY_STAKE_DEN - ADVERSARY_STAKE_NUM;
    expected_committee * honest_num / ADVERSARY_STAKE_DEN + 1
}

pub fn finality_threshold_for_draw(expected_committee: u64, realized_committee: u64) -> u64 {
    finality_threshold(expected_committee.max(realized_committee))
}

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

    #[test]
    fn the_threshold_is_a_two_thirds_supermajority_of_the_expected_committee() {
        assert_eq!(finality_threshold(4), 3);
        assert_eq!(finality_threshold(7), 5);
        assert_eq!(finality_threshold(12), 9);
        assert_eq!(finality_threshold(500), 334);
    }

    #[test]
    fn two_agreeing_thresholds_overlap_in_more_than_the_adversary_can_hold() {
        let e = COMMITTEE_BUDGET;
        let tau = finality_threshold(e);
        let adversary_seats = e * ADVERSARY_STAKE_NUM / ADVERSARY_STAKE_DEN;
        let honest_seats = e - adversary_seats;
        assert!(adversary_seats < tau, "the adversary alone must fall below the threshold");
        assert!(
            2 * tau - e > adversary_seats,
            "two agreeing sets share more seats than the adversary can hold, so both cannot reach the threshold"
        );
        assert!(tau <= honest_seats, "the honest set must be able to reach the threshold");
    }
}
