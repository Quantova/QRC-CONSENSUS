// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub const SLOT_MS: u64 = 150;

pub const VALIDATOR_RESOURCE_BUDGET: u64 = 1;

pub const VALIDATOR_STAKE_QTOV: u64 = 2_000;

pub const MIN_HEIGHT: u64 = 1;

pub fn supermajority(committee_size: usize) -> usize {
    2 * committee_size / 3 + 1
}

pub fn is_quorum(attesters: usize, committee_size: usize) -> bool {
    attesters * 3 > 2 * committee_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_matches_two_thirds_plus_one() {
        assert_eq!(supermajority(4), 3);
        assert_eq!(supermajority(7), 5);
        assert_eq!(supermajority(500), 334);
    }

    #[test]
    fn is_quorum_agrees_with_threshold() {
        for size in [4usize, 7, 10, 100, 500] {
            let t = supermajority(size);
            assert!(is_quorum(t, size));
            assert!(!is_quorum(t - 1, size));
        }
    }
}
