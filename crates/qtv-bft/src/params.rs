//! Consensus parameters for the stage one core. These are named constants, not

/// Logical duration of a slot in milliseconds. One block is proposed per slot.
pub const SLOT_MS: u64 = 150;

/// The validator resource budget. A block whose cost exceeds this bound is
pub const VALIDATOR_RESOURCE_BUDGET: u64 = 1;

/// Stake required to run a validator, in QTOV.
pub const VALIDATOR_STAKE_QTOV: u64 = 2_000;

/// Unbonding period in days.
pub const UNBONDING_DAYS: u64 = 14;

/// The first height. Its block descends from Genesis. Mirrors MinHeight.
pub const MIN_HEIGHT: u64 = 1;

/// The supermajority threshold: two thirds of the committee plus one. A set of
pub fn supermajority(committee_size: usize) -> usize {
    2 * committee_size / 3 + 1
}

/// True when the given number of distinct attesters forms a quorum.
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
