//! Stake weighted verifiable random sortition. A validator draws a verifiable

use qtv_crypto::vrf::{verify, OUTPUT_BYTES, PROOF_BYTES, PUBLIC_KEY_BYTES};

use crate::beacon::Beacon;
use crate::validator::SamplerValidator;

/// The size of the output value space, two to the sixty four.
const VALUE_SPACE: u128 = 1u128 << 64;

/// Interpret the leading eight bytes of an output as a value in the space
pub fn output_value(output: &[u8; OUTPUT_BYTES]) -> u64 {
    let mut head = [0u8; 8];
    head.copy_from_slice(&output[..8]);
    u64::from_be_bytes(head)
}

/// The selection threshold in the output value space for a validator of `weight`
pub fn threshold(weight: u64, total: u64, budget: u64) -> u128 {
    if total == 0 || weight == 0 {
        return 0;
    }
    let num = (budget as u128) * (weight as u128);
    let denom = total as u128;
    if num >= denom {
        return VALUE_SPACE;
    }
    num * VALUE_SPACE / denom
}

/// True when an output value selects a validator of the given weight.
pub fn is_selected(value: u64, weight: u64, total: u64, budget: u64) -> bool {
    u128::from(value) < threshold(weight, total, budget)
}

/// The selection probability of a validator, min(1, budget * weight / total).
pub fn selection_probability(weight: u64, total: u64, budget: u64) -> f64 {
    if total == 0 || weight == 0 {
        return 0.0;
    }
    let p = budget as f64 * weight as f64 / total as f64;
    if p > 1.0 {
        1.0
    } else {
        p
    }
}

/// The expected committee size for a set of native weights under the budget,
pub fn expected_committee_size(weights: &[u64], budget: u64) -> f64 {
    let total: u64 = weights.iter().sum();
    weights
        .iter()
        .map(|&w| selection_probability(w, total, budget))
        .sum()
}

/// A sortition draw: a verifiable random output and its proof for one beacon
#[derive(Clone)]
pub struct Draw {
    pub output: [u8; OUTPUT_BYTES],
    pub proof: [u8; PROOF_BYTES],
}

impl Draw {
    /// The output value this draw is scored by.
    pub fn value(&self) -> u64 {
        output_value(&self.output)
    }
}

/// Evaluate the sortition draw for a validator over the beacon, under a domain
pub fn draw(validator: &SamplerValidator, beacon: &Beacon, domain: &[u8], slot: u64) -> Draw {
    let input = beacon.sortition_input(domain, slot);
    let (output, proof) = validator.evaluate(&input);
    Draw { output, proof }
}

/// Verify that a draw is a valid sortition credential for the given public key
#[allow(clippy::too_many_arguments)]
pub fn verify_selection(
    public_key: &[u8; PUBLIC_KEY_BYTES],
    beacon: &Beacon,
    domain: &[u8],
    slot: u64,
    weight: u64,
    total: u64,
    budget: u64,
    draw: &Draw,
) -> bool {
    let input = beacon.sortition_input(domain, slot);
    if !verify(public_key, &input, &draw.output, &draw.proof) {
        return false;
    }
    is_selected(draw.value(), weight, total, budget)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_weight_never_selected() {
        assert_eq!(threshold(0, 100, 10), 0);
        assert!(!is_selected(0, 0, 100, 10));
    }

    #[test]
    fn full_stake_saturates_the_space() {
        // A weight that alone meets the budget share is always selected.
        assert_eq!(threshold(100, 100, 1), VALUE_SPACE);
        assert!(is_selected(u64::MAX, 100, 100, 1));
    }

    #[test]
    fn threshold_grows_with_stake() {
        let a = threshold(10, 1_000, 50);
        let b = threshold(20, 1_000, 50);
        assert!(b > a);
        // Double the stake, double the threshold in the unsaturated range.
        assert_eq!(b, 2 * a);
    }

    #[test]
    fn expected_size_equals_budget_when_unsaturated() {
        let weights = [100u64, 100, 100, 100, 100];
        let size = expected_committee_size(&weights, 2);
        assert!((size - 2.0).abs() < 1e-9);
    }

    #[test]
    fn expected_size_never_exceeds_the_set() {
        let weights = [1u64, 1, 1];
        // A budget above the set saturates every share; the expected size is the
        // set, never more.
        let size = expected_committee_size(&weights, 10);
        assert!((size - 3.0).abs() < 1e-9);
    }
}
