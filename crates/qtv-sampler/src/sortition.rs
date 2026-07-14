//! Stake weighted verifiable random sortition. A validator draws a verifiable
//! random output over a beacon input with its own key. The output is a value in
//! a fixed space, and the validator is selected when that value falls below a
//! threshold set by its native stake. The selection probability is therefore
//! min(1, budget * weight / total), proportional to stake until it saturates at
//! the whole space, so more stake means a proportionally higher chance of
//! selection, bounded by the committee budget.
//!
//! The threshold is a pure function of public stake, so any node recomputes it
//! and rechecks the output and proof against the public key. A validator whose
//! output is not below its threshold has no passing proof, and because the
//! verifiable random function is deterministic and unforgeable it cannot grind a
//! lower output. A prover and a bridged holding both weigh zero, so their
//! threshold is zero and they are never selected.

use qtv_crypto::vrf::{verify, OUTPUT_BYTES, PROOF_BYTES, PUBLIC_KEY_BYTES};

use crate::beacon::Beacon;
use crate::validator::SamplerValidator;

/// The size of the output value space, two to the sixty four.
const VALUE_SPACE: u128 = 1u128 << 64;

/// Interpret the leading eight bytes of an output as a value in the space
/// [0, 2^64). The full output still binds the proof; this is the projection the
/// threshold compares against.
pub fn output_value(output: &[u8; OUTPUT_BYTES]) -> u64 {
    let mut head = [0u8; 8];
    head.copy_from_slice(&output[..8]);
    u64::from_be_bytes(head)
}

/// The selection threshold in the output value space for a validator of `weight`
/// out of `total` native weight, given the committee `budget`. A validator is a
/// member when its output value is below this threshold. The value equals
/// min(1, budget * weight / total) scaled to the space, so it saturates at the
/// whole space when a stake is large enough to be selected with certainty.
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
/// The expected committee size is the sum of these over the validator set.
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
/// the sum of the per validator selection probabilities. When no stake saturates
/// its threshold this equals the budget exactly, which is how the budget bounds
/// the committee size.
pub fn expected_committee_size(weights: &[u64], budget: u64) -> f64 {
    let total: u64 = weights.iter().sum();
    weights
        .iter()
        .map(|&w| selection_probability(w, total, budget))
        .sum()
}

/// A sortition draw: a verifiable random output and its proof for one beacon
/// input. It is the credential a validator presents for committee membership or
/// proposer eligibility, and any node rechecks it without the secret key.
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
/// tag and slot. Deterministic in the key and the input.
pub fn draw(validator: &SamplerValidator, beacon: &Beacon, domain: &[u8], slot: u64) -> Draw {
    let input = beacon.sortition_input(domain, slot);
    let (output, proof) = validator.evaluate(&input);
    Draw { output, proof }
}

/// Verify that a draw is a valid sortition credential for the given public key
/// over the beacon, domain, and slot: the proof must check against the key and
/// the output, and the output must place the validator below its stake weighted
/// threshold. Returns false for a draw that does not verify or a validator whose
/// output is not below threshold, including any zero weight participant.
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
