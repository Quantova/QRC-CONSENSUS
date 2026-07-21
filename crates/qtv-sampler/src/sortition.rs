use qtv_crypto::sha3::shake256;

use crate::beacon::Beacon;
use crate::onetime::{MerklePath, Root, PREIMAGE_BYTES};

pub const OUTPUT_BYTES: usize = 32;

const VALUE_SPACE: u128 = 1u128 << 64;

pub fn output_value(output: &[u8; OUTPUT_BYTES]) -> u64 {
    let mut head = [0u8; 8];
    head.copy_from_slice(&output[..8]);
    u64::from_be_bytes(head)
}

pub fn sortition_output(
    preimage: &[u8; PREIMAGE_BYTES],
    beacon: &Beacon,
    domain: &[u8],
    slot: u64,
) -> [u8; OUTPUT_BYTES] {
    let mut buf = Vec::with_capacity(domain.len() + PREIMAGE_BYTES + beacon.seed().len() + 8);
    buf.extend_from_slice(domain);
    buf.extend_from_slice(preimage);
    buf.extend_from_slice(beacon.seed());
    buf.extend_from_slice(&slot.to_le_bytes());
    let mut out = [0u8; OUTPUT_BYTES];
    shake256(&buf, &mut out);
    out
}

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

pub fn is_selected(value: u64, weight: u64, total: u64, budget: u64) -> bool {
    u128::from(value) < threshold(weight, total, budget)
}

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

pub fn expected_committee_size(weights: &[u64], budget: u64) -> f64 {
    let total: u64 = weights.iter().sum();
    weights
        .iter()
        .map(|&w| selection_probability(w, total, budget))
        .sum()
}

fn output_unit_interval(output: &[u8; OUTPUT_BYTES]) -> f64 {
    let mut u = 0.0f64;
    for &b in output.iter().rev() {
        u = (u + b as f64) / 256.0;
    }
    if u <= 0.0 {
        u = f64::from_bits(1);
    }
    u
}

pub fn leader_score(output: &[u8; OUTPUT_BYTES], weight: u64) -> f64 {
    if weight == 0 {
        return f64::INFINITY;
    }
    -output_unit_interval(output).ln() / (weight as f64)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub position: u64,
    pub preimage: [u8; PREIMAGE_BYTES],
    pub path: MerklePath,
}

impl Credential {
    pub fn output(&self, beacon: &Beacon, domain: &[u8], slot: u64) -> [u8; OUTPUT_BYTES] {
        sortition_output(&self.preimage, beacon, domain, slot)
    }

    pub fn value(&self, beacon: &Beacon, domain: &[u8], slot: u64) -> u64 {
        output_value(&self.output(beacon, domain, slot))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(8 + PREIMAGE_BYTES + self.path.siblings.len() * PREIMAGE_BYTES);
        buf.extend_from_slice(&self.position.to_le_bytes());
        buf.extend_from_slice(&self.preimage);
        for sib in &self.path.siblings {
            buf.extend_from_slice(sib);
        }
        buf
    }
}

pub fn verify_membership(root: &Root, slot: u64, credential: &Credential) -> bool {
    credential.position == slot
        && root.verify_membership(credential.position, &credential.preimage, &credential.path)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_selection(
    root: &Root,
    beacon: &Beacon,
    domain: &[u8],
    slot: u64,
    weight: u64,
    total: u64,
    budget: u64,
    credential: &Credential,
) -> bool {
    if !verify_membership(root, slot, credential) {
        return false;
    }
    let value = credential.value(beacon, domain, slot);
    is_selected(value, weight, total, budget)
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
        assert_eq!(threshold(100, 100, 1), VALUE_SPACE);
        assert!(is_selected(u64::MAX, 100, 100, 1));
    }

    #[test]
    fn threshold_grows_with_stake() {
        let a = threshold(10, 1_000, 50);
        let b = threshold(20, 1_000, 50);
        assert!(b > a);
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
        let size = expected_committee_size(&weights, 10);
        assert!((size - 3.0).abs() < 1e-9);
    }

    fn output_with_prefix(prefix: u64) -> [u8; OUTPUT_BYTES] {
        let mut out = [0u8; OUTPUT_BYTES];
        out[..8].copy_from_slice(&prefix.to_be_bytes());
        out
    }

    #[test]
    fn the_score_is_monotone_in_the_output_at_equal_weight() {
        let low = output_with_prefix(1);
        let mid = output_with_prefix(1 << 40);
        let high = output_with_prefix(u64::MAX);
        assert!(leader_score(&low, 100) > leader_score(&mid, 100));
        assert!(leader_score(&mid, 100) > leader_score(&high, 100));
    }

    #[test]
    fn a_smaller_weight_raises_the_score_for_a_fixed_output() {
        let output = output_with_prefix(12_345 << 32);
        let big = leader_score(&output, 2_000);
        let small = leader_score(&output, 500);
        assert!(small > big);
        assert!(big.is_finite() && big > 0.0);
        assert!((small / big - 4.0).abs() < 1e-9);
    }
}
