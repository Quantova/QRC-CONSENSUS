// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::sha3::shake256;

use q_vrf::PublicKey;

use crate::beacon::{Beacon, SEED_BYTES};
use crate::onetime::{MerklePath, Root, PREIMAGE_BYTES};

pub const OUTPUT_BYTES: usize = 32;

const VALUE_SPACE: u128 = 1u128 << 64;

pub fn output_value(output: &[u8; OUTPUT_BYTES]) -> u64 {
    let mut head = [0u8; 8];
    head.copy_from_slice(&output[..8]);
    u64::from_be_bytes(head)
}

const INLINE_DOMAIN: usize = 32;

pub fn sortition_output(
    preimage: &[u8; PREIMAGE_BYTES],
    beacon: &Beacon,
    domain: &[u8],
    slot: u64,
) -> [u8; OUTPUT_BYTES] {
    let mut out = [0u8; OUTPUT_BYTES];
    if domain.len() <= INLINE_DOMAIN {
        let mut buf = [0u8; INLINE_DOMAIN + PREIMAGE_BYTES + SEED_BYTES + 8];
        let mut n = domain.len();
        buf[..n].copy_from_slice(domain);
        buf[n..n + PREIMAGE_BYTES].copy_from_slice(preimage);
        n += PREIMAGE_BYTES;
        buf[n..n + SEED_BYTES].copy_from_slice(beacon.seed());
        n += SEED_BYTES;
        buf[n..n + 8].copy_from_slice(&slot.to_le_bytes());
        n += 8;
        shake256(&buf[..n], &mut out);
    } else {
        let mut buf = Vec::with_capacity(domain.len() + PREIMAGE_BYTES + SEED_BYTES + 8);
        buf.extend_from_slice(domain);
        buf.extend_from_slice(preimage);
        buf.extend_from_slice(beacon.seed());
        buf.extend_from_slice(&slot.to_le_bytes());
        shake256(&buf, &mut out);
    }
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
    let total: u64 = weights.iter().copied().fold(0u64, u64::saturating_add);
    weights
        .iter()
        .map(|&w| selection_probability(w, total, budget))
        .sum()
}

pub fn expected_committee(weights: &[u64], budget: u64) -> u64 {
    let total: u128 = weights.iter().map(|&w| w as u128).fold(0u128, u128::saturating_add);
    if total == 0 {
        return 0;
    }
    let budget = budget as u128;
    let scaled: u128 = weights
        .iter()
        .map(|&w| budget.saturating_mul(w as u128).min(total))
        .fold(0u128, u128::saturating_add);
    ((scaled + total / 2) / total) as u64
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

pub const LEADER_SCORE_FRAC_BITS: u32 = 48;

pub fn leader_neg_log2(output: &[u8; OUTPUT_BYTES]) -> u128 {
    let frac = LEADER_SCORE_FRAC_BITS;
    let v = output_value(output) as u128 + 1;
    let floor_log2 = 127 - v.leading_zeros();
    let mut mantissa = if floor_log2 <= frac {
        v << (frac - floor_log2)
    } else {
        v >> (floor_log2 - frac)
    };
    let mut log2 = (floor_log2 as u128) << frac;
    for i in 0..frac {
        mantissa = (mantissa * mantissa) >> frac;
        if mantissa >= (2u128 << frac) {
            mantissa >>= 1;
            log2 |= 1u128 << (frac - 1 - i);
        }
    }
    (64u128 << frac) - log2
}

pub fn leader_prefers(
    cand_neg_log2: u128,
    cand_weight: u64,
    cand_id: u64,
    best_neg_log2: u128,
    best_weight: u64,
    best_id: u64,
) -> bool {
    let lhs = cand_neg_log2 * best_weight as u128;
    let rhs = best_neg_log2 * cand_weight as u128;
    lhs < rhs || (lhs == rhs && cand_id < best_id)
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
        && PublicKey::from_root(*root).opens(
            credential.position,
            &credential.preimage,
            &credential.path,
        )
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

    #[test]
    fn expected_committee_is_deterministic_integer_math() {
        assert_eq!(expected_committee(&vec![1_000u64; 1_000], 500), 500);
        assert_eq!(expected_committee(&[1, 1, 1], 10), 3);
        assert_eq!(expected_committee(&[100, 100, 100, 100, 100], 2), 2);
        assert_eq!(expected_committee(&[], 5), 0);
        assert_eq!(expected_committee(&[0, 0], 5), 0);
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

    #[test]
    fn the_integer_neg_log2_is_deterministic_and_monotone() {
        let low = output_with_prefix(1);
        let mid = output_with_prefix(1 << 40);
        let high = output_with_prefix(u64::MAX);
        assert_eq!(leader_neg_log2(&mid), leader_neg_log2(&mid));
        assert!(leader_neg_log2(&low) > leader_neg_log2(&mid));
        assert!(leader_neg_log2(&mid) > leader_neg_log2(&high));
        assert_eq!(leader_neg_log2(&high), 0);
    }

    #[test]
    fn the_integer_preference_matches_the_floating_reference() {
        let mut out = [0u8; OUTPUT_BYTES];
        let weights = [500u64, 2_000, 2_000, 7_500, 40_000];
        for trial in 0..4_000u64 {
            let mut base = Vec::new();
            base.extend_from_slice(b"leader-agreement");
            base.extend_from_slice(&trial.to_le_bytes());
            let n = 2 + (trial % 5);
            let mut best_int: Option<(u128, u64, u64)> = None;
            let mut best_flt: Option<(f64, u64)> = None;
            for c in 0..n {
                let mut seed = base.clone();
                seed.extend_from_slice(&c.to_le_bytes());
                shake256(&seed, &mut out);
                let w = weights[(c as usize) % weights.len()];
                let id = c + 1;
                let nl = leader_neg_log2(&out);
                if best_int.map_or(true, |(bnl, bw, bid)| leader_prefers(nl, w, id, bnl, bw, bid)) {
                    best_int = Some((nl, w, id));
                }
                let s = leader_score(&out, w);
                if best_flt.map_or(true, |(bs, bid)| s < bs || (s == bs && id < bid)) {
                    best_flt = Some((s, id));
                }
            }
            assert_eq!(
                best_int.unwrap().2,
                best_flt.unwrap().1,
                "the integer and floating leaders differ at trial {trial}"
            );
        }
    }
}
