// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::sha3::shake256;

use crate::validator::ValidatorId;

const EPOCH_SEED_DOMAIN: &[u8] = b"QORUS/onetime/epoch-rotation/v1";

pub fn epoch_of(height: u64, heights_per_epoch: u64) -> u64 {
    if heights_per_epoch == 0 {
        return 0;
    }
    height / heights_per_epoch
}

pub fn slot_in_epoch(height: u64, heights_per_epoch: u64) -> u64 {
    if heights_per_epoch == 0 {
        return height;
    }
    height % heights_per_epoch
}

pub fn is_epoch_start(height: u64, heights_per_epoch: u64) -> bool {
    heights_per_epoch != 0 && height % heights_per_epoch == 0
}

pub fn epoch_tree_seed(base_seed: &[u8; 32], epoch: u64) -> [u8; 32] {
    if epoch == 0 {
        return *base_seed;
    }
    const D: usize = EPOCH_SEED_DOMAIN.len();
    let mut buf = [0u8; D + 32 + 8];
    buf[..D].copy_from_slice(EPOCH_SEED_DOMAIN);
    buf[D..D + 32].copy_from_slice(base_seed);
    buf[D + 32..].copy_from_slice(&epoch.to_le_bytes());
    let mut out = [0u8; 32];
    shake256(&buf, &mut out);
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChurnBound {
    pub max_entrants: u64,
}

impl ChurnBound {
    pub fn new(max_entrants: u64) -> Self {
        ChurnBound { max_entrants }
    }

    pub fn admit(&self, prev: &[ValidatorId], requested: &[ValidatorId]) -> Vec<ValidatorId> {
        let mut req: Vec<ValidatorId> = requested.to_vec();
        req.sort_unstable();
        req.dedup();
        let mut next: Vec<ValidatorId> = Vec::new();
        for id in &req {
            if prev.contains(id) {
                next.push(*id);
            }
        }
        let mut admitted = 0u64;
        for id in &req {
            if !prev.contains(id) && admitted < self.max_entrants {
                next.push(*id);
                admitted += 1;
            }
        }
        next.sort_unstable();
        next
    }

    pub fn entrants(&self, prev: &[ValidatorId], requested: &[ValidatorId]) -> u64 {
        self.admit(prev, requested)
            .iter()
            .filter(|id| !prev.contains(id))
            .count() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_epoch_and_slot_split_a_height_over_the_epoch_length() {
        let len = 8;
        assert_eq!(epoch_of(0, len), 0);
        assert_eq!(slot_in_epoch(0, len), 0);
        assert_eq!(epoch_of(7, len), 0);
        assert_eq!(slot_in_epoch(7, len), 7);
        assert_eq!(epoch_of(8, len), 1);
        assert_eq!(slot_in_epoch(8, len), 0);
        assert_eq!(epoch_of(65, len), 8);
        assert_eq!(slot_in_epoch(65, len), 1);
        assert!(is_epoch_start(8, len));
        assert!(!is_epoch_start(9, len));
    }

    #[test]
    fn a_zero_length_epoch_keeps_the_height_as_the_slot() {
        assert_eq!(epoch_of(100, 0), 0);
        assert_eq!(slot_in_epoch(100, 0), 100);
        assert!(!is_epoch_start(0, 0));
    }

    #[test]
    fn epoch_zero_keeps_the_base_seed_and_later_epochs_diverge() {
        let base = [7u8; 32];
        assert_eq!(epoch_tree_seed(&base, 0), base);
        let one = epoch_tree_seed(&base, 1);
        let two = epoch_tree_seed(&base, 2);
        assert_ne!(one, base);
        assert_ne!(one, two);
        assert_eq!(one, epoch_tree_seed(&base, 1));
    }

    #[test]
    fn a_different_base_seed_moves_every_rotated_seed() {
        let a = epoch_tree_seed(&[1u8; 32], 5);
        let b = epoch_tree_seed(&[2u8; 32], 5);
        assert_ne!(a, b);
    }

    #[test]
    fn the_churn_bound_caps_new_entrants_and_carries_incumbents() {
        let bound = ChurnBound::new(1);
        let prev = vec![1u64, 2, 3];
        let requested = vec![1, 2, 3, 4, 5];
        let next = bound.admit(&prev, &requested);
        assert_eq!(next, vec![1, 2, 3, 4]);
        assert_eq!(bound.entrants(&prev, &requested), 1);
    }

    #[test]
    fn an_exit_is_never_capped() {
        let bound = ChurnBound::new(0);
        let prev = vec![1u64, 2, 3];
        let requested = vec![1, 3];
        let next = bound.admit(&prev, &requested);
        assert_eq!(next, vec![1, 3]);
        assert_eq!(bound.entrants(&prev, &requested), 0);
    }

    #[test]
    fn the_admitted_set_is_deterministic_regardless_of_request_order() {
        let bound = ChurnBound::new(2);
        let prev = vec![2u64, 4];
        let a = bound.admit(&prev, &[9, 4, 7, 2, 5]);
        let b = bound.admit(&prev, &[5, 2, 9, 7, 4]);
        assert_eq!(a, b);
        assert_eq!(a, vec![2, 4, 5, 7]);
    }
}
