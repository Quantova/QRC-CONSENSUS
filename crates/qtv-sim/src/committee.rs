//! A fixed size committee is sampled per round from the beacon seed of the

use crate::hash::{combine, mix64};
use crate::validator::{ValidatorId, ValidatorSet};

pub fn sample_committee(set: &ValidatorSet, seed: u64, size: usize) -> Vec<ValidatorId> {
    let mut scored: Vec<(u64, ValidatorId)> = set
        .ids()
        .into_iter()
        .map(|id| (combine(seed, id), id))
        .collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let take = size.min(scored.len());
    scored.into_iter().take(take).map(|(_, id)| id).collect()
}

pub fn rotation_order(committee: &[ValidatorId], seed: u64, round: u64) -> Vec<ValidatorId> {
    if committee.is_empty() {
        return Vec::new();
    }
    let base = (mix64(seed) as usize).wrapping_add(round as usize) % committee.len();
    (0..committee.len())
        .map(|k| committee[(base + k) % committee.len()])
        .collect()
}

pub fn leader(committee: &[ValidatorId], seed: u64, round: u64) -> Option<ValidatorId> {
    rotation_order(committee, seed, round).into_iter().next()
}

pub fn supermajority(committee_size: usize) -> usize {
    2 * committee_size / 3 + 1
}
