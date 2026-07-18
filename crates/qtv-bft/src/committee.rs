//! A committee is sampled per slot from the voting validators, scored by the
//! beacon seed of the previous block. The leader rotates deterministically
//! within the committee by height and view. With a full committee in id order
//! the rotation reduces to Leader(h, v) == ((h + v) % N) + 1 of the formal
//! model.

use crate::block::Height;
use crate::hash::score;
use crate::validator::{ValidatorId, ValidatorSet};

pub type View = u64;

/// Sample a committee of at most `size` voting validators, preferring the
/// lowest scores under the seed. The result is returned in ascending id order,
/// the canonical order the leader rotation walks. Provers are never sampled.
pub fn sample_committee(set: &ValidatorSet, seed: &[u8; 32], size: usize) -> Vec<ValidatorId> {
    let mut scored: Vec<([u8; 32], ValidatorId)> = set
        .voting_ids()
        .into_iter()
        .map(|id| (score(seed, id), id))
        .collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let take = size.min(scored.len());
    let mut committee: Vec<ValidatorId> = scored.into_iter().take(take).map(|(_, id)| id).collect();
    committee.sort_unstable();
    committee
}

/// The leader of a height and view, drawn deterministically from the committee.
pub fn leader(committee: &[ValidatorId], height: Height, view: View) -> Option<ValidatorId> {
    if committee.is_empty() {
        return None;
    }
    let index = ((height + view) as usize) % committee.len();
    Some(committee[index])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_committee_is_all_voting_validators_in_order() {
        let set = ValidatorSet::new(4).with_prover();
        let committee = sample_committee(&set, &[0xBEu8; 32], 4);
        assert_eq!(committee, vec![1, 2, 3, 4]);
    }

    #[test]
    fn sampling_is_deterministic() {
        let set = ValidatorSet::new(10);
        let a = sample_committee(&set, &[99u8; 32], 5);
        let b = sample_committee(&set, &[99u8; 32], 5);
        assert_eq!(a, b);
        assert_eq!(a.len(), 5);
    }

    #[test]
    fn leader_matches_the_model_formula_on_a_full_committee() {
        let n = 4u64;
        let committee: Vec<ValidatorId> = (1..=n).collect();
        for height in 1..=6u64 {
            for view in 0..4u64 {
                let expected = ((height + view) % n) + 1;
                assert_eq!(leader(&committee, height, view), Some(expected));
            }
        }
    }

    #[test]
    fn view_change_rotates_the_leader() {
        let committee: Vec<ValidatorId> = (1..=4).collect();
        let first = leader(&committee, 1, 0).unwrap();
        let second = leader(&committee, 1, 1).unwrap();
        assert_ne!(first, second);
    }
}
