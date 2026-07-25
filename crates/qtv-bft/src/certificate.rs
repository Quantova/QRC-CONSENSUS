// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::attest::Attestation;
use crate::block::{Block, Height};
use crate::hash::fold;
use crate::params::is_quorum;
use crate::validator::{ValidatorId, ValidatorSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub height: Height,
    pub block: Block,
    pub attesters: Vec<ValidatorId>,
}

impl Certificate {
    pub fn quorum_size(&self) -> usize {
        self.attesters.len()
    }

    pub fn digest_bytes(&self) -> Vec<u8> {
        let mut out = self.block.to_bytes();
        for id in &self.attesters {
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }

    pub fn beacon(&self, prev_seed: &[u8; 32]) -> [u8; 32] {
        fold(prev_seed, &self.digest_bytes())
    }
}

pub fn aggregate(
    height: Height,
    block: Block,
    committee: &[ValidatorId],
    attestations: &[Attestation],
    set: &ValidatorSet,
) -> Option<Certificate> {
    let mut attesters: Vec<ValidatorId> = Vec::new();
    for att in attestations {
        if att.height != height || att.block != block {
            continue;
        }
        if !committee.contains(&att.from) {
            continue;
        }
        let public_key = match set.public_key(att.from) {
            Some(pk) => pk,
            None => continue,
        };
        if !att.verify(public_key) {
            continue;
        }
        if !attesters.contains(&att.from) {
            attesters.push(att.from);
        }
    }
    if is_quorum(attesters.len(), committee.len()) {
        attesters.sort_unstable();
        Some(Certificate {
            height,
            block,
            attesters,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Parent;

    fn attest_all(set: &ValidatorSet, committee: &[ValidatorId], block: Block) -> Vec<Attestation> {
        committee
            .iter()
            .map(|&id| Attestation::create(set.get(id).unwrap(), block.height, block))
            .collect()
    }

    #[test]
    fn quorum_of_verified_attestations_finalizes() {
        let set = ValidatorSet::new(4);
        let committee = vec![1, 2, 3, 4];
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let atts = attest_all(&set, &committee, block);
        let cert = aggregate(1, block, &committee, &atts, &set).expect("quorum");
        assert_eq!(cert.attesters, vec![1, 2, 3, 4]);
        assert_eq!(cert.block, block);
    }

    #[test]
    fn below_quorum_does_not_finalize() {
        let set = ValidatorSet::new(4);
        let committee = vec![1, 2, 3, 4];
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let atts = attest_all(&set, &[1, 2], block);
        assert!(aggregate(1, block, &committee, &atts, &set).is_none());
    }

    #[test]
    fn forged_attestation_does_not_count_toward_quorum() {
        let set = ValidatorSet::new(4);
        let committee = vec![1, 2, 3, 4];
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let mut atts = attest_all(&set, &[1, 2], block);
        let mut forged = Attestation::create(set.get(3).unwrap(), 1, block);
        forged.sig[10] ^= 255;
        atts.push(forged);
        assert!(aggregate(1, block, &committee, &atts, &set).is_none());
    }

    #[test]
    fn votes_for_another_block_are_not_counted() {
        let set = ValidatorSet::new(4);
        let committee = vec![1, 2, 3, 4];
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let other = Block::new(1, [10u8; 32], Parent::Genesis);
        let mut atts = attest_all(&set, &[1, 2], block);
        atts.extend(attest_all(&set, &[3, 4], other));
        assert!(aggregate(1, block, &committee, &atts, &set).is_none());
    }

    #[test]
    fn beacon_depends_on_the_certificate() {
        let set = ValidatorSet::new(4);
        let committee = vec![1, 2, 3, 4];
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let atts = attest_all(&set, &committee, block);
        let cert = aggregate(1, block, &committee, &atts, &set).unwrap();
        assert_eq!(cert.beacon(&[7u8; 32]), cert.beacon(&[7u8; 32]));
        assert_ne!(cert.beacon(&[7u8; 32]), cert.beacon(&[8u8; 32]));
    }
}
