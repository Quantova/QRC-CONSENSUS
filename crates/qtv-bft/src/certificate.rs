//! When a supermajority of the committee has attested one block, the
//! attestations aggregate into a single finality certificate and the block is
//! final. The certificate keeps only the attester set, not the list of votes,
//! so consensus votes never consume block space. Each attestation is verified
//! with its signer ML-DSA key before it counts, so a forged attestation can
//! never help a block finalize. Mirrors the Finalize action and the certs
//! variable of the formal model.

use crate::attest::Attestation;
use crate::block::{Block, Height};
use crate::hash::fold;
use crate::params::is_quorum;
use crate::validator::{ValidatorId, ValidatorSet};

/// A finality certificate for one height. It records the finalized block and
/// the set of validators whose verified attestations formed the quorum.
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

    /// A compact digest of the certificate: the block bytes followed by the
    /// attester ids. The beacon for the next height folds this in, so leader
    /// election derives from the aggregate rather than any single validator.
    pub fn digest_bytes(&self) -> Vec<u8> {
        let mut out = self.block.to_bytes();
        for id in &self.attesters {
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }

    /// The beacon that seeds the next height, folded from a previous seed and
    /// this certificate.
    pub fn beacon(&self, prev_seed: u64) -> u64 {
        fold(prev_seed, &self.digest_bytes())
    }
}

/// Aggregate the attestations for a block at a height into a certificate. An
/// attestation counts only when it is for this height and block, comes from a
/// committee member, and its ML-DSA signature verifies under that member key.
/// A certificate forms only when the distinct verified attesters are a quorum,
/// meaning more than two thirds of the committee.
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
        let block = Block::new(1, 9, Parent::Genesis);
        let atts = attest_all(&set, &committee, block);
        let cert = aggregate(1, block, &committee, &atts, &set).expect("quorum");
        assert_eq!(cert.attesters, vec![1, 2, 3, 4]);
        assert_eq!(cert.block, block);
    }

    #[test]
    fn below_quorum_does_not_finalize() {
        let set = ValidatorSet::new(4);
        let committee = vec![1, 2, 3, 4];
        let block = Block::new(1, 9, Parent::Genesis);
        let atts = attest_all(&set, &[1, 2], block);
        assert!(aggregate(1, block, &committee, &atts, &set).is_none());
    }

    #[test]
    fn forged_attestation_does_not_count_toward_quorum() {
        let set = ValidatorSet::new(4);
        let committee = vec![1, 2, 3, 4];
        let block = Block::new(1, 9, Parent::Genesis);
        // Two honest attestations plus one attestation with a corrupted signature.
        let mut atts = attest_all(&set, &[1, 2], block);
        let mut forged = Attestation::create(set.get(3).unwrap(), 1, block);
        forged.sig[10] ^= 0xff;
        atts.push(forged);
        // Only two verified attesters remain, below the quorum of three.
        assert!(aggregate(1, block, &committee, &atts, &set).is_none());
    }

    #[test]
    fn votes_for_another_block_are_not_counted() {
        let set = ValidatorSet::new(4);
        let committee = vec![1, 2, 3, 4];
        let block = Block::new(1, 9, Parent::Genesis);
        let other = Block::new(1, 10, Parent::Genesis);
        let mut atts = attest_all(&set, &[1, 2], block);
        atts.extend(attest_all(&set, &[3, 4], other));
        assert!(aggregate(1, block, &committee, &atts, &set).is_none());
    }

    #[test]
    fn beacon_depends_on_the_certificate() {
        let set = ValidatorSet::new(4);
        let committee = vec![1, 2, 3, 4];
        let block = Block::new(1, 9, Parent::Genesis);
        let atts = attest_all(&set, &committee, block);
        let cert = aggregate(1, block, &committee, &atts, &set).unwrap();
        assert_eq!(cert.beacon(7), cert.beacon(7));
        assert_ne!(cert.beacon(7), cert.beacon(8));
    }
}
