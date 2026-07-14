//! One round of the protocol. The proposer offers the canonical block for the
//! height, the committee votes, and a validator that votes for two different
//! blocks at the same height is flagged for slashing. Offline validators are
//! skipped and never slashed.

use crate::committee::{rotation_order, sample_committee};
use crate::hash::combine;
use crate::validator::{Fault, ValidatorId, ValidatorSet};

pub type BlockId = u64;

pub fn canonical_block(height: u64, seed: u64) -> BlockId {
    combine(seed, combine(height, 0x1))
}

pub fn conflicting_block(height: u64, seed: u64) -> BlockId {
    combine(seed, combine(height, 0x2))
}

pub type Vote = (ValidatorId, BlockId);

pub fn select_proposer(
    set: &ValidatorSet,
    committee: &[ValidatorId],
    seed: u64,
    height: u64,
) -> Option<ValidatorId> {
    rotation_order(committee, seed, height)
        .into_iter()
        .find(|id| set.fault_of(*id) != Fault::Offline)
}

pub fn collect_votes(
    set: &ValidatorSet,
    committee: &[ValidatorId],
    proposal: BlockId,
    conflict: BlockId,
) -> Vec<Vote> {
    let mut votes = Vec::new();
    for &id in committee {
        match set.fault_of(id) {
            Fault::Honest => votes.push((id, proposal)),
            Fault::Offline => {}
            Fault::Conflicting => votes.push((id, conflict)),
            Fault::Equivocating => {
                votes.push((id, proposal));
                votes.push((id, conflict));
            }
        }
    }
    votes
}

pub fn detect_equivocation(votes: &[Vote]) -> Vec<ValidatorId> {
    let mut flagged = Vec::new();
    for &(voter, block) in votes {
        let two = votes.iter().any(|&(other, b)| other == voter && b != block);
        if two && !flagged.contains(&voter) {
            flagged.push(voter);
        }
    }
    flagged.sort_unstable();
    flagged
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundOutcome {
    pub height: u64,
    pub seed: u64,
    pub committee: Vec<ValidatorId>,
    pub proposer: Option<ValidatorId>,
    pub proposal: Option<BlockId>,
    pub slashed: Vec<ValidatorId>,
}

pub fn run_round(
    set: &ValidatorSet,
    height: u64,
    seed: u64,
    committee_size: usize,
) -> RoundOutcome {
    let committee = sample_committee(set, seed, committee_size);
    let proposer = select_proposer(set, &committee, seed, height);
    let proposal = proposer.map(|_| canonical_block(height, seed));

    let slashed = match proposal {
        Some(block) => {
            let conflict = conflicting_block(height, seed);
            let votes = collect_votes(set, &committee, block, conflict);
            detect_equivocation(&votes)
        }
        None => Vec::new(),
    };

    RoundOutcome {
        height,
        seed,
        committee,
        proposer,
        proposal,
        slashed,
    }
}
