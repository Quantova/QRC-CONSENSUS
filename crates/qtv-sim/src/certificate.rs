//! Votes are aggregated into a single certificate rather than kept as a list.

use crate::committee::supermajority;
use crate::round::{BlockId, Vote};
use crate::validator::ValidatorId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub height: u64,
    pub seed: u64,
    pub block: BlockId,
    pub voters: u64,
    pub weight: u32,
    pub valid: bool,
}

fn tally(committee: &[ValidatorId], votes: &[Vote], block: BlockId) -> (u64, u32) {
    let mut mask: u64 = 0;
    let mut weight: u32 = 0;
    for &(voter, b) in votes {
        if b != block || voter >= 64 || !committee.contains(&voter) {
            continue;
        }
        let bit = 1u64 << voter;
        if mask & bit == 0 {
            mask |= bit;
            weight += 1;
        }
    }
    (mask, weight)
}

pub fn aggregate(
    height: u64,
    seed: u64,
    committee: &[ValidatorId],
    votes: &[Vote],
    committee_size: usize,
) -> Option<Certificate> {
    let threshold = supermajority(committee_size) as u32;
    let mut blocks: Vec<BlockId> = votes.iter().map(|&(_, b)| b).collect();
    blocks.sort_unstable();
    blocks.dedup();
    for block in blocks {
        let (voters, weight) = tally(committee, votes, block);
        if weight >= threshold {
            return Some(Certificate {
                height,
                seed,
                block,
                voters,
                weight,
                valid: true,
            });
        }
    }
    None
}
