// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::committee::supermajority;
use crate::round::{BlockId, Vote};
use crate::validator::ValidatorId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub height: u64,
    pub seed: u64,
    pub block: BlockId,
    pub voters: Vec<ValidatorId>,
    pub weight: u32,
}

fn tally(committee: &[ValidatorId], votes: &[Vote], block: BlockId) -> (Vec<ValidatorId>, u32) {
    let mut voters: Vec<ValidatorId> = votes
        .iter()
        .filter(|&&(voter, b)| b == block && committee.contains(&voter))
        .map(|&(voter, _)| voter)
        .collect();
    voters.sort_unstable();
    voters.dedup();
    let weight = voters.len() as u32;
    (voters, weight)
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
            });
        }
    }
    None
}
