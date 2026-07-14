//! Committee and leader selection by verifiable random sortition. A registry
//! holds the validators and the committee budget. For a slot, every voting
//! validator draws over the beacon and the ones below their stake weighted
//! threshold form the committee. The leader of the slot is the committee member
//! with the lowest leader draw, and that draw is the proposer eligibility proof
//! any node rechecks.
//!
//! Provers hold no vote and are never drawn. An offline validator that is
//! selected keeps its place in the committee and is simply skipped in the round
//! by the core, never removed here and never slashed. Only native stake counts,
//! so a bridged holding never lifts a validator into the committee.

use qtv_crypto::vrf::{verify, PUBLIC_KEY_BYTES};

use crate::beacon::Beacon;
use crate::params::{COMMITTEE_BUDGET, DOMAIN_COMMITTEE, DOMAIN_LEADER};
use crate::sortition::{draw, is_selected, Draw};
use crate::validator::{SamplerValidator, ValidatorId};

/// A committee member: its id and the committee draw that admitted it.
pub struct Member {
    pub id: ValidatorId,
    pub draw: Draw,
}

/// The committee sampled for a slot, in ascending id order.
pub struct Committee {
    pub members: Vec<Member>,
}

impl Committee {
    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Member ids in ascending order.
    pub fn ids(&self) -> Vec<ValidatorId> {
        self.members.iter().map(|m| m.id).collect()
    }

    pub fn contains(&self, id: ValidatorId) -> bool {
        self.members.iter().any(|m| m.id == id)
    }
}

/// The leader of a slot: its id and the leader draw that proves eligibility.
pub struct Leader {
    pub id: ValidatorId,
    pub draw: Draw,
}

/// Verify a proposer eligibility proof: the leader draw checks against the
/// public key over the leader input for the slot. The canonical leader of a slot
/// is the eligible committee member with the lowest such draw, so a node
/// confirms a proposer by checking this proof and that it wins that comparison.
pub fn verify_leader(
    public_key: &[u8; PUBLIC_KEY_BYTES],
    beacon: &Beacon,
    slot: u64,
    draw: &Draw,
) -> bool {
    let input = beacon.sortition_input(DOMAIN_LEADER, slot);
    verify(public_key, &input, &draw.output, &draw.proof)
}

/// A registry of validators and the committee budget that bounds the target
/// committee size.
pub struct Registry {
    validators: Vec<SamplerValidator>,
    budget: u64,
}

impl Registry {
    /// A registry over the given validators with the protocol committee budget.
    pub fn new(validators: Vec<SamplerValidator>) -> Self {
        Registry {
            validators,
            budget: COMMITTEE_BUDGET,
        }
    }

    /// Override the committee budget, used to size small committees in tests.
    pub fn with_budget(mut self, budget: u64) -> Self {
        self.budget = budget;
        self
    }

    pub fn budget(&self) -> u64 {
        self.budget
    }

    pub fn get(&self, id: ValidatorId) -> Option<&SamplerValidator> {
        self.validators.iter().find(|v| v.id == id)
    }

    /// Total native weight of the voting validators. Provers and bridged
    /// holdings weigh zero, so neither lifts the total.
    pub fn total_weight(&self) -> u64 {
        self.validators.iter().map(SamplerValidator::weight).sum()
    }

    /// Native weights of the voting validators, for reasoning about the expected
    /// committee size against the budget.
    pub fn weights(&self) -> Vec<u64> {
        self.validators
            .iter()
            .filter(|v| !v.is_prover())
            .map(SamplerValidator::weight)
            .collect()
    }

    /// Sample the committee for a slot. Every voting validator draws over the
    /// beacon, and the ones whose output falls below their stake weighted
    /// threshold are admitted. Provers are never drawn. The result is in
    /// ascending id order.
    pub fn sample_committee(&self, beacon: &Beacon, slot: u64) -> Committee {
        let total = self.total_weight();
        let mut members: Vec<Member> = Vec::new();
        for v in &self.validators {
            if v.is_prover() {
                continue;
            }
            let d = draw(v, beacon, DOMAIN_COMMITTEE, slot);
            if is_selected(d.value(), v.weight(), total, self.budget) {
                members.push(Member { id: v.id, draw: d });
            }
        }
        members.sort_by_key(|m| m.id);
        Committee { members }
    }

    /// Elect the leader of a slot from a committee: the member with the lowest
    /// leader draw, ties broken by the lower id. The returned draw is the
    /// proposer eligibility proof. Returns None for an empty committee.
    pub fn elect_leader(
        &self,
        committee: &Committee,
        beacon: &Beacon,
        slot: u64,
    ) -> Option<Leader> {
        let mut best: Option<Leader> = None;
        for m in &committee.members {
            let Some(v) = self.get(m.id) else { continue };
            let d = draw(v, beacon, DOMAIN_LEADER, slot);
            let take = match &best {
                None => true,
                Some(b) => d.output < b.draw.output || (d.output == b.draw.output && m.id < b.id),
            };
            if take {
                best = Some(Leader { id: m.id, draw: d });
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validators(stakes: &[u64]) -> Vec<SamplerValidator> {
        stakes
            .iter()
            .enumerate()
            .map(|(i, &s)| SamplerValidator::new(i as u64 + 1, s))
            .collect()
    }

    #[test]
    fn a_generous_budget_admits_every_validator_and_elects_one_leader() {
        let reg = Registry::new(validators(&[100, 100, 100])).with_budget(10);
        let beacon = Beacon::genesis();
        let committee = reg.sample_committee(&beacon, 0);
        assert_eq!(committee.ids(), vec![1, 2, 3]);
        let leader = reg.elect_leader(&committee, &beacon, 0).unwrap();
        assert!(committee.contains(leader.id));
    }
}
