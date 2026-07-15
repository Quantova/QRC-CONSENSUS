//! Committee and leader selection on the one time key sortition. A registry holds
//! the staking accounts and the committee budget. For a slot every voting account
//! reveals its one time credential over the beacon, and the ones whose committee
//! output falls below their stake weighted threshold form the committee. The
//! leader of the slot is the committee member that wins the stake weighted leader
//! race, and its credential is the proposer eligibility proof any node rechecks.
//!
//! Provers hold no vote and are never drawn. An offline account that is selected
//! keeps its place in the committee and is simply skipped in the round by the
//! core, never removed here and never slashed. Only native stake counts, so a
//! bridged holding never lifts an account into the committee.

use crate::beacon::Beacon;
use crate::onetime::Root;
use crate::params::{COMMITTEE_BUDGET, DOMAIN_COMMITTEE, DOMAIN_LEADER};
use crate::sortition::{is_selected, leader_score, verify_membership, Credential};
use crate::validator::{Registration, SamplerValidator, ValidatorId};

/// A committee member: its id, its native weight, and the one time credential
/// that admitted it.
pub struct Member {
    pub id: ValidatorId,
    pub weight: u64,
    pub credential: Credential,
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

/// The leader of a slot: its id and the credential that proves eligibility.
pub struct Leader {
    pub id: ValidatorId,
    pub credential: Credential,
}

/// Verify a proposer eligibility proof: the leader credential authenticates to
/// the account's registered root at the slot, so the credential is genuinely that
/// account's one time reveal for the slot. The canonical leader of a slot is the
/// eligible committee member that wins the stake weighted leader race, so a node
/// confirms a proposer by checking this proof and that it wins that race.
pub fn verify_leader(root: &Root, slot: u64, credential: &Credential) -> bool {
    verify_membership(root, slot, credential)
}

/// A registry of staking accounts and the committee budget that bounds the target
/// committee size.
pub struct Registry {
    validators: Vec<SamplerValidator>,
    budget: u64,
}

impl Registry {
    /// A registry over the given accounts with the protocol committee budget.
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

    /// The public registration of an account, the root and weight a verifier reads
    /// from the stake registry. An account not registered here returns None, so a
    /// draw claiming a root that is not registered is rejected for want of a root
    /// to check against.
    pub fn registration(&self, id: ValidatorId) -> Option<Registration> {
        self.get(id).map(Registration::of)
    }

    /// Total native weight of the voting accounts. Provers and bridged holdings
    /// weigh zero, so neither lifts the total.
    pub fn total_weight(&self) -> u64 {
        self.validators.iter().map(SamplerValidator::weight).sum()
    }

    /// Native weights of the voting accounts, for reasoning about the expected
    /// committee size against the budget.
    pub fn weights(&self) -> Vec<u64> {
        self.validators
            .iter()
            .filter(|v| !v.is_prover())
            .map(SamplerValidator::weight)
            .collect()
    }

    /// Sample the committee for a slot. Every voting account reveals its one time
    /// credential over the beacon, and the ones whose committee output falls below
    /// their stake weighted threshold are admitted. Provers are never drawn. The
    /// result is in ascending id order.
    pub fn sample_committee(&self, beacon: &Beacon, slot: u64) -> Committee {
        let total = self.total_weight();
        let mut members: Vec<Member> = Vec::new();
        for v in &self.validators {
            if v.is_prover() {
                continue;
            }
            let credential = v.reveal(slot);
            let value = credential.value(beacon, DOMAIN_COMMITTEE, slot);
            if is_selected(value, v.weight(), total, self.budget) {
                members.push(Member {
                    id: v.id,
                    weight: v.weight(),
                    credential,
                });
            }
        }
        members.sort_by_key(|m| m.id);
        Committee { members }
    }

    /// Elect the leader of a slot from a committee: the member that wins the stake
    /// weighted leader race, the lowest leader score, ties broken by the lower id.
    /// The leader score is the sub weight model, so splitting a stake across many
    /// accounts does not raise the chance of leading. The returned credential is
    /// the proposer eligibility proof. Returns None for an empty committee.
    pub fn elect_leader(
        &self,
        committee: &Committee,
        beacon: &Beacon,
        slot: u64,
    ) -> Option<Leader> {
        let mut best: Option<(f64, ValidatorId, Credential)> = None;
        for m in &committee.members {
            let output = m.credential.output(beacon, DOMAIN_LEADER, slot);
            let score = leader_score(&output, m.weight);
            let take = match &best {
                None => true,
                Some((bs, bid, _)) => score < *bs || (score == *bs && m.id < *bid),
            };
            if take {
                best = Some((score, m.id, m.credential.clone()));
            }
        }
        best.map(|(_, id, credential)| Leader { id, credential })
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
    fn a_generous_budget_admits_every_account_and_elects_one_leader() {
        let reg = Registry::new(validators(&[100, 100, 100])).with_budget(10);
        let beacon = Beacon::genesis();
        let committee = reg.sample_committee(&beacon, 0);
        assert_eq!(committee.ids(), vec![1, 2, 3]);
        let leader = reg.elect_leader(&committee, &beacon, 0).unwrap();
        assert!(committee.contains(leader.id));
        // The leader credential rechecks against the leader's registered root.
        let root = reg.registration(leader.id).unwrap().root;
        assert!(verify_leader(&root, 0, &leader.credential));
    }
}
