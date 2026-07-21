use crate::beacon::Beacon;
use crate::onetime::Root;
use crate::params::{COMMITTEE_BUDGET, DOMAIN_COMMITTEE, DOMAIN_LEADER, MIN_SELF_STAKE};
use crate::sortition::{is_selected, leader_score, verify_membership, Credential};
use crate::validator::{Registration, SamplerValidator, ValidatorId};

pub struct Member {
    pub id: ValidatorId,
    pub weight: u64,
    pub credential: Credential,
}

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

    pub fn ids(&self) -> Vec<ValidatorId> {
        self.members.iter().map(|m| m.id).collect()
    }

    pub fn contains(&self, id: ValidatorId) -> bool {
        self.members.iter().any(|m| m.id == id)
    }
}

pub struct Leader {
    pub id: ValidatorId,
    pub credential: Credential,
}

pub fn verify_leader(root: &Root, slot: u64, credential: &Credential) -> bool {
    verify_membership(root, slot, credential)
}

pub struct Registry {
    validators: Vec<SamplerValidator>,
    budget: u64,
    floor: u64,
}

impl Registry {
    pub fn new(validators: Vec<SamplerValidator>) -> Self {
        Registry {
            validators,
            budget: COMMITTEE_BUDGET,
            floor: MIN_SELF_STAKE,
        }
    }

    pub fn with_budget(mut self, budget: u64) -> Self {
        self.budget = budget;
        self
    }

    pub fn with_floor(mut self, floor: u64) -> Self {
        self.floor = floor;
        self
    }

    pub fn floor(&self) -> u64 {
        self.floor
    }

    pub fn budget(&self) -> u64 {
        self.budget
    }

    pub fn get(&self, id: ValidatorId) -> Option<&SamplerValidator> {
        self.validators.iter().find(|v| v.id == id)
    }

    pub fn registration(&self, id: ValidatorId) -> Option<Registration> {
        self.get(id).map(Registration::of)
    }

    pub fn total_weight(&self) -> u64 {
        self.validators
            .iter()
            .map(SamplerValidator::weight)
            .filter(|&w| w >= self.floor)
            .sum()
    }

    pub fn weights(&self) -> Vec<u64> {
        self.validators
            .iter()
            .filter(|v| !v.is_prover() && v.weight() >= self.floor)
            .map(SamplerValidator::weight)
            .collect()
    }

    pub fn sample_committee(&self, beacon: &Beacon, slot: u64) -> Committee {
        let total = self.total_weight();
        let mut members: Vec<Member> = Vec::new();
        for v in &self.validators {
            if v.is_prover() || v.weight() < self.floor {
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
        let reg = Registry::new(validators(&[100, 100, 100]))
            .with_budget(10)
            .with_floor(0);
        let beacon = Beacon::genesis();
        let committee = reg.sample_committee(&beacon, 0);
        assert_eq!(committee.ids(), vec![1, 2, 3]);
        let leader = reg.elect_leader(&committee, &beacon, 0).unwrap();
        assert!(committee.contains(leader.id));
        let root = reg.registration(leader.id).unwrap().root;
        assert!(verify_leader(&root, 0, &leader.credential));
    }
}
