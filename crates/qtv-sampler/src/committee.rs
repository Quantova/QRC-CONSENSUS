use crate::beacon::Beacon;
use crate::onetime::{Root, PREIMAGE_BYTES};
use crate::params::{COMMITTEE_BUDGET, DOMAIN_COMMITTEE, DOMAIN_LEADER, MIN_SELF_STAKE};
use crate::sortition::{leader_neg_log2, leader_prefers, verify_membership, verify_selection, Credential};
use crate::validator::{Registration, ValidatorId};

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

    /// The committee's reveal preimages in ascending member id order. Each is fixed by
    /// the member's registered one time tree, so no member can choose the value it
    /// contributes.
    pub fn reveals(&self) -> Vec<[u8; PREIMAGE_BYTES]> {
        self.members.iter().map(|m| m.credential.preimage).collect()
    }

    /// The next slot beacon, advanced from this committee's reveals rather than from any
    /// block or certificate bytes a proposer could pick.
    pub fn next_beacon(&self, beacon: &Beacon, slot: u64) -> Beacon {
        beacon.advance_from_reveals(slot, &self.reveals())
    }
}

pub struct Leader {
    pub id: ValidatorId,
    pub credential: Credential,
}

pub fn verify_leader(root: &Root, slot: u64, credential: &Credential) -> bool {
    verify_membership(root, slot, credential)
}

/// The lowest score member of a committee is its leader for the slot. The score is
/// compared by exact integer arithmetic, so every node elects the identical leader.
pub fn elect_leader(committee: &Committee, beacon: &Beacon, slot: u64) -> Option<Leader> {
    let mut best: Option<(u128, u64, ValidatorId, Credential)> = None;
    for m in &committee.members {
        let output = m.credential.output(beacon, DOMAIN_LEADER, slot);
        let neg_log2 = leader_neg_log2(&output);
        let take = match &best {
            None => true,
            Some((bnl, bw, bid, _)) => leader_prefers(neg_log2, m.weight, m.id, *bnl, *bw, *bid),
        };
        if take {
            best = Some((neg_log2, m.weight, m.id, m.credential.clone()));
        }
    }
    best.map(|(_, _, id, credential)| Leader { id, credential })
}

/// A validator's own sortition reveal for a slot, its id and its one time credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedReveal {
    pub id: ValidatorId,
    pub credential: Credential,
}

impl PublishedReveal {
    pub fn new(id: ValidatorId, credential: Credential) -> Self {
        PublishedReveal { id, credential }
    }
}

/// A view over the registered validator set holding only each validator's registration,
/// its id, sortition root, and stake weight. The committee is assembled from published
/// reveals, each verified against the root held here.
pub struct CommitteeView {
    registrations: Vec<Registration>,
    budget: u64,
    floor: u64,
}

impl CommitteeView {
    pub fn new(registrations: Vec<Registration>) -> Self {
        CommitteeView {
            registrations,
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

    pub fn registration(&self, id: ValidatorId) -> Option<&Registration> {
        self.registrations.iter().find(|r| r.id == id)
    }

    pub fn total_weight(&self) -> u64 {
        self.registrations
            .iter()
            .map(|r| r.weight)
            .filter(|&w| w >= self.floor)
            .sum()
    }

    pub fn weights(&self) -> Vec<u64> {
        self.registrations
            .iter()
            .filter(|r| r.weight >= self.floor)
            .map(|r| r.weight)
            .collect()
    }

    /// Whether a credential published by `id` authenticates to that validator's
    /// registered root and is selected for the slot.
    pub fn admits(
        &self,
        beacon: &Beacon,
        slot: u64,
        id: ValidatorId,
        credential: &Credential,
    ) -> bool {
        let total = self.total_weight();
        match self.registration(id) {
            Some(reg) if reg.weight >= self.floor => verify_selection(
                &reg.root,
                beacon,
                DOMAIN_COMMITTEE,
                slot,
                reg.weight,
                total,
                self.budget,
                credential,
            ),
            _ => false,
        }
    }

    /// Assemble the committee for a slot from the reveals validators publish for
    /// themselves, admitting each that authenticates to its author's root and is
    /// selected. An unregistered author, a reveal that does not authenticate, and a
    /// duplicate are dropped.
    pub fn form_committee(
        &self,
        beacon: &Beacon,
        slot: u64,
        published: &[PublishedReveal],
    ) -> Committee {
        let total = self.total_weight();
        let mut members: Vec<Member> = Vec::new();
        for reveal in published {
            if members.iter().any(|m| m.id == reveal.id) {
                continue;
            }
            let reg = match self.registration(reveal.id) {
                Some(reg) if reg.weight >= self.floor => reg,
                _ => continue,
            };
            if !verify_selection(
                &reg.root,
                beacon,
                DOMAIN_COMMITTEE,
                slot,
                reg.weight,
                total,
                self.budget,
                &reveal.credential,
            ) {
                continue;
            }
            members.push(Member {
                id: reveal.id,
                weight: reg.weight,
                credential: reveal.credential.clone(),
            });
        }
        members.sort_by_key(|m| m.id);
        Committee { members }
    }

    pub fn elect_leader(&self, committee: &Committee, beacon: &Beacon, slot: u64) -> Option<Leader> {
        elect_leader(committee, beacon, slot)
    }
}

// Roster backed sampler for the test suite and the local simulation, the reference the
// sortition math is proven against. Compiled only under cfg(test) or the test-fixtures
// feature and absent from a default build.
#[cfg(any(test, feature = "test-fixtures"))]
pub use roster::Registry;

#[cfg(any(test, feature = "test-fixtures"))]
mod roster {
    use super::{elect_leader, Committee, Leader, Member};
    use crate::beacon::Beacon;
    use crate::params::{COMMITTEE_BUDGET, DOMAIN_COMMITTEE, MIN_SELF_STAKE};
    use crate::sortition::is_selected;
    use crate::validator::{Registration, SamplerValidator, ValidatorId};

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
            elect_leader(committee, beacon, slot)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::SamplerValidator;

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

    #[test]
    fn a_published_reveal_committee_reproduces_the_sortition_committee() {
        let set = validators(&[100, 100, 100, 100, 100]);
        let reg = Registry::new(set.iter().map(|v| v.clone()).collect())
            .with_budget(3)
            .with_floor(0);
        let view = CommitteeView::new(set.iter().map(Registration::of).collect())
            .with_budget(3)
            .with_floor(0);
        for slot in 0..16u64 {
            let beacon = Beacon::genesis();
            let published: Vec<PublishedReveal> = set
                .iter()
                .map(|v| PublishedReveal::new(v.id, v.reveal(slot)))
                .collect();
            let drawn = reg.sample_committee(&beacon, slot);
            let assembled = view.form_committee(&beacon, slot, &published);
            assert_eq!(
                assembled.ids(),
                drawn.ids(),
                "the assembled committee differs at slot {slot}"
            );
            let a = view.elect_leader(&assembled, &beacon, slot).map(|l| l.id);
            let b = reg.elect_leader(&drawn, &beacon, slot).map(|l| l.id);
            assert_eq!(a, b, "the leader differs at slot {slot}");
        }
    }

    #[test]
    fn a_reveal_that_does_not_authenticate_is_not_admitted() {
        let set = validators(&[100, 100, 100]);
        let view = CommitteeView::new(set.iter().map(Registration::of).collect())
            .with_budget(10)
            .with_floor(0);
        let beacon = Beacon::genesis();
        let slot = 0;
        let honest: Vec<PublishedReveal> = set
            .iter()
            .map(|v| PublishedReveal::new(v.id, v.reveal(slot)))
            .collect();
        assert!(view.form_committee(&beacon, slot, &honest).contains(1));

        let forged = vec![PublishedReveal::new(1, set[1].reveal(slot))];
        let committee = view.form_committee(&beacon, slot, &forged);
        assert!(
            !committee.contains(1),
            "a reveal that does not open the committed root admitted its author"
        );
        assert!(committee.is_empty());
    }

    #[test]
    fn a_validator_that_never_publishes_is_absent() {
        let set = validators(&[100, 100, 100]);
        let view = CommitteeView::new(set.iter().map(Registration::of).collect())
            .with_budget(10)
            .with_floor(0);
        let beacon = Beacon::genesis();
        let slot = 0;
        let published = vec![
            PublishedReveal::new(1, set[0].reveal(slot)),
            PublishedReveal::new(3, set[2].reveal(slot)),
        ];
        let committee = view.form_committee(&beacon, slot, &published);
        assert!(committee.contains(1));
        assert!(committee.contains(3));
        assert!(!committee.contains(2), "a silent validator was admitted");
    }

    #[test]
    fn the_elected_leader_matches_the_floating_reference_and_is_stable() {
        use crate::sortition::leader_score;
        let set = validators(&[500, 2_000, 2_000, 7_500, 40_000, 2_000, 15_000]);
        let reg = Registry::new(set.iter().map(|v| v.clone()).collect())
            .with_budget(500)
            .with_floor(0);
        for slot in 0..64u64 {
            let beacon = Beacon::genesis();
            let committee = reg.sample_committee(&beacon, slot);
            if committee.is_empty() {
                continue;
            }
            let elected = elect_leader(&committee, &beacon, slot).unwrap().id;
            assert_eq!(elected, elect_leader(&committee, &beacon, slot).unwrap().id);
            let mut best: Option<(f64, ValidatorId)> = None;
            for m in &committee.members {
                let score = leader_score(&m.credential.output(&beacon, DOMAIN_LEADER, slot), m.weight);
                if best.map_or(true, |(bs, bid)| score < bs || (score == bs && m.id < bid)) {
                    best = Some((score, m.id));
                }
            }
            assert_eq!(elected, best.unwrap().1, "the leader differs at slot {slot}");
        }
    }

    #[test]
    fn a_proposer_cannot_shift_its_own_next_slot_draw() {
        use crate::beacon::SEED_BYTES;
        use qtv_crypto::sha3::shake256;
        use std::collections::BTreeSet;

        let set = validators(&[100, 100, 100, 100, 100]);
        let reg = Registry::new(set.iter().map(|v| v.clone()).collect())
            .with_budget(10)
            .with_floor(0);
        let beacon = Beacon::genesis();
        let slot = 3u64;
        let next_slot = slot + 1;
        let committee = reg.sample_committee(&beacon, slot);
        assert!(!committee.is_empty());
        let proposer = &set[0];
        assert!(committee.contains(proposer.id));

        let unbiased = committee.next_beacon(&beacon, slot);
        let fixed = proposer
            .reveal(next_slot)
            .value(&unbiased, DOMAIN_LEADER, next_slot);

        let mut reveal_draws = BTreeSet::new();
        let mut digest_draws = BTreeSet::new();
        for candidate in 0u64..64 {
            let mut digest = [0u8; SEED_BYTES];
            shake256(&candidate.to_le_bytes(), &mut digest);

            let reveal_next = committee.next_beacon(&beacon, slot);
            reveal_draws.insert(
                proposer
                    .reveal(next_slot)
                    .value(&reveal_next, DOMAIN_LEADER, next_slot),
            );

            let digest_next = beacon.advance(&digest, slot);
            digest_draws.insert(
                proposer
                    .reveal(next_slot)
                    .value(&digest_next, DOMAIN_LEADER, next_slot),
            );
        }

        assert_eq!(reveal_draws.len(), 1, "the reveal beacon leaves the proposer no lever");
        assert_eq!(*reveal_draws.iter().next().unwrap(), fixed);
        assert!(
            digest_draws.len() > 1,
            "the old certificate digest beacon let the proposer grind its next draw"
        );
    }
}
