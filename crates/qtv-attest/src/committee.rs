// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::ml_dsa::PublicKey;
use qtv_crypto::sha3::shake256;
use qtv_sampler::committee::{Committee, CommitteeView};
use qtv_sampler::onetime::Root;
use qtv_sampler::sortition::DrawMode;

use crate::attester::{Attester, ValidatorId};
use crate::params::COMMITTEE_BUDGET;

pub type CommitteeDigest = [u8; 32];

#[derive(Clone)]
pub struct MemberKey {
    pub id: ValidatorId,
    pub weight: u64,
    pub stake: u64,
    pub root: Root,
    pub attest_pk: PublicKey,
}

#[derive(Clone)]
pub struct CommitteeCommitment {
    pub slot: u64,
    pub total_weight: u64,
    pub budget: u64,
    pub members: Vec<MemberKey>,
    pub absent_stake: u128,
    pub mode: DrawMode,
}

impl CommitteeCommitment {
    pub fn from_attesters(slot: u64, attesters: &[&Attester]) -> Self {
        Self::from_attesters_with_budget(slot, attesters, COMMITTEE_BUDGET)
    }

    pub fn from_attesters_with_budget(slot: u64, attesters: &[&Attester], budget: u64) -> Self {
        let members: Vec<MemberKey> = attesters
            .iter()
            .map(|a| MemberKey {
                id: a.id(),
                weight: a.weight(),
                stake: a.weight(),
                root: a.root(),
                attest_pk: *a.attest_public_key(),
            })
            .collect();
        Self::from_member_keys(slot, members, budget, DrawMode::Unbound)
    }

    pub fn from_member_keys(
        slot: u64,
        mut members: Vec<MemberKey>,
        budget: u64,
        mode: DrawMode,
    ) -> Self {
        members.sort_by_key(|m| m.id);
        members.dedup_by_key(|m| m.id);
        let total = members
            .iter()
            .try_fold(0u64, |sum, m| sum.checked_add(m.weight));
        match total {
            Some(total) => Self::from_member_keys_with_total(slot, members, budget, total, mode),
            None => Self::from_member_keys_with_total(slot, Vec::new(), budget, 0, mode),
        }
    }

    pub fn from_member_keys_with_total(
        slot: u64,
        mut members: Vec<MemberKey>,
        budget: u64,
        total_weight: u64,
        mode: DrawMode,
    ) -> Self {
        members.sort_by_key(|m| m.id);
        members.dedup_by_key(|m| m.id);
        let mut keys: Vec<&[u8]> = members.iter().map(|m| &m.attest_pk[..]).collect();
        keys.sort_unstable();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            members.clear();
        }
        CommitteeCommitment {
            slot,
            total_weight,
            budget,
            members,
            absent_stake: 0,
            mode,
        }
    }

    pub fn from_view(
        slot: u64,
        view: &CommitteeView,
        committee: &Committee,
        attest_key: impl Fn(ValidatorId) -> Option<PublicKey>,
    ) -> Option<Self> {
        let mode = view.mode();
        let total = view.total_weight();
        let key_of = |id: ValidatorId| -> Option<MemberKey> {
            let reg = view.registration(id)?;
            Some(MemberKey {
                id,
                weight: view.effective_weight(reg.weight),
                stake: reg.weight,
                root: reg.root,
                attest_pk: attest_key(id)?,
            })
        };
        let members: Vec<MemberKey> = if mode == DrawMode::Full {
            view.eligible()
                .map(|r| key_of(r.id))
                .collect::<Option<Vec<_>>>()?
        } else {
            committee
                .members
                .iter()
                .map(|m| key_of(m.id))
                .collect::<Option<Vec<_>>>()?
        };
        let absent_stake = if mode == DrawMode::Full {
            0
        } else {
            let budget = u128::from(view.budget());
            let total_wide = u128::from(total);
            let expected: u128 = view
                .eligible()
                .map(|r| {
                    let weight = u128::from(view.effective_weight(r.weight));
                    if weight == 0 || total_wide == 0 {
                        0
                    } else if budget.saturating_mul(weight) >= total_wide {
                        u128::from(r.weight)
                    } else {
                        u128::from(r.weight).saturating_mul(budget.saturating_mul(weight))
                            / total_wide
                    }
                })
                .fold(0u128, u128::saturating_add);
            let realized: u128 = members
                .iter()
                .map(|m| u128::from(m.stake))
                .fold(0u128, u128::saturating_add);
            expected.saturating_sub(realized)
        };
        Some(
            Self::from_member_keys_with_total(slot, members, view.budget(), total, mode)
                .with_absent_stake(absent_stake),
        )
    }

    pub fn with_mode(mut self, mode: DrawMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_total_weight(mut self, total_weight: u64) -> Self {
        self.total_weight = total_weight;
        self
    }

    pub fn with_absent_stake(mut self, absent_stake: u128) -> Self {
        self.absent_stake = absent_stake;
        self
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn committee_weight(&self) -> u64 {
        self.members
            .iter()
            .map(|m| m.weight)
            .fold(0u64, u64::saturating_add)
    }

    pub fn weight_of(&self, id: ValidatorId) -> u64 {
        self.member(id).map(|m| m.weight).unwrap_or(0)
    }

    pub fn committee_stake(&self) -> u128 {
        self.members
            .iter()
            .map(|m| m.stake as u128)
            .fold(0u128, u128::saturating_add)
    }

    pub fn quorum_stake(&self) -> u128 {
        self.committee_stake().saturating_add(self.absent_stake)
    }

    pub fn stake_of(&self, id: ValidatorId) -> u64 {
        self.member(id).map(|m| m.stake).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn member(&self, id: ValidatorId) -> Option<&MemberKey> {
        self.members
            .binary_search_by_key(&id, |m| m.id)
            .ok()
            .map(|i| &self.members[i])
    }

    pub fn contains(&self, id: ValidatorId) -> bool {
        self.member(id).is_some()
    }

    pub fn digest(&self) -> CommitteeDigest {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"QORUS-ATTEST-COMMITTEE");
        buf.extend_from_slice(&self.slot.to_le_bytes());
        buf.extend_from_slice(&self.budget.to_le_bytes());
        buf.extend_from_slice(&self.total_weight.to_le_bytes());
        buf.extend_from_slice(&(self.members.len() as u64).to_le_bytes());
        for m in &self.members {
            buf.extend_from_slice(&m.id.to_le_bytes());
            buf.extend_from_slice(&m.weight.to_le_bytes());
            buf.extend_from_slice(&m.stake.to_le_bytes());
            buf.extend_from_slice(&m.root.digest);
            buf.extend_from_slice(&m.root.slots.to_le_bytes());
            buf.extend_from_slice(&m.attest_pk);
        }
        if self.absent_stake > 0 {
            buf.extend_from_slice(&self.absent_stake.to_le_bytes());
        }
        if self.mode != DrawMode::Unbound {
            buf.extend_from_slice(b"QORUS-ATTEST-DRAW");
            buf.push(self.mode.tag());
        }
        let mut out = [0u8; 32];
        shake256(&buf, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_are_held_in_ascending_id_order() {
        let a = Attester::new(3, 100);
        let b = Attester::new(1, 100);
        let c = Attester::new(2, 100);
        let commitment = CommitteeCommitment::from_attesters(0, &[&a, &b, &c]);
        assert_eq!(
            commitment.members.iter().map(|m| m.id).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(commitment.total_weight, 300);
        assert_eq!(commitment.len(), 3);
    }

    #[test]
    fn the_registered_total_overrides_the_drawn_member_sum_and_rebinds_the_digest() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let drawn = CommitteeCommitment::from_attesters(0, &[&a, &b]);
        assert_eq!(drawn.total_weight, 200);
        let registered = drawn.clone().with_total_weight(1_000);
        assert_eq!(registered.total_weight, 1_000);
        assert_ne!(
            drawn.digest(),
            registered.digest(),
            "the sortition denominator is bound into the committee digest"
        );
    }

    #[test]
    fn a_non_member_is_not_found() {
        let a = Attester::new(1, 100);
        let commitment = CommitteeCommitment::from_attesters(0, &[&a]);
        assert!(commitment.contains(1));
        assert!(!commitment.contains(2));
        assert!(commitment.member(2).is_none());
    }

    #[test]
    fn the_digest_changes_with_the_committee() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let one = CommitteeCommitment::from_attesters(0, &[&a]);
        let two = CommitteeCommitment::from_attesters(0, &[&a, &b]);
        let other_slot = CommitteeCommitment::from_attesters(1, &[&a]);
        assert_eq!(one.digest(), one.digest());
        assert_ne!(one.digest(), two.digest());
        assert_ne!(one.digest(), other_slot.digest());
    }
}
