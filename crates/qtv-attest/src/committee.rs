use qtv_crypto::ml_dsa::PublicKey;
use qtv_crypto::sha3::shake256;
use qtv_sampler::onetime::Root;

use crate::attester::{Attester, ValidatorId};
use crate::params::COMMITTEE_BUDGET;

pub type CommitteeDigest = [u8; 32];

#[derive(Clone)]
pub struct MemberKey {
    pub id: ValidatorId,
    pub weight: u64,
    pub root: Root,
    pub attest_pk: PublicKey,
}

#[derive(Clone)]
pub struct CommitteeCommitment {
    pub slot: u64,
    pub total_weight: u64,
    pub budget: u64,
    pub members: Vec<MemberKey>,
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
                root: a.root(),
                attest_pk: *a.attest_public_key(),
            })
            .collect();
        Self::from_member_keys(slot, members, budget)
    }

    /// Build the committee commitment from the public member keys, each a validator's
    /// id, stake weight, sortition root, and attestation public key.
    pub fn from_member_keys(slot: u64, mut members: Vec<MemberKey>, budget: u64) -> Self {
        members.sort_by_key(|m| m.id);
        let total_weight = members.iter().map(|m| m.weight).sum();
        CommitteeCommitment {
            slot,
            total_weight,
            budget,
            members,
        }
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn member(&self, id: ValidatorId) -> Option<&MemberKey> {
        self.members.iter().find(|m| m.id == id)
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
            buf.extend_from_slice(&m.root.digest);
            buf.extend_from_slice(&m.root.slots.to_le_bytes());
            buf.extend_from_slice(&m.attest_pk);
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
