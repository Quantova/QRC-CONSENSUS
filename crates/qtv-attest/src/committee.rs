//! The committee commitment. It is the public record of the entitled committee
//! for a slot: each member id with its verifiable random key, its module lattice
//! key, and its native weight, together with the total weight and the committee
//! budget. A light client is given this commitment and the beacon, and needs no
//! secret to recheck entitlement or a signature.
//!
//! The commitment folds into a single digest that the certificate envelope
//! carries, so a stage one body and a stage two body over the same envelope are
//! bound to the same committee. Reproducing the commitment from the beacon is the
//! sampler's job; this layer only commits to it and verifies against it.

use qtv_crypto::ml_dsa::PublicKey;
use qtv_crypto::sha3::shake256;
use qtv_crypto::vrf_mldsa::PUBLIC_KEY_BYTES;

use crate::attester::{Attester, ValidatorId};
use crate::params::COMMITTEE_BUDGET;

/// A 32 byte commitment to the committee for a slot.
pub type CommitteeDigest = [u8; 32];

/// The public keys and weight of one committee member.
#[derive(Clone)]
pub struct MemberKey {
    pub id: ValidatorId,
    pub weight: u64,
    pub vrf_pk: [u8; PUBLIC_KEY_BYTES],
    pub attest_pk: PublicKey,
}

/// The committee for a slot, with the total weight and budget that the stake
/// weighted entitlement check reads. Members are held in ascending id order.
#[derive(Clone)]
pub struct CommitteeCommitment {
    pub slot: u64,
    pub total_weight: u64,
    pub budget: u64,
    pub members: Vec<MemberKey>,
}

impl CommitteeCommitment {
    /// Commit to the given attesters as the committee for a slot, using the
    /// protocol committee budget. The total weight is the sum of the member
    /// weights, the denominator the entitlement threshold is taken against.
    pub fn from_attesters(slot: u64, attesters: &[&Attester]) -> Self {
        Self::from_attesters_with_budget(slot, attesters, COMMITTEE_BUDGET)
    }

    /// Commit to the given attesters under an explicit budget, used to size small
    /// committees in tests.
    pub fn from_attesters_with_budget(slot: u64, attesters: &[&Attester], budget: u64) -> Self {
        let mut members: Vec<MemberKey> = attesters
            .iter()
            .map(|a| MemberKey {
                id: a.id(),
                weight: a.weight(),
                vrf_pk: *a.vrf_public_key(),
                attest_pk: *a.attest_public_key(),
            })
            .collect();
        members.sort_by_key(|m| m.id);
        let total_weight = members.iter().map(|m| m.weight).sum();
        CommitteeCommitment {
            slot,
            total_weight,
            budget,
            members,
        }
    }

    /// The number of committee members, the denominator of the supermajority.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The member record for an id, or None when the id is not on the committee.
    pub fn member(&self, id: ValidatorId) -> Option<&MemberKey> {
        self.members.iter().find(|m| m.id == id)
    }

    pub fn contains(&self, id: ValidatorId) -> bool {
        self.member(id).is_some()
    }

    /// The commitment digest carried by the envelope. It folds the slot, budget,
    /// total weight, and every member id, weight, and public key in id order, so
    /// any change to the committee changes the digest.
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
            buf.extend_from_slice(&m.vrf_pk);
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
