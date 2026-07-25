// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::sha3::shake256;

use crate::onetime::{OneTimeTree, Root};
use crate::sortition::Credential;
use crate::stake::Stake;

pub type ValidatorId = u64;

pub const DEFAULT_SLOTS: u64 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Validator,
    Prover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Honest,
    Offline,
}

// Domain tag under which a validator's secret is expanded into the seed of its one
// time sortition tree. It is distinct from the signing key domain in qtv-bft, so
// the one secret a validator holds yields two independent derived seeds and neither
// derived seed reveals the other or the secret.
const SORTITION_TREE_DOMAIN: &[u8] = b"QORUS/validator-keying/v1/sortition-tree";

/// Expand a validator's 32 byte secret into the seed of its one time sortition
pub fn sortition_tree_seed(secret: &[u8; 32]) -> [u8; 32] {
    const D: usize = SORTITION_TREE_DOMAIN.len();
    let mut buf = [0u8; D + 32];
    buf[..D].copy_from_slice(SORTITION_TREE_DOMAIN);
    buf[D..].copy_from_slice(secret);
    let mut out = [0u8; 32];
    shake256(&buf, &mut out);
    out
}

pub struct SamplerValidator {
    pub id: ValidatorId,
    pub role: Role,
    pub fault: Fault,
    stake: Stake,
    seed: [u8; 32],
    epoch: u64,
    tree: OneTimeTree,
}

impl Clone for SamplerValidator {
    fn clone(&self) -> Self {
        SamplerValidator {
            id: self.id,
            role: self.role,
            fault: self.fault,
            stake: self.stake,
            seed: self.seed,
            epoch: self.epoch,
            tree: OneTimeTree::new(
                crate::epoch::epoch_tree_seed(&self.seed, self.epoch),
                self.tree.slots(),
            ),
        }
    }
}

impl SamplerValidator {
    pub fn from_secret(id: ValidatorId, secret: &[u8; 32], stake: u64) -> Self {
        Self::from_secret_with_slots(id, secret, stake, DEFAULT_SLOTS)
    }

    pub fn from_secret_with_slots(
        id: ValidatorId,
        secret: &[u8; 32],
        stake: u64,
        slots: u64,
    ) -> Self {
        let seed = sortition_tree_seed(secret);
        SamplerValidator {
            id,
            role: Role::Validator,
            fault: Fault::Honest,
            stake: Stake::native(stake),
            seed,
            epoch: 0,
            tree: OneTimeTree::new(seed, slots),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn rotate_to(&self, epoch: u64) -> SamplerValidator {
        SamplerValidator {
            id: self.id,
            role: self.role,
            fault: self.fault,
            stake: self.stake,
            seed: self.seed,
            epoch,
            tree: OneTimeTree::new(
                crate::epoch::epoch_tree_seed(&self.seed, epoch),
                self.tree.slots(),
            ),
        }
    }

    pub fn from_secret_with_stake(id: ValidatorId, secret: &[u8; 32], stake: Stake) -> Self {
        let mut v = SamplerValidator::from_secret(id, secret, 0);
        v.stake = stake;
        v
    }

    pub fn prover_from_secret(id: ValidatorId, secret: &[u8; 32]) -> Self {
        let mut v = SamplerValidator::from_secret(id, secret, 0);
        v.role = Role::Prover;
        v
    }

    pub fn root(&self) -> Root {
        self.tree.root()
    }

    pub fn slots(&self) -> u64 {
        self.tree.slots()
    }

    pub fn stake(&self) -> Stake {
        self.stake
    }

    pub fn is_prover(&self) -> bool {
        self.role == Role::Prover
    }

    pub fn is_offline(&self) -> bool {
        self.fault == Fault::Offline
    }

    pub fn weight(&self) -> u64 {
        match self.role {
            Role::Prover => 0,
            Role::Validator => self.stake.weight(),
        }
    }

    pub fn reveal(&self, slot: u64) -> Credential {
        Credential {
            position: slot,
            preimage: self.tree.preimage(slot),
            path: self.tree.path(slot),
        }
    }

    pub fn reveal_out_of_position(&self, leaf_slot: u64, claim_slot: u64) -> Credential {
        Credential {
            position: claim_slot,
            preimage: self.tree.preimage(leaf_slot),
            path: self.tree.path(leaf_slot),
        }
    }
}

// Test and simulation fixtures. These construct a validator from a deterministic,
// per id seed so the test suite and the local devnet simulation are reproducible.
// They are compiled only under `cfg(test)` or the `test-fixtures` feature and are
// never part of a node binary: a production validator is always built from a real
// secret through `from_secret`, so no key material is ever derived from the public
// id on any running path.
#[cfg(any(test, feature = "test-fixtures"))]
const FIXTURE_SECRET_DOMAIN: &[u8] = b"QORUS/TEST-ONLY/insecure-fixture-secret/v1";

/// A deterministic, per id secret for tests and the devnet simulation only. This is
#[cfg(any(test, feature = "test-fixtures"))]
pub fn fixture_secret(id: ValidatorId) -> [u8; 32] {
    const D: usize = FIXTURE_SECRET_DOMAIN.len();
    let mut buf = [0u8; D + 8];
    buf[..D].copy_from_slice(FIXTURE_SECRET_DOMAIN);
    buf[D..].copy_from_slice(&id.to_le_bytes());
    let mut out = [0u8; 32];
    shake256(&buf, &mut out);
    out
}

#[cfg(any(test, feature = "test-fixtures"))]
impl SamplerValidator {
    pub fn new(id: ValidatorId, stake: u64) -> Self {
        Self::from_secret(id, &fixture_secret(id), stake)
    }

    pub fn with_slots(id: ValidatorId, stake: u64, slots: u64) -> Self {
        Self::from_secret_with_slots(id, &fixture_secret(id), stake, slots)
    }

    pub fn with_stake(id: ValidatorId, stake: Stake) -> Self {
        Self::from_secret_with_stake(id, &fixture_secret(id), stake)
    }

    pub fn prover(id: ValidatorId) -> Self {
        Self::prover_from_secret(id, &fixture_secret(id))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    pub id: ValidatorId,
    pub root: Root,
    pub weight: u64,
}

impl Registration {
    pub fn of(validator: &SamplerValidator) -> Self {
        Registration {
            id: validator.id,
            root: validator.root(),
            weight: validator.weight(),
        }
    }
}

#[cfg(test)]
pub fn forged_path(depth: usize) -> crate::onetime::MerklePath {
    crate::onetime::MerklePath {
        siblings: vec![[0u8; 32]; depth],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stake::{OriginTag, Stake};

    #[test]
    fn roots_are_deterministic_in_the_secret() {
        let secret = [7u8; 32];
        let a = SamplerValidator::from_secret(7, &secret, 2_000);
        let b = SamplerValidator::from_secret(7, &secret, 2_000);
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn two_secrets_commit_two_roots() {
        let a = SamplerValidator::from_secret(7, &[1u8; 32], 2_000);
        let b = SamplerValidator::from_secret(7, &[2u8; 32], 2_000);
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn the_tree_seed_is_not_the_secret() {
        let secret = [9u8; 32];
        assert_ne!(sortition_tree_seed(&secret), secret);
    }

    #[test]
    fn a_clone_commits_the_same_root_and_reveals() {
        let a = SamplerValidator::from_secret(3, &[3u8; 32], 2_000);
        let b = a.clone();
        assert_eq!(a.root(), b.root());
        assert_eq!(a.reveal(4), b.reveal(4));
    }

    #[test]
    fn prover_weighs_zero() {
        let p = SamplerValidator::prover_from_secret(9, &[9u8; 32]);
        assert!(p.is_prover());
        assert_eq!(p.weight(), 0);
    }

    #[test]
    fn bridged_holding_weighs_zero() {
        let tag = OriginTag { chain: 1, asset: 1 };
        let v = SamplerValidator::from_secret_with_stake(3, &[3u8; 32], Stake::bridged(1_000_000, tag));
        assert_eq!(v.weight(), 0);
    }

    #[test]
    fn offline_validator_keeps_its_weight_and_candidacy() {
        let mut v = SamplerValidator::from_secret(2, &[2u8; 32], 2_000);
        v.fault = Fault::Offline;
        assert!(v.is_offline());
        assert_eq!(v.weight(), 2_000);
    }

    #[test]
    fn a_reveal_authenticates_to_the_registered_root() {
        let v = SamplerValidator::from_secret(1, &[1u8; 32], 100);
        let reg = Registration::of(&v);
        let cred = v.reveal(5);
        assert!(reg.root.verify_membership(5, &cred.preimage, &cred.path));
    }

    #[test]
    fn rotation_commits_a_fresh_root_each_epoch() {
        let base = SamplerValidator::from_secret(1, &[1u8; 32], 100);
        let one = base.rotate_to(1);
        let two = base.rotate_to(2);
        assert_eq!(base.epoch(), 0);
        assert_eq!(one.epoch(), 1);
        assert_ne!(base.root(), one.root());
        assert_ne!(one.root(), two.root());
        assert_eq!(one.root(), base.rotate_to(1).root());
    }

    #[test]
    fn rotated_reveals_carry_the_committee_past_the_old_fixed_ceiling() {
        let epoch_len = 8u64;
        let slots = epoch_len;
        let old_ceiling = crate::validator::DEFAULT_SLOTS;
        let base = SamplerValidator::from_secret_with_slots(1, &[3u8; 32], 100, slots);
        let mut highest = 0u64;
        for height in 0..(old_ceiling + slots + 4) {
            let epoch = crate::epoch::epoch_of(height, epoch_len);
            let slot = crate::epoch::slot_in_epoch(height, epoch_len);
            let rotated = base.rotate_to(epoch);
            let reg = Registration::of(&rotated);
            let cred = rotated.reveal(slot);
            assert!(
                reg.root.verify_membership(slot, &cred.preimage, &cred.path),
                "the rotated reveal failed to authenticate at height {height}"
            );
            highest = height;
        }
        assert!(
            highest > old_ceiling,
            "the run did not pass the old fixed slot ceiling"
        );
    }
}
