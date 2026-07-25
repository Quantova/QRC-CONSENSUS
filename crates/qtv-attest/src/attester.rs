// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_bft::block::{Block, Height};
use qtv_bft::committee::View;
use qtv_bft::validator::Validator;
use qtv_crypto::ml_dsa::{verify, PublicKey, Signature};
use qtv_sampler::beacon::Beacon;
use qtv_sampler::onetime::Root;
use qtv_sampler::validator::SamplerValidator;

use crate::attestation::Attestation;

pub use qtv_bft::validator::ValidatorId;

pub const EPOCH_REG_CONTEXT: &[u8] = b"QORUS-EPOCH-REGISTER";

pub fn epoch_registration_message(id: ValidatorId, epoch: u64, root: &Root) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 8 + 32 + 8);
    msg.extend_from_slice(&id.to_le_bytes());
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(&root.digest);
    msg.extend_from_slice(&root.slots.to_le_bytes());
    msg
}

pub fn epoch_registration_verifies(
    attest_pk: &PublicKey,
    id: ValidatorId,
    epoch: u64,
    root: &Root,
    sig: &Signature,
) -> bool {
    let msg = epoch_registration_message(id, epoch, root);
    verify(attest_pk, &msg, sig, EPOCH_REG_CONTEXT)
}

/// A validator that attests. It holds one high entropy secret and derives from it,
/// under two distinct domains, both the ML-DSA-65 signing key it signs with and the
/// one time sortition tree it reveals membership from. The secret never leaves the
/// attester; only the commitments, the signing public key and the sortition Merkle
/// root, are published at registration.
pub struct Attester {
    signer: Validator,
    sampler: SamplerValidator,
}

impl Attester {
    pub fn from_secret(id: ValidatorId, secret: &[u8; 32], stake: u64) -> Self {
        Attester {
            signer: Validator::from_secret(id, secret),
            sampler: SamplerValidator::from_secret(id, secret, stake),
        }
    }

    pub fn from_secret_with_slots(
        id: ValidatorId,
        secret: &[u8; 32],
        stake: u64,
        slots: u64,
    ) -> Self {
        Attester {
            signer: Validator::from_secret(id, secret),
            sampler: SamplerValidator::from_secret_with_slots(id, secret, stake, slots),
        }
    }

    pub fn prover_from_secret(id: ValidatorId, secret: &[u8; 32]) -> Self {
        Attester {
            signer: Validator::prover_from_secret(id, secret),
            sampler: SamplerValidator::prover_from_secret(id, secret),
        }
    }

    pub fn at_epoch(&self, epoch: u64) -> Self {
        Attester {
            signer: self.signer.clone(),
            sampler: self.sampler.rotate_to(epoch),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.sampler.epoch()
    }

    pub fn epoch_registration(&self, epoch: u64) -> (Root, Signature) {
        let root = self.sampler.rotate_to(epoch).root();
        let msg = epoch_registration_message(self.id(), epoch, &root);
        let sig = self.signer.sign(&msg, EPOCH_REG_CONTEXT);
        (root, sig)
    }

    pub fn id(&self) -> ValidatorId {
        self.signer.id
    }

    pub fn weight(&self) -> u64 {
        self.sampler.weight()
    }

    pub fn attest_public_key(&self) -> &PublicKey {
        self.signer.public_key()
    }

    pub fn root(&self) -> Root {
        self.sampler.root()
    }

    /// The attester's own sortition reveal for a slot.
    pub fn reveal(&self, slot: u64) -> qtv_sampler::sortition::Credential {
        self.sampler.reveal(slot)
    }

    pub fn attest(
        &self,
        height: Height,
        slot: u64,
        view: View,
        block: Block,
        beacon: &Beacon,
    ) -> Attestation {
        let _ = beacon;
        let membership = self.sampler.reveal(slot);
        Attestation::create(&self.signer, height, slot, view, block, membership)
    }
}

// Test and simulation fixtures. An attester built here derives its one secret from a
// deterministic, per id seed so the test suite and the local devnet simulation are
// reproducible. They are compiled only under `cfg(test)` or the `test-fixtures`
// feature and are never part of a node binary: a production attester is always built
// from a real secret through `from_secret`, so neither its signing key nor its
// sortition tree is ever derived from the public id on any running path.
#[cfg(any(test, feature = "test-fixtures"))]
const FIXTURE_SECRET_DOMAIN: &[u8] = b"QORUS/TEST-ONLY/insecure-fixture-secret/v1";

/// A deterministic, per id secret for tests and the devnet simulation only, shared
/// across the consensus crates so a given id maps to one secret everywhere. This is
/// the "fixed test seed" the security work permits inside tests; it is not a
/// production derivation and cannot be reached from a node binary.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn fixture_secret(id: ValidatorId) -> [u8; 32] {
    const D: usize = FIXTURE_SECRET_DOMAIN.len();
    let mut buf = [0u8; D + 8];
    buf[..D].copy_from_slice(FIXTURE_SECRET_DOMAIN);
    buf[D..].copy_from_slice(&id.to_le_bytes());
    let mut out = [0u8; 32];
    qtv_crypto::sha3::shake256(&buf, &mut out);
    out
}

#[cfg(any(test, feature = "test-fixtures"))]
impl Attester {
    pub fn new(id: ValidatorId, stake: u64) -> Self {
        Self::from_secret(id, &fixture_secret(id), stake)
    }

    pub fn with_slots(id: ValidatorId, stake: u64, slots: u64) -> Self {
        Self::from_secret_with_slots(id, &fixture_secret(id), stake, slots)
    }

    pub fn prover(id: ValidatorId) -> Self {
        Self::prover_from_secret(id, &fixture_secret(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtv_bft::block::Parent;

    #[test]
    fn an_attester_attests_under_one_identity() {
        let a = Attester::new(1, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [7u8; 32], Parent::Genesis);
        let att = a.attest(1, 0, 0, block, &beacon);
        assert_eq!(att.from, a.id());
        assert!(att.signature_verifies(a.attest_public_key()));
        assert!(att.is_entitled(&a.root(), &beacon, a.weight(), a.weight(), 100));
    }

    #[test]
    fn one_secret_drives_the_signing_key_and_the_sortition_tree() {
        let secret = [42u8; 32];
        let a = Attester::from_secret(1, &secret, 100);
        let b = Attester::from_secret(1, &secret, 100);
        // The one secret reproduces both commitments exactly.
        assert_eq!(a.attest_public_key(), b.attest_public_key());
        assert_eq!(a.root(), b.root());
        // A different secret moves both commitments.
        let c = Attester::from_secret(1, &[43u8; 32], 100);
        assert_ne!(a.attest_public_key(), c.attest_public_key());
        assert_ne!(a.root(), c.root());
    }

    #[test]
    fn with_slots_attests_at_a_slot_beyond_the_default() {
        let slots = 4096;
        let a = Attester::with_slots(1, 100, slots);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [7u8; 32], Parent::Genesis);
        let slot = 4000;
        let att = a.attest(1, slot, 0, block, &beacon);
        assert_eq!(att.membership.path.siblings.len(), 12);
        assert!(att.signature_verifies(a.attest_public_key()));
        assert!(att.is_entitled(&a.root(), &beacon, a.weight(), a.weight(), 100));
    }

    #[test]
    fn an_epoch_registration_authenticates_the_rotated_root_to_the_stable_key() {
        let a = Attester::new(1, 100);
        let (root, sig) = a.epoch_registration(3);
        assert_eq!(root, a.at_epoch(3).root());
        assert_ne!(root, a.root(), "the rotated root differs from the genesis root");
        assert!(epoch_registration_verifies(
            a.attest_public_key(),
            a.id(),
            3,
            &root,
            &sig
        ));
        assert!(
            !epoch_registration_verifies(a.attest_public_key(), a.id(), 4, &root, &sig),
            "the signature does not carry to another epoch"
        );
        let other = Attester::new(2, 100);
        assert!(
            !epoch_registration_verifies(other.attest_public_key(), a.id(), 3, &root, &sig),
            "another key does not verify the registration"
        );
    }

    #[test]
    fn a_prover_weighs_zero_and_is_never_entitled() {
        let p = Attester::prover(9);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [7u8; 32], Parent::Genesis);
        let att = p.attest(1, 0, 0, block, &beacon);
        assert_eq!(p.weight(), 0);
        assert!(att.signature_verifies(p.attest_public_key()));
        assert!(!att.is_entitled(&p.root(), &beacon, 0, 100, 100));
    }
}
