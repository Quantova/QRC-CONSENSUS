//! An attester is a committee candidate that holds both consensus keys: the
//! module lattice signing key that authenticates its attestation and the
//! verifiable random key that proves its committee entitlement. Composing the
//! stage one validator and the sampler validator keeps one identity behind both
//! the signature and the sortition proof, so an attestation and its entitlement
//! proof always speak for the same key.

use qtv_bft::block::{Block, Height};
use qtv_bft::validator::Validator;
use qtv_crypto::ml_dsa::PublicKey;
use qtv_sampler::beacon::Beacon;
use qtv_sampler::onetime::Root;
use qtv_sampler::validator::SamplerValidator;

use crate::attestation::Attestation;

pub use qtv_bft::validator::ValidatorId;

/// A committee candidate holding a module lattice key pair and a verifiable
/// random key pair, both derived deterministically from its id.
pub struct Attester {
    signer: Validator,
    sampler: SamplerValidator,
}

impl Attester {
    /// An attester for `id` with `stake` native weight, over the default slot count.
    pub fn new(id: ValidatorId, stake: u64) -> Self {
        Attester {
            signer: Validator::new(id),
            sampler: SamplerValidator::new(id, stake),
        }
    }

    /// An attester over an explicit one time slot count. The default constructor
    /// sizes the tree at the sampler default, which is deliberately small; a real
    /// chain sizes the slot count against the bonding period separately and far
    /// larger, and a driver that needs to finalise more heights than the default
    /// serves asks for the count it needs here. The tree build, the credential
    /// Merkle path, and the certificate verification all follow the count, with the
    /// path depth growing as the log of it, so the whole draw and verify path holds
    /// at any count the caller requests.
    pub fn with_slots(id: ValidatorId, stake: u64, slots: u64) -> Self {
        Attester {
            signer: Validator::new(id),
            sampler: SamplerValidator::with_slots(id, stake, slots),
        }
    }

    /// A prover holds no vote and no stake, so it weighs zero and is never
    /// entitled. It keeps a module lattice key only to show a signature alone
    /// never buys committee entitlement.
    pub fn prover(id: ValidatorId) -> Self {
        Attester {
            signer: Validator::new(id),
            sampler: SamplerValidator::prover(id),
        }
    }

    pub fn id(&self) -> ValidatorId {
        self.signer.id
    }

    /// The native weight this attester brings to sortition.
    pub fn weight(&self) -> u64 {
        self.sampler.weight()
    }

    /// The module lattice public key its attestation signature is checked under.
    pub fn attest_public_key(&self) -> &PublicKey {
        self.signer.public_key()
    }

    /// The committed one time root its committee entitlement is checked against.
    pub fn root(&self) -> Root {
        self.sampler.root()
    }

    /// Attest a block at a height and slot. The attestation carries the committee
    /// membership credential, the account's one time reveal for the slot, and the
    /// module lattice signature over the canonical message, tying entitlement to
    /// the signature under one identity. The reveal is a fixed function of the
    /// slot, so the beacon is not needed to produce it; the beacon binds the output
    /// at verification, where entitlement is checked.
    pub fn attest(&self, height: Height, slot: u64, block: Block, beacon: &Beacon) -> Attestation {
        let _ = beacon;
        let membership = self.sampler.reveal(slot);
        Attestation::create(&self.signer, height, slot, block, membership)
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
        let block = Block::new(1, 7, Parent::Genesis);
        let att = a.attest(1, 0, block, &beacon);
        assert_eq!(att.from, a.id());
        assert!(att.signature_verifies(a.attest_public_key()));
        assert!(att.is_entitled(&a.root(), &beacon, a.weight(), a.weight(), 100));
    }

    #[test]
    fn with_slots_attests_at_a_slot_beyond_the_default() {
        // A tree sized well above the default serves a slot past the default count.
        // The whole path holds: the tree builds to the requested count, the reveal
        // authenticates through a deeper Merkle path, and entitlement checks below
        // the stake weighted threshold.
        let slots = 4096;
        let a = Attester::with_slots(1, 100, slots);
        let beacon = Beacon::genesis();
        let block = Block::new(1, 7, Parent::Genesis);
        let slot = 4000;
        let att = a.attest(1, slot, block, &beacon);
        // The authentication path is the log of the padded leaf count, twelve here.
        assert_eq!(att.membership.path.siblings.len(), 12);
        assert!(att.signature_verifies(a.attest_public_key()));
        assert!(att.is_entitled(&a.root(), &beacon, a.weight(), a.weight(), 100));
    }

    #[test]
    fn a_prover_weighs_zero_and_is_never_entitled() {
        let p = Attester::prover(9);
        let beacon = Beacon::genesis();
        let block = Block::new(1, 7, Parent::Genesis);
        let att = p.attest(1, 0, block, &beacon);
        assert_eq!(p.weight(), 0);
        // The signature is genuine, yet zero weight means no passing entitlement.
        assert!(att.signature_verifies(p.attest_public_key()));
        assert!(!att.is_entitled(&p.root(), &beacon, 0, 100, 100));
    }
}
