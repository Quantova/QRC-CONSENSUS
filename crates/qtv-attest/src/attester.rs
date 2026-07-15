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
    /// An attester for `id` with `stake` native weight.
    pub fn new(id: ValidatorId, stake: u64) -> Self {
        Attester {
            signer: Validator::new(id),
            sampler: SamplerValidator::new(id, stake),
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
