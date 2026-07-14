//! An attester is a committee candidate that holds both consensus keys: the
//! module lattice signing key that authenticates its attestation and the
//! verifiable random key that proves its committee entitlement. Composing the
//! stage one validator and the sampler validator keeps one identity behind both
//! the signature and the sortition proof, so an attestation and its entitlement
//! proof always speak for the same key.

use qtv_bft::block::{Block, Height};
use qtv_bft::validator::Validator;
use qtv_crypto::ml_dsa::PublicKey;
use qtv_crypto::vrf::PUBLIC_KEY_BYTES;
use qtv_sampler::beacon::Beacon;
use qtv_sampler::sortition::draw;
use qtv_sampler::validator::SamplerValidator;

use crate::attestation::Attestation;
use crate::params::DOMAIN_COMMITTEE;

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

    /// The verifiable random public key its committee entitlement is checked
    /// under.
    pub fn vrf_public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        self.sampler.public_key()
    }

    /// Attest a block at a height and slot. The attestation carries the committee
    /// membership draw over the beacon and the module lattice signature over the
    /// canonical message, tying entitlement to the signature under one key.
    pub fn attest(&self, height: Height, slot: u64, block: Block, beacon: &Beacon) -> Attestation {
        let membership = draw(&self.sampler, beacon, DOMAIN_COMMITTEE, slot);
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
        assert!(att.is_entitled(a.vrf_public_key(), &beacon, a.weight(), a.weight(), 100));
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
        assert!(!att.is_entitled(p.vrf_public_key(), &beacon, 0, 100, 100));
    }
}
