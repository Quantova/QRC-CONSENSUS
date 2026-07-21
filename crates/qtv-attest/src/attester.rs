use qtv_bft::block::{Block, Height};
use qtv_bft::validator::Validator;
use qtv_crypto::ml_dsa::PublicKey;
use qtv_sampler::beacon::Beacon;
use qtv_sampler::onetime::Root;
use qtv_sampler::validator::SamplerValidator;

use crate::attestation::Attestation;

pub use qtv_bft::validator::ValidatorId;

pub struct Attester {
    signer: Validator,
    sampler: SamplerValidator,
}

impl Attester {
    pub fn new(id: ValidatorId, stake: u64) -> Self {
        Attester {
            signer: Validator::new(id),
            sampler: SamplerValidator::new(id, stake),
        }
    }

    pub fn with_slots(id: ValidatorId, stake: u64, slots: u64) -> Self {
        Attester {
            signer: Validator::new(id),
            sampler: SamplerValidator::with_slots(id, stake, slots),
        }
    }

    pub fn prover(id: ValidatorId) -> Self {
        Attester {
            signer: Validator::new(id),
            sampler: SamplerValidator::prover(id),
        }
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
        let block = Block::new(1, [7u8; 32], Parent::Genesis);
        let att = a.attest(1, 0, block, &beacon);
        assert_eq!(att.from, a.id());
        assert!(att.signature_verifies(a.attest_public_key()));
        assert!(att.is_entitled(&a.root(), &beacon, a.weight(), a.weight(), 100));
    }

    #[test]
    fn with_slots_attests_at_a_slot_beyond_the_default() {
        let slots = 4096;
        let a = Attester::with_slots(1, 100, slots);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [7u8; 32], Parent::Genesis);
        let slot = 4000;
        let att = a.attest(1, slot, block, &beacon);
        assert_eq!(att.membership.path.siblings.len(), 12);
        assert!(att.signature_verifies(a.attest_public_key()));
        assert!(att.is_entitled(&a.root(), &beacon, a.weight(), a.weight(), 100));
    }

    #[test]
    fn a_prover_weighs_zero_and_is_never_entitled() {
        let p = Attester::prover(9);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [7u8; 32], Parent::Genesis);
        let att = p.attest(1, 0, block, &beacon);
        assert_eq!(p.weight(), 0);
        assert!(att.signature_verifies(p.attest_public_key()));
        assert!(!att.is_entitled(&p.root(), &beacon, 0, 100, 100));
    }
}
