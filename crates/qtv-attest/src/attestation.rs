//! The canonical certificate attestation. It binds the height, the slot, the
//! full block, the committee membership proof, and the module lattice signature
//! into one authenticated fact. The membership proof is the sampler draw that
//! shows the signer was entitled to the committee for the slot, so an
//! attestation counts only when the same key both proved entitlement through the
//! sampler and signed the block with ML-DSA.

use qtv_bft::block::{Block, Height};
use qtv_bft::validator::{Validator, ValidatorId};
use qtv_crypto::ml_dsa::{verify, PublicKey, Signature};
use qtv_crypto::vrf_mldsa::PUBLIC_KEY_BYTES;
use qtv_sampler::beacon::Beacon;
use qtv_sampler::sortition::{verify_selection, Draw};

use crate::params::{ATTEST_CONTEXT, DOMAIN_COMMITTEE};

/// The message a signer binds: the height, the slot, and the full block bytes.
/// Binding the slot stops an attestation being replayed at another slot, and
/// binding the block stops it being replayed for another block.
pub fn attestation_message(height: Height, slot: u64, block: &Block) -> Vec<u8> {
    let mut msg = Vec::with_capacity(16 + 33);
    msg.extend_from_slice(&height.to_le_bytes());
    msg.extend_from_slice(&slot.to_le_bytes());
    msg.extend_from_slice(&block.to_bytes());
    msg
}

/// A signed attestation from one entitled committee member for one block at one
/// height and slot. It carries the sampler membership draw and the module
/// lattice signature, the two facts a verifier checks independently.
#[derive(Clone)]
pub struct Attestation {
    pub from: ValidatorId,
    pub height: Height,
    pub slot: u64,
    pub block: Block,
    pub membership: Draw,
    pub sig: Signature,
}

impl Attestation {
    /// Produce an attestation by signing the block with the signer module
    /// lattice key and carrying the given committee membership draw. Signing is
    /// deterministic, so an attestation is reproducible from the same inputs.
    pub fn create(
        signer: &Validator,
        height: Height,
        slot: u64,
        block: Block,
        membership: Draw,
    ) -> Self {
        let msg = attestation_message(height, slot, &block);
        let sig = signer.sign(&msg, ATTEST_CONTEXT);
        Attestation {
            from: signer.id,
            height,
            slot,
            block,
            membership,
            sig,
        }
    }

    /// True when the module lattice signature verifies under the attester public
    /// key. This authenticates the fact; entitlement is a separate check. Returns
    /// false for any forged or tampered signature or block.
    pub fn signature_verifies(&self, attest_pk: &PublicKey) -> bool {
        let msg = attestation_message(self.height, self.slot, &self.block);
        verify(attest_pk, &msg, &self.sig, ATTEST_CONTEXT)
    }

    /// True when the membership draw proves the signer was an entitled committee
    /// member for the slot: the draw verifies under the verifiable random key and
    /// its output falls below the signer stake weighted threshold. A prover and a
    /// bridged holding weigh zero, so neither is ever entitled.
    pub fn is_entitled(
        &self,
        vrf_pk: &[u8; PUBLIC_KEY_BYTES],
        beacon: &Beacon,
        weight: u64,
        total: u64,
        budget: u64,
    ) -> bool {
        verify_selection(
            vrf_pk,
            beacon,
            DOMAIN_COMMITTEE,
            self.slot,
            weight,
            total,
            budget,
            &self.membership,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qtv_bft::block::Parent;
    use qtv_sampler::sortition::draw;
    use qtv_sampler::validator::SamplerValidator;

    // A budget that saturates a single validator's whole stake share, so a valid
    // draw is always below threshold and the member is entitled.
    const SATURATING_BUDGET: u64 = 100;

    fn parts(id: u64, stake: u64) -> (Validator, SamplerValidator) {
        (Validator::new(id), SamplerValidator::new(id, stake))
    }

    #[test]
    fn a_signed_entitled_attestation_checks_on_both_facts() {
        let (signer, sampler) = parts(1, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, 5, Parent::Genesis);
        let membership = draw(&sampler, &beacon, DOMAIN_COMMITTEE, 0);
        let att = Attestation::create(&signer, 1, 0, block, membership);

        assert!(att.signature_verifies(signer.public_key()));
        assert!(att.is_entitled(sampler.public_key(), &beacon, 100, 100, SATURATING_BUDGET));
    }

    #[test]
    fn a_signature_under_the_wrong_key_is_rejected() {
        let (signer, sampler) = parts(1, 100);
        let other = Validator::new(2);
        let beacon = Beacon::genesis();
        let block = Block::new(1, 5, Parent::Genesis);
        let membership = draw(&sampler, &beacon, DOMAIN_COMMITTEE, 0);
        let att = Attestation::create(&signer, 1, 0, block, membership);
        assert!(!att.signature_verifies(other.public_key()));
    }

    #[test]
    fn a_tampered_block_breaks_the_signature() {
        let (signer, sampler) = parts(1, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, 5, Parent::Genesis);
        let membership = draw(&sampler, &beacon, DOMAIN_COMMITTEE, 0);
        let mut att = Attestation::create(&signer, 1, 0, block, membership);
        att.block = Block::new(1, 6, Parent::Genesis);
        assert!(!att.signature_verifies(signer.public_key()));
    }

    #[test]
    fn a_membership_draw_from_another_key_is_not_entitled() {
        let (signer, sampler) = parts(1, 100);
        let impostor = SamplerValidator::new(9, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, 5, Parent::Genesis);
        // Draw with the impostor key but sign with the real signer key.
        let membership = draw(&impostor, &beacon, DOMAIN_COMMITTEE, 0);
        let att = Attestation::create(&signer, 1, 0, block, membership);
        // The draw does not verify under the signer's own verifiable random key.
        assert!(!att.is_entitled(sampler.public_key(), &beacon, 100, 100, SATURATING_BUDGET));
    }
}
