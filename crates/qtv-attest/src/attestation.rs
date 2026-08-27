// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_bft::block::{Block, Height};
use qtv_bft::committee::View;
use qtv_bft::validator::{Validator, ValidatorId};
use qtv_crypto::ml_dsa::{verify, PublicKey, Signature};
use qtv_sampler::beacon::Beacon;
use qtv_sampler::onetime::Root;
use qtv_sampler::sortition::{verify_selection, Credential};

use crate::committee::CommitteeDigest;
use crate::params::{ATTEST_CONTEXT, DOMAIN_COMMITTEE};

pub fn attestation_message(
    chain_id: u64,
    height: Height,
    slot: u64,
    view: View,
    committee: &CommitteeDigest,
    block: &Block,
) -> Vec<u8> {
    // The chain id leads the preimage so an attestation, and therefore the certificate it joins, is
    // bound to the chain it was produced on. A verifier rebuilds the message with its own chain id, so
    // a certificate valid on one chain does not verify on another even when the validator keys are
    // shared across instances.
    let mut msg = Vec::with_capacity(8 + 24 + 33);
    msg.extend_from_slice(&chain_id.to_le_bytes());
    msg.extend_from_slice(&height.to_le_bytes());
    msg.extend_from_slice(&slot.to_le_bytes());
    msg.extend_from_slice(&view.to_le_bytes());
    msg.extend_from_slice(committee);
    msg.extend_from_slice(&block.to_bytes());
    msg
}

#[derive(Clone)]
pub struct Attestation {
    pub from: ValidatorId,
    pub height: Height,
    pub slot: u64,
    pub view: View,
    pub committee: CommitteeDigest,
    pub block: Block,
    pub membership: Credential,
    pub sig: Signature,
}

impl Attestation {
    pub fn create(
        signer: &Validator,
        chain_id: u64,
        height: Height,
        slot: u64,
        view: View,
        committee: CommitteeDigest,
        block: Block,
        membership: Credential,
    ) -> Self {
        let msg = attestation_message(chain_id, height, slot, view, &committee, &block);
        let sig = signer.sign(&msg, ATTEST_CONTEXT);
        Attestation {
            from: signer.id,
            height,
            slot,
            view,
            committee,
            block,
            membership,
            sig,
        }
    }

    pub fn signature_verifies(&self, chain_id: u64, attest_pk: &PublicKey) -> bool {
        let msg =
            attestation_message(chain_id, self.height, self.slot, self.view, &self.committee, &self.block);
        verify(attest_pk, &msg, &self.sig, ATTEST_CONTEXT)
    }

    pub fn is_entitled(
        &self,
        root: &Root,
        beacon: &Beacon,
        weight: u64,
        total: u64,
        budget: u64,
    ) -> bool {
        verify_selection(
            root,
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
    use qtv_sampler::validator::SamplerValidator;

    const SATURATING_BUDGET: u64 = 100;

    fn parts(id: u64, stake: u64) -> (Validator, SamplerValidator) {
        (Validator::new(id), SamplerValidator::new(id, stake))
    }

    #[test]
    fn a_signed_entitled_attestation_checks_on_both_facts() {
        let (signer, sampler) = parts(1, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [5u8; 32], Parent::Genesis);
        let membership = sampler.reveal(0);
        let att = Attestation::create(&signer, 1, 1, 0, 0, [0u8; 32], block, membership);

        assert!(att.signature_verifies(1, signer.public_key()));
        assert!(att.is_entitled(&sampler.root(), &beacon, 100, 100, SATURATING_BUDGET));
    }

    #[test]
    fn a_signature_under_the_wrong_key_is_rejected() {
        let (signer, sampler) = parts(1, 100);
        let other = Validator::new(2);
        let block = Block::new(1, [5u8; 32], Parent::Genesis);
        let membership = sampler.reveal(0);
        let att = Attestation::create(&signer, 1, 1, 0, 0, [0u8; 32], block, membership);
        assert!(!att.signature_verifies(1, other.public_key()));
    }

    #[test]
    fn a_tampered_block_breaks_the_signature() {
        let (signer, sampler) = parts(1, 100);
        let block = Block::new(1, [5u8; 32], Parent::Genesis);
        let membership = sampler.reveal(0);
        let mut att = Attestation::create(&signer, 1, 1, 0, 0, [0u8; 32], block, membership);
        att.block = Block::new(1, [6u8; 32], Parent::Genesis);
        assert!(!att.signature_verifies(1, signer.public_key()));
    }

    #[test]
    fn a_membership_credential_from_another_account_is_not_entitled() {
        let (signer, sampler) = parts(1, 100);
        let impostor = SamplerValidator::new(9, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [5u8; 32], Parent::Genesis);
        let membership = impostor.reveal(0);
        let att = Attestation::create(&signer, 1, 1, 0, 0, [0u8; 32], block, membership);
        assert!(!att.is_entitled(&sampler.root(), &beacon, 100, 100, SATURATING_BUDGET));
    }

    #[test]
    fn an_attestation_is_bound_to_its_chain_and_will_not_verify_under_another() {
        // The chain id is folded into the signed preimage, so an attestation, and the certificate it
        // joins, is valid only on its own chain, even when validator keys are shared across instances.
        let (signer, sampler) = parts(1, 100);
        let block = Block::new(1, [5u8; 32], Parent::Genesis);
        let membership = sampler.reveal(0);
        let chain_a = 7u64;
        let chain_b = 9u64;
        let att = Attestation::create(&signer, chain_a, 1, 0, 0, [0u8; 32], block, membership);
        assert!(
            att.signature_verifies(chain_a, signer.public_key()),
            "the attestation verifies on its own chain"
        );
        assert!(
            !att.signature_verifies(chain_b, signer.public_key()),
            "the same attestation does not verify on another chain"
        );
    }
}
