//! Attestation with a real module lattice signature. A committee member signs

use core::fmt;

use qtv_crypto::ml_dsa::{verify, PublicKey, Signature};

use crate::block::{Block, Height};
use crate::validator::{Validator, ValidatorId};

/// Domain separation context for consensus attestations.
pub const ATTEST_CONTEXT: &[u8] = b"QORUS-STAGE1-ATTEST";

/// The message a validator signs to attest a block at a height. It binds the
pub fn attestation_message(height: Height, block: &Block) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 33);
    msg.extend_from_slice(&height.to_le_bytes());
    msg.extend_from_slice(&block.to_bytes());
    msg
}

/// A signed attestation from one validator for one block at one height.
#[derive(Clone, PartialEq, Eq)]
pub struct Attestation {
    pub from: ValidatorId,
    pub height: Height,
    pub block: Block,
    pub sig: Signature,
}

impl Attestation {
    /// Produce an attestation by signing the block with the validator ML-DSA
    pub fn create(validator: &Validator, height: Height, block: Block) -> Self {
        let msg = attestation_message(height, &block);
        let sig = validator.sign(&msg, ATTEST_CONTEXT);
        Attestation {
            from: validator.id,
            height,
            block,
            sig,
        }
    }

    /// Verify the attestation signature against a public key. Returns false for
    pub fn verify(&self, public_key: &PublicKey) -> bool {
        let msg = attestation_message(self.height, &self.block);
        verify(public_key, &msg, &self.sig, ATTEST_CONTEXT)
    }
}

impl fmt::Debug for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attestation")
            .field("from", &self.from)
            .field("height", &self.height)
            .field("block", &self.block)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Parent;

    #[test]
    fn real_attestation_verifies() {
        let v = Validator::new(1);
        let block = Block::new(1, [5u8; 32], Parent::Genesis);
        let att = Attestation::create(&v, 1, block);
        assert!(att.verify(v.public_key()));
    }

    #[test]
    fn attestation_under_wrong_key_is_rejected() {
        let signer = Validator::new(1);
        let other = Validator::new(2);
        let block = Block::new(1, [5u8; 32], Parent::Genesis);
        let att = Attestation::create(&signer, 1, block);
        assert!(!att.verify(other.public_key()));
    }

    #[test]
    fn tampered_block_breaks_the_attestation() {
        let v = Validator::new(1);
        let block = Block::new(1, [5u8; 32], Parent::Genesis);
        let mut att = Attestation::create(&v, 1, block);
        att.block = Block::new(1, [6u8; 32], Parent::Genesis);
        assert!(!att.verify(v.public_key()));
    }

    #[test]
    fn forged_signature_bytes_are_rejected() {
        let v = Validator::new(1);
        let block = Block::new(1, [5u8; 32], Parent::Genesis);
        let mut att = Attestation::create(&v, 1, block);
        att.sig[0] ^= 255;
        assert!(!att.verify(v.public_key()));
    }
}
