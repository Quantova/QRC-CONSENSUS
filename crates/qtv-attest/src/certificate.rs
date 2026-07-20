//! The finality certificate. A certificate is an envelope and the aggregated module lattice
//! attestations of the entitled supermajority. The envelope fixes the subject, the height, the slot,
//! the block, and the digest of the committee commitment. The body is the attestations in ascending
//! signer id order, so the certificate is canonical regardless of the order they arrived in.
//!
//! The certificate is module lattice only, per the frozen consensus decision, and it carries the
//! signatures directly. There is no succinct or proof based stage, and no classical or non finalised
//! cryptography anywhere in it.

use qtv_crypto::sha3::shake256;

use qtv_bft::block::{Block, Height};

use crate::attestation::Attestation;
use crate::attester::ValidatorId;
use crate::committee::{CommitteeCommitment, CommitteeDigest};

/// The shared certificate envelope, the subject a certificate binds to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub height: Height,
    pub slot: u64,
    pub block: Block,
    pub committee: CommitteeDigest,
}

impl Envelope {
    /// The envelope for a decision, committing to the committee by its digest.
    pub fn new(height: Height, slot: u64, block: Block, commitment: &CommitteeCommitment) -> Self {
        Envelope {
            height,
            slot,
            block,
            committee: commitment.digest(),
        }
    }
}

/// A finality certificate: the aggregated module lattice attestations of the entitled supermajority,
/// held in ascending signer id order.
#[derive(Clone)]
pub struct Certificate {
    pub envelope: Envelope,
    pub attestations: Vec<Attestation>,
}

impl Certificate {
    /// A certificate over an envelope and its aggregated attestations. The attestations are stored in
    /// ascending signer id order, so the certificate is canonical regardless of the order they arrived
    /// in.
    pub fn new(envelope: Envelope, mut attestations: Vec<Attestation>) -> Self {
        attestations.sort_by_key(|a| a.from);
        Certificate {
            envelope,
            attestations,
        }
    }

    /// The distinct attester ids the certificate claims, in ascending order.
    pub fn attesters(&self) -> Vec<ValidatorId> {
        let mut ids: Vec<ValidatorId> = self.attestations.iter().map(|a| a.from).collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// A canonical digest of the whole certificate. Two certificates aggregated from the same
    /// attestations digest equal, which is how determinism is checked.
    pub fn digest(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.envelope.height.to_le_bytes());
        buf.extend_from_slice(&self.envelope.slot.to_le_bytes());
        buf.extend_from_slice(&self.envelope.block.to_bytes());
        buf.extend_from_slice(&self.envelope.committee);
        buf.extend_from_slice(&(self.attestations.len() as u64).to_le_bytes());
        for a in &self.attestations {
            buf.extend_from_slice(&a.from.to_le_bytes());
            buf.extend_from_slice(&a.membership.to_bytes());
            buf.extend_from_slice(&a.sig);
        }
        let mut out = [0u8; 32];
        shake256(&buf, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attester::Attester;
    use qtv_bft::block::Parent;
    use qtv_sampler::beacon::Beacon;

    #[test]
    fn a_certificate_lists_its_signers_in_order() {
        let a = Attester::new(2, 100);
        let b = Attester::new(1, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [5u8; 32], Parent::Genesis);
        let commitment = CommitteeCommitment::from_attesters(0, &[&a, &b]);
        let envelope = Envelope::new(1, 0, block, &commitment);
        let atts = vec![
            a.attest(1, 0, block, &beacon),
            b.attest(1, 0, block, &beacon),
        ];
        let cert = Certificate::new(envelope, atts);
        assert_eq!(cert.attesters(), vec![1, 2]);
    }
}
