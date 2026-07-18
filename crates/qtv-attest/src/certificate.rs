//! The staged finality certificate. A certificate is an envelope and a body. The
//! envelope fixes the subject: the height, the slot, the block, and the digest of
//! the committee commitment. The body is staged.
//!
//! A stage one body carries the aggregated module lattice attestations, the form
//! at genesis before recursive succinctness. A stage two body carries a single
//! succinct proof in their place, over the same envelope, so the wrapper shape
//! never changes when succinctness activates. The succinct proving and its
//! verification live in the prover; this crate fixes only the typed seam through
//! the `SuccinctVerifier` trait and never accepts a stage two body without one.
//!
//! Governance tallies travel this same wrapper: a tally is a succinct body over a
//! referendum subject rather than a block, which is why the envelope and the seam
//! stay agnostic to what the body proves.

use qtv_crypto::sha3::shake256;

use qtv_bft::block::{Block, Height};

use crate::attestation::Attestation;
use crate::attester::ValidatorId;
use crate::committee::{CommitteeCommitment, CommitteeDigest};

/// Which stage produced a certificate body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    One,
    Two,
}

/// The shared certificate envelope. Both bodies bind to the same envelope, so a
/// stage one and a stage two certificate for one decision agree on the subject
/// and the committee.
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

/// The stage one body: the aggregated module lattice attestations of the entitled
/// supermajority, held in ascending signer id order.
#[derive(Clone)]
pub struct Stage1Body {
    pub attestations: Vec<Attestation>,
}

/// A single succinct proof that stands in for the aggregated attestations. Its
/// bytes are opaque here; the prover produces and checks them.
#[derive(Clone)]
pub struct SuccinctProof {
    pub bytes: Vec<u8>,
}

/// The stage two body: the entitled attester count the proof attests to, and the
/// succinct proof itself.
#[derive(Clone)]
pub struct Stage2Body {
    pub attester_count: usize,
    pub proof: SuccinctProof,
}

/// The staged body of a certificate.
#[derive(Clone)]
pub enum Body {
    Stage1(Stage1Body),
    Stage2(Stage2Body),
}

/// The typed seam for the stage two succinct path. The prover implements this;
/// qtv-attest fixes only the interface so the wrapper is stable before recursive
/// succinctness lands. A light client with a verifier checks the succinct body
/// through it, and one without a verifier reports the body pending rather than
/// silently accepting it.
pub trait SuccinctVerifier {
    fn verify(
        &self,
        envelope: &Envelope,
        body: &Stage2Body,
        commitment: &CommitteeCommitment,
    ) -> bool;
}

/// A staged finality certificate.
#[derive(Clone)]
pub struct Certificate {
    pub envelope: Envelope,
    pub body: Body,
}

impl Certificate {
    /// A stage one certificate over an envelope and its aggregated attestations.
    /// The attestations are stored in ascending signer id order, so the
    /// certificate is canonical regardless of the order they arrived in.
    pub fn stage_one(envelope: Envelope, mut attestations: Vec<Attestation>) -> Self {
        attestations.sort_by_key(|a| a.from);
        Certificate {
            envelope,
            body: Body::Stage1(Stage1Body { attestations }),
        }
    }

    /// A stage two certificate over the same envelope shape, carrying the entitled
    /// count and the succinct proof in place of the attestations.
    pub fn stage_two(envelope: Envelope, attester_count: usize, proof: SuccinctProof) -> Self {
        Certificate {
            envelope,
            body: Body::Stage2(Stage2Body {
                attester_count,
                proof,
            }),
        }
    }

    pub fn stage(&self) -> Stage {
        match self.body {
            Body::Stage1(_) => Stage::One,
            Body::Stage2(_) => Stage::Two,
        }
    }

    /// The distinct attester ids the certificate claims, in ascending order. A
    /// stage one certificate lists its signers; a stage two certificate hides
    /// them behind the proof and reports none here.
    pub fn attesters(&self) -> Vec<ValidatorId> {
        match &self.body {
            Body::Stage1(b) => {
                let mut ids: Vec<ValidatorId> = b.attestations.iter().map(|a| a.from).collect();
                ids.sort_unstable();
                ids.dedup();
                ids
            }
            Body::Stage2(_) => Vec::new(),
        }
    }

    /// A canonical digest of the whole certificate. Two certificates aggregated
    /// from the same attestations digest equal, which is how determinism is
    /// checked without comparing opaque proof bytes field by field.
    pub fn digest(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.envelope.height.to_le_bytes());
        buf.extend_from_slice(&self.envelope.slot.to_le_bytes());
        buf.extend_from_slice(&self.envelope.block.to_bytes());
        buf.extend_from_slice(&self.envelope.committee);
        match &self.body {
            Body::Stage1(b) => {
                buf.push(1);
                buf.extend_from_slice(&(b.attestations.len() as u64).to_le_bytes());
                for a in &b.attestations {
                    buf.extend_from_slice(&a.from.to_le_bytes());
                    buf.extend_from_slice(&a.membership.to_bytes());
                    buf.extend_from_slice(&a.sig);
                }
            }
            Body::Stage2(b) => {
                buf.push(2);
                buf.extend_from_slice(&(b.attester_count as u64).to_le_bytes());
                buf.extend_from_slice(&b.proof.bytes);
            }
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
    fn a_stage_one_body_lists_its_signers_in_order() {
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
        let cert = Certificate::stage_one(envelope, atts);
        assert_eq!(cert.stage(), Stage::One);
        assert_eq!(cert.attesters(), vec![1, 2]);
    }

    #[test]
    fn a_stage_two_body_shares_the_envelope_and_hides_signers() {
        let a = Attester::new(1, 100);
        let block = Block::new(1, [5u8; 32], Parent::Genesis);
        let commitment = CommitteeCommitment::from_attesters(0, &[&a]);
        let envelope = Envelope::new(1, 0, block, &commitment);
        let cert = Certificate::stage_two(
            envelope,
            1,
            SuccinctProof {
                bytes: vec![0u8; 4],
            },
        );
        assert_eq!(cert.stage(), Stage::Two);
        assert!(cert.attesters().is_empty());
    }
}
