//! The stage two succinct path, wired to the prover.

use qtv_crypto::sha3::shake256;

use qtv_stark::entry::{prove_batch, verify_batch, BatchProof};

use crate::attestation::Attestation;
use crate::certificate::{Certificate, Envelope, Stage2Body, SuccinctProof, SuccinctVerifier};
use crate::committee::{CommitteeCommitment, CommitteeDigest};
use crate::params::is_quorum;

/// The number of SHAKE256 squeeze segments the stage two certificate proves, one
pub const STAGE2_SEGMENTS: usize = 16;

/// The domain tag of the stage two preimage.
const PREIMAGE_TAG: &[u8] = b"QORUS-STAGE2";

/// The domain tag of the attestation set digest.
const SET_TAG: &[u8] = b"QORUS-ATTEST-SET";

/// Fold a committee attestation set into a 32 byte digest, in ascending signer
pub fn attestation_set_digest(attestations: &[Attestation]) -> [u8; 32] {
    let mut ordered: Vec<&Attestation> = attestations.iter().collect();
    ordered.sort_by_key(|a| a.from);
    ordered.dedup_by_key(|a| a.from);

    let mut buf = Vec::new();
    buf.extend_from_slice(SET_TAG);
    buf.extend_from_slice(&(ordered.len() as u64).to_le_bytes());
    for att in ordered {
        buf.extend_from_slice(&att.from.to_le_bytes());
        buf.extend_from_slice(&att.membership.to_bytes());
        buf.extend_from_slice(&att.sig);
    }
    let mut out = [0u8; 32];
    shake256(&buf, &mut out);
    out
}

/// The number of distinct signers in an attestation set.
fn distinct_count(attestations: &[Attestation]) -> usize {
    let mut ids: Vec<u64> = attestations.iter().map(|a| a.from).collect();
    ids.sort_unstable();
    ids.dedup();
    ids.len()
}

/// The single block preimage the fused certificate hashes for a decision. It
pub fn stage_two_preimage(
    envelope: &Envelope,
    committee: &CommitteeDigest,
    count: usize,
    set_digest: &[u8; 32],
) -> Vec<u8> {
    let mut block_digest = [0u8; 32];
    shake256(&envelope.block.to_bytes(), &mut block_digest);

    let mut msg = Vec::with_capacity(PREIMAGE_TAG.len() + 8 + 8 + 32 + 32 + 8 + 32);
    msg.extend_from_slice(PREIMAGE_TAG);
    msg.extend_from_slice(&envelope.height.to_le_bytes());
    msg.extend_from_slice(&envelope.slot.to_le_bytes());
    msg.extend_from_slice(&block_digest);
    msg.extend_from_slice(committee);
    msg.extend_from_slice(&(count as u64).to_le_bytes());
    msg.extend_from_slice(set_digest);
    msg
}

// The body bytes of a stage two certificate: the 32 byte attestation set digest
// then the serialized batch certificate. The verifier rebuilds the preimage from
// the digest, so it must travel with the proof.
fn encode_body(set_digest: &[u8; 32], batch: &BatchProof) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + batch.size());
    bytes.extend_from_slice(set_digest);
    bytes.extend_from_slice(&batch.to_bytes());
    bytes
}

fn decode_body(bytes: &[u8]) -> Option<([u8; 32], BatchProof)> {
    if bytes.len() < 32 {
        return None;
    }
    let mut set_digest = [0u8; 32];
    set_digest.copy_from_slice(&bytes[..32]);
    let batch = BatchProof::from_bytes(&bytes[32..])?;
    Some((set_digest, batch))
}

/// Prove a stage two certificate over an envelope and the committee attestation
pub fn prove_stage_two(envelope: Envelope, attestations: &[Attestation]) -> Certificate {
    prove_stage_two_with_segments(envelope, attestations, STAGE2_SEGMENTS)
}

/// Prove a stage two certificate with an explicit segment count. The verifier
pub fn prove_stage_two_with_segments(
    envelope: Envelope,
    attestations: &[Attestation],
    segments: usize,
) -> Certificate {
    let set_digest = attestation_set_digest(attestations);
    let count = distinct_count(attestations);
    let preimage = stage_two_preimage(&envelope, &envelope.committee, count, &set_digest);
    let batch = prove_batch(&preimage, segments);
    let bytes = encode_body(&set_digest, &batch);
    Certificate::stage_two(envelope, count, SuccinctProof { bytes })
}

/// The prover backed stage two verifier. It reconstructs the decision preimage
pub struct ProverVerifier;

impl SuccinctVerifier for ProverVerifier {
    fn verify(
        &self,
        envelope: &Envelope,
        body: &Stage2Body,
        commitment: &CommitteeCommitment,
    ) -> bool {
        let (set_digest, batch) = match decode_body(&body.proof.bytes) {
            Some(parts) => parts,
            None => return false,
        };
        if !is_quorum(body.attester_count, commitment.len()) {
            return false;
        }
        let preimage = stage_two_preimage(
            envelope,
            &commitment.digest(),
            body.attester_count,
            &set_digest,
        );
        verify_batch(&preimage, &batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attester::Attester;
    use crate::verify::{RejectReason, Verdict};
    use qtv_bft::block::Parent;
    use qtv_sampler::beacon::Beacon;
    use qtv_stark::entry::BatchProof;

    use crate::aggregate::aggregate;
    use crate::certificate::Body;
    use qtv_bft::block::Block;

    // A small segment count keeps the proving in the tests cheap; production uses
    // STAGE2_SEGMENTS. The verifier reads the count off the proof either way.
    const TEST_SEGMENTS: usize = 2;

    // A small committee whose equal weights all saturate under a budget of the
    // member count, so every member is entitled.
    fn small_decision() -> (Vec<Attester>, CommitteeCommitment, Block, Beacon) {
        let members: Vec<Attester> = (1..=4).map(|id| Attester::new(id, 100)).collect();
        let refs: Vec<&Attester> = members.iter().collect();
        let commitment = CommitteeCommitment::from_attesters_with_budget(0, &refs, 4);
        let block = Block::new(1, 9, Parent::Genesis);
        (members, commitment, block, Beacon::genesis())
    }

    #[test]
    fn a_stage_two_certificate_verifies_through_the_light_client_path() {
        let (members, commitment, block, beacon) = small_decision();
        let atts: Vec<_> = members[..3]
            .iter()
            .map(|a| a.attest(1, 0, block, &beacon))
            .collect();
        let stage_one = aggregate(1, 0, block, &commitment, &beacon, &atts).expect("quorum");

        let attestations = match &stage_one.body {
            Body::Stage1(b) => b.attestations.clone(),
            _ => unreachable!(),
        };
        let stage_two =
            prove_stage_two_with_segments(stage_one.envelope.clone(), &attestations, TEST_SEGMENTS);

        // The envelope is shared with the stage one certificate.
        assert_eq!(stage_two.envelope, stage_one.envelope);
        // Pending without a verifier, decided through the seam with one.
        assert_eq!(
            stage_two.verify(&commitment, &beacon),
            Verdict::StageTwoPending
        );
        assert!(stage_two
            .verify_with(&commitment, &beacon, &ProverVerifier)
            .is_verified());
    }

    #[test]
    fn a_stage_two_certificate_for_a_wrong_committee_is_rejected() {
        let (members, commitment, block, beacon) = small_decision();
        let atts: Vec<_> = members[..3]
            .iter()
            .map(|a| a.attest(1, 0, block, &beacon))
            .collect();
        let stage_one = aggregate(1, 0, block, &commitment, &beacon, &atts).expect("quorum");
        let attestations = match &stage_one.body {
            Body::Stage1(b) => b.attestations.clone(),
            _ => unreachable!(),
        };
        let stage_two =
            prove_stage_two_with_segments(stage_one.envelope.clone(), &attestations, TEST_SEGMENTS);

        // A different committee gives a different commitment digest, so the
        // envelope no longer matches and the seam rejects before the proof.
        let others: Vec<Attester> = (10..=13).map(|id| Attester::new(id, 100)).collect();
        let other_refs: Vec<&Attester> = others.iter().collect();
        let other = CommitteeCommitment::from_attesters_with_budget(0, &other_refs, 4);
        assert_eq!(
            stage_two.verify_with(&other, &beacon, &ProverVerifier),
            Verdict::Rejected(RejectReason::CommitmentMismatch)
        );
    }

    #[test]
    fn a_tampered_proof_is_rejected() {
        let (members, commitment, block, beacon) = small_decision();
        let atts: Vec<_> = members[..3]
            .iter()
            .map(|a| a.attest(1, 0, block, &beacon))
            .collect();
        let stage_one = aggregate(1, 0, block, &commitment, &beacon, &atts).expect("quorum");
        let attestations = match &stage_one.body {
            Body::Stage1(b) => b.attestations.clone(),
            _ => unreachable!(),
        };
        let mut stage_two =
            prove_stage_two_with_segments(stage_one.envelope.clone(), &attestations, TEST_SEGMENTS);

        if let Body::Stage2(body) = &mut stage_two.body {
            let mid = body.proof.bytes.len() / 2;
            body.proof.bytes[mid] ^= 1;
        }
        assert_eq!(
            stage_two.verify_with(&commitment, &beacon, &ProverVerifier),
            Verdict::Rejected(RejectReason::SuccinctProof)
        );
    }

    #[test]
    fn a_count_below_the_supermajority_is_rejected() {
        let (members, commitment, block, beacon) = small_decision();
        let atts: Vec<_> = members[..3]
            .iter()
            .map(|a| a.attest(1, 0, block, &beacon))
            .collect();
        let stage_one = aggregate(1, 0, block, &commitment, &beacon, &atts).expect("quorum");
        let attestations = match &stage_one.body {
            Body::Stage1(b) => b.attestations.clone(),
            _ => unreachable!(),
        };
        // Re-prove with an honest count but hand the verifier a body claiming a
        // count below the quorum, so the preimage and the count check both fail.
        let set_digest = attestation_set_digest(&attestations);
        let preimage =
            stage_two_preimage(&stage_one.envelope, &commitment.digest(), 1, &set_digest);
        let batch = prove_batch(&preimage, TEST_SEGMENTS);
        let bytes = encode_body(&set_digest, &batch);
        let cert = Certificate::stage_two(stage_one.envelope.clone(), 1, SuccinctProof { bytes });
        assert_eq!(
            cert.verify_with(&commitment, &beacon, &ProverVerifier),
            Verdict::Rejected(RejectReason::SuccinctProof)
        );
    }

    #[test]
    fn the_set_digest_changes_with_the_attestations() {
        let (members, _commitment, block, beacon) = small_decision();
        let atts: Vec<_> = members
            .iter()
            .map(|a| a.attest(1, 0, block, &beacon))
            .collect();
        let full = attestation_set_digest(&atts);
        let fewer = attestation_set_digest(&atts[..3]);
        assert_ne!(full, fewer);
        assert_eq!(full, attestation_set_digest(&atts));
    }

    #[test]
    fn a_malformed_body_is_rejected() {
        assert!(decode_body(&[0u8; 4]).is_none());
        assert!(BatchProof::from_bytes(&[0u8; 2]).is_none());
    }
}
