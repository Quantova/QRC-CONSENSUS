//! The stage two succinct path, wired to the prover.
//!
//! A stage two certificate replaces the aggregated attestations with one small
//! constant proof from q-prover. This module produces that proof and implements
//! the `SuccinctVerifier` seam so a light client checks it through the same
//! verification path it uses for a stage one certificate.
//!
//! The proof is the prover's fused certificate over a single block preimage that
//! binds the decision: the height, the slot, the block digest, the committee
//! commitment digest, the supermajority count, and a digest of the committee
//! attestation set. The prover proves in circuit that SHAKE256 of that preimage
//! is the genuine permutation and that the per coefficient module lattice verify
//! arithmetic, the canonical reduction, the transform domain matrix vector
//! product, the response infinity norm, the commitment decomposition, and the hint
//! recovery, is carried out over the coefficients the hash produces, fused so the
//! hashing and the arithmetic cannot be split. The response coefficients the norm
//! and the matrix vector product bands consume are decoded from the real committee
//! signatures, so the fused relation runs over genuine signature witness.
//!
//! What this binds and what it does not is stated exactly in NOTES-stage-two.md.
//! The certificate binds the decision subject, the committee, and the count into
//! a real constant size proof and carries the attestation set digest; it does not
//! yet reconstruct the hash derived coefficients to each member's expanded matrix,
//! decoded response, and public key, close the full verify equation, or re-derive
//! the multi block attestation hash in circuit, which is the remaining stage two
//! work.

use qtv_crypto::sha3::shake256;

use qtv_stark::entry::{prove_batch, verify_batch, BatchProof};

use crate::attestation::Attestation;
use crate::certificate::{Certificate, Envelope, Stage2Body, SuccinctProof, SuccinctVerifier};
use crate::committee::{CommitteeCommitment, CommitteeDigest};
use crate::params::is_quorum;

/// The number of SHAKE256 squeeze segments the stage two certificate proves, one
/// hash derived coefficient each. This matches the prover's definitive fused
/// certificate.
pub const STAGE2_SEGMENTS: usize = 16;

/// The domain tag of the stage two preimage.
const PREIMAGE_TAG: &[u8] = b"QORUS-STAGE2";

/// The domain tag of the attestation set digest.
const SET_TAG: &[u8] = b"QORUS-ATTEST-SET";

/// Fold a committee attestation set into a 32 byte digest, in ascending signer
/// order, so the preimage binds the exact signatures and membership draws the
/// aggregator admitted. Duplicate signers are folded once.
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

// The ML DSA 65 encoding constants the response decode needs, from FIPS 204,
// Table 1 and section 7.2. They are public standard parameters.
const MLDSA_Q: u64 = 8_380_417; // 2^23 - 2^13 + 1
const MLDSA_GAMMA1: i64 = 1 << 19; // response coefficient range
const MLDSA_N: usize = 256; // ring degree
const MLDSA_L: usize = 5; // response polynomials
const CTILDE_BYTES: usize = 48; // challenge encoding length, lambda over four
const POLYZ_BITS: usize = 20; // packed bits per response coefficient
const POLYZ_PACKED: usize = MLDSA_N * POLYZ_BITS / 8; // 640 bytes per response poly

// The centered response coefficient mapped into the range zero to the modulus,
// so its centered representative is the signed response value the norm bounds.
fn to_field(signed: i64) -> u64 {
    if signed < 0 {
        (signed + MLDSA_Q as i64) as u64
    } else {
        signed as u64
    }
}

// Decode the response polynomials z from one signature, the L times N coefficients
// the norm band and the matrix vector product consume, each mapped into the field.
// The response is packed twenty bits per coefficient after the challenge encoding,
// least significant bit first, and each raw value v decodes to gamma1 minus v, the
// signed response whose infinity norm verification checks (FIPS 204, section 7.2).
fn decode_response(sig: &[u8]) -> Vec<u64> {
    let mut out = Vec::with_capacity(MLDSA_L * MLDSA_N);
    for poly in 0..MLDSA_L {
        let base = CTILDE_BYTES + poly * POLYZ_PACKED;
        let mut acc: u64 = 0;
        let mut acc_bits = 0usize;
        let mut byte = base;
        for _ in 0..MLDSA_N {
            while acc_bits < POLYZ_BITS {
                acc |= (sig[byte] as u64) << acc_bits;
                byte += 1;
                acc_bits += 8;
            }
            let raw = (acc & ((1 << POLYZ_BITS) - 1)) as i64;
            acc >>= POLYZ_BITS;
            acc_bits -= POLYZ_BITS;
            out.push(to_field(MLDSA_GAMMA1 - raw));
        }
    }
    out
}

/// Collect the member response coefficients the fused certificate proves over,
/// decoded from the real committee signatures in ascending signer order, up to the
/// requested count. Each is a genuine ML DSA 65 response coefficient inside the
/// response bound, so the norm and matrix vector product bands run over real
/// signature witness rather than a stand in.
pub fn member_responses(attestations: &[Attestation], want: usize) -> Vec<u64> {
    let mut ordered: Vec<&Attestation> = attestations.iter().collect();
    ordered.sort_by_key(|a| a.from);
    ordered.dedup_by_key(|a| a.from);

    let mut out = Vec::with_capacity(want);
    'outer: for att in ordered {
        for z in decode_response(&att.sig) {
            out.push(z);
            if out.len() == want {
                break 'outer;
            }
        }
    }
    out
}

/// The single block preimage the fused certificate hashes for a decision. It
/// binds the envelope subject, the committee digest, the supermajority count, and
/// the attestation set digest, and fits one SHAKE256 rate block so the fused
/// certificate absorbs it in one block.
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
/// set the aggregator admitted for the decision. The proof is the prover's fused
/// certificate over the decision preimage; the returned certificate reuses the
/// envelope and carries the count and the proof in place of the attestations.
pub fn prove_stage_two(envelope: Envelope, attestations: &[Attestation]) -> Certificate {
    prove_stage_two_with_segments(envelope, attestations, STAGE2_SEGMENTS)
}

/// Prove a stage two certificate with an explicit segment count. The verifier
/// reads the count off the proof, so a certificate proved with fewer segments
/// still verifies; production uses `STAGE2_SEGMENTS`, and a smaller count keeps
/// the tests cheap.
pub fn prove_stage_two_with_segments(
    envelope: Envelope,
    attestations: &[Attestation],
    segments: usize,
) -> Certificate {
    let set_digest = attestation_set_digest(attestations);
    let count = distinct_count(attestations);
    let preimage = stage_two_preimage(&envelope, &envelope.committee, count, &set_digest);
    // The response coefficients the fused certificate's norm and matrix vector
    // product bands consume, decoded from the real committee signatures.
    let responses = member_responses(attestations, segments);
    let batch = prove_batch(&preimage, segments, &responses);
    let bytes = encode_body(&set_digest, &batch);
    Certificate::stage_two(envelope, count, SuccinctProof { bytes })
}

/// The prover backed stage two verifier. It reconstructs the decision preimage
/// from the public envelope, the committee commitment, and the count and digest
/// carried in the body, then checks the prover certificate and that the count is
/// a supermajority of the committee.
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
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
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
        let responses = member_responses(&attestations, TEST_SEGMENTS);
        let batch = prove_batch(&preimage, TEST_SEGMENTS, &responses);
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

    #[test]
    fn member_responses_decode_inside_the_response_bound() {
        // The responses the fused certificate proves over are decoded from the real
        // committee signatures, and every one is a genuine ML DSA 65 response
        // coefficient inside the norm bound the certificate enforces.
        let (members, _commitment, block, beacon) = small_decision();
        let atts: Vec<_> = members
            .iter()
            .map(|a| a.attest(1, 0, block, &beacon))
            .collect();
        let responses = member_responses(&atts, STAGE2_SEGMENTS);
        assert_eq!(responses.len(), STAGE2_SEGMENTS);
        const BOUND: u64 = (1 << 19) - 196; // gamma1 - beta
        for z in responses {
            let centered = if z > MLDSA_Q / 2 { MLDSA_Q - z } else { z };
            assert!(centered < BOUND, "response {z} out of the norm bound");
        }
    }
}
