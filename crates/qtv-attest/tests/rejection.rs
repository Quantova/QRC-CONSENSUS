// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_attest::verify::RejectReason;
use qtv_attest::{
    Attester, Beacon, Block, Certificate, CommitteeCommitment, Envelope, Parent, Verdict,
};

fn setup() -> (Vec<Attester>, Beacon, Block, CommitteeCommitment) {
    let members: Vec<Attester> = (1..=4).map(|id| Attester::new(id, 100)).collect();
    let refs: Vec<&Attester> = members.iter().collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);
    let commitment = CommitteeCommitment::from_attesters(0, &refs);
    (members, beacon, block, commitment)
}

fn quorum_attestations(
    members: &[Attester],
    beacon: &Beacon,
    block: Block,
    committee: [u8; 32],
) -> Vec<qtv_attest::Attestation> {
    members[..3]
        .iter()
        .map(|a| {
            a.attest(1, 1, 0, 0, committee, block, beacon)
                .expect("the attester serves this slot")
        })
        .collect()
}

#[test]
fn a_forged_signature_is_rejected() {
    let (members, beacon, block, commitment) = setup();
    let mut atts = quorum_attestations(&members, &beacon, block, commitment.digest());
    atts[0].sig[0] ^= 255;
    let cert = Certificate::new(Envelope::new(1, 0, block, &commitment), atts);
    assert_eq!(
        cert.verify(1, &commitment, &beacon, 3),
        Verdict::Rejected(RejectReason::BadSignature)
    );
}

#[test]
fn a_swapped_block_is_rejected_as_wrong_subject() {
    let (members, beacon, block, commitment) = setup();
    let mut atts = quorum_attestations(&members, &beacon, block, commitment.digest());
    atts[0].block = Block::new(1, [10u8; 32], Parent::Genesis);
    let cert = Certificate::new(Envelope::new(1, 0, block, &commitment), atts);
    assert_eq!(
        cert.verify(1, &commitment, &beacon, 3),
        Verdict::Rejected(RejectReason::WrongSubject)
    );
}

#[test]
fn a_mangled_membership_credential_is_rejected_as_not_entitled() {
    let (members, beacon, block, commitment) = setup();
    let mut atts = quorum_attestations(&members, &beacon, block, commitment.digest());
    atts[0].membership.preimage[0] ^= 1;
    let cert = Certificate::new(Envelope::new(1, 0, block, &commitment), atts);
    assert_eq!(
        cert.verify(1, &commitment, &beacon, 3),
        Verdict::Rejected(RejectReason::NotEntitled)
    );
}

#[test]
fn a_commitment_with_a_denominator_below_its_own_committee_is_refused() {
    let (members, beacon, block, commitment) = setup();
    let atts = quorum_attestations(&members, &beacon, block, commitment.digest());
    let envelope = Envelope::new(1, 0, block, &commitment);
    let cert = Certificate::new(envelope, atts);

    let starved = CommitteeCommitment::from_attesters(0, &members.iter().collect::<Vec<_>>())
        .with_total_weight(1);
    assert_eq!(
        cert.verify(1, &starved, &beacon, 3),
        Verdict::Rejected(RejectReason::CommitmentMismatch),
        "a re-parameterised commitment does not match the digest the envelope names"
    );
}

#[test]
fn a_repeated_attestation_does_not_invalidate_a_good_certificate() {
    let (members, beacon, block, commitment) = setup();
    let mut atts = quorum_attestations(&members, &beacon, block, commitment.digest());
    let repeat = atts[0].clone();
    atts.push(repeat);
    let envelope = Envelope::new(1, 0, block, &commitment);
    let cert = Certificate::new(envelope, atts);
    assert_eq!(cert.verify(1, &commitment, &beacon, 3), Verdict::Verified);
}

#[test]
fn a_certificate_whose_height_is_not_its_blocks_height_is_refused() {
    let (members, beacon, block, commitment) = setup();
    let atts = quorum_attestations(&members, &beacon, block, commitment.digest());
    let mut envelope = Envelope::new(1, 0, block, &commitment);
    envelope.height = 9;
    let cert = Certificate::new(envelope, atts);
    assert_eq!(
        cert.verify(1, &commitment, &beacon, 3),
        Verdict::Rejected(RejectReason::HeightMismatch)
    );
}
