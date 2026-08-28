// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_attest::aggregate::aggregate;
use qtv_attest::verify::RejectReason;
use qtv_attest::{
    Attester, Beacon, Block, Certificate, CommitteeCommitment, Envelope, Parent, Verdict,
};

fn committee_of_four() -> Vec<Attester> {
    (1..=4).map(|id| Attester::new(id, 100)).collect()
}

#[test]
fn an_entitled_supermajority_certificate_verifies() {
    let members = committee_of_four();
    let refs: Vec<&Attester> = members.iter().collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);
    let commitment = CommitteeCommitment::from_attesters(0, &refs);

    let atts: Vec<_> = members[..3]
        .iter()
        .map(|a| a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon))
        .collect();

    let cert = aggregate(1, 1, 0, block, &commitment, &beacon, &atts, 3).expect("quorum");
    assert_eq!(cert.attesters(), vec![1, 2, 3]);
    assert!(cert.verify(1, &commitment, &beacon, 3).is_verified());
    assert_eq!(cert.verify(1, &commitment, &beacon, 3), Verdict::Verified);
}

#[test]
fn a_certificate_missing_the_supermajority_does_not_verify() {
    let members = committee_of_four();
    let refs: Vec<&Attester> = members.iter().collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);
    let commitment = CommitteeCommitment::from_attesters(0, &refs);

    let atts: Vec<_> = members[..2]
        .iter()
        .map(|a| a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon))
        .collect();

    assert!(aggregate(1, 1, 0, block, &commitment, &beacon, &atts, 3).is_none());

    let envelope = Envelope::new(1, 0, block, &commitment);
    let cert = Certificate::new(envelope, atts);
    assert_eq!(
        cert.verify(1, &commitment, &beacon, 3),
        Verdict::Rejected(RejectReason::NotAQuorum)
    );
}
