//! A certificate built from an entitled supermajority verifies, and a

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
    let block = Block::new(1, 9, Parent::Genesis);
    let commitment = CommitteeCommitment::from_attesters(0, &refs);

    // Three of four entitled members attest, a supermajority.
    let atts: Vec<_> = members[..3]
        .iter()
        .map(|a| a.attest(1, 0, block, &beacon))
        .collect();

    let cert = aggregate(1, 0, block, &commitment, &beacon, &atts).expect("quorum");
    assert_eq!(cert.attesters(), vec![1, 2, 3]);
    assert!(cert.verify(&commitment, &beacon).is_verified());
    assert_eq!(cert.verify(&commitment, &beacon), Verdict::Verified);
}

#[test]
fn a_certificate_missing_the_supermajority_does_not_verify() {
    let members = committee_of_four();
    let refs: Vec<&Attester> = members.iter().collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, 9, Parent::Genesis);
    let commitment = CommitteeCommitment::from_attesters(0, &refs);

    // Only two of four attest, one short of the quorum of three.
    let atts: Vec<_> = members[..2]
        .iter()
        .map(|a| a.attest(1, 0, block, &beacon))
        .collect();

    // Aggregation refuses to form a certificate.
    assert!(aggregate(1, 0, block, &commitment, &beacon, &atts).is_none());

    // A certificate hand built from the same two attestations is rejected as
    // not a quorum, so it never finalizes the block.
    let envelope = Envelope::new(1, 0, block, &commitment);
    let cert = Certificate::stage_one(envelope, atts);
    assert_eq!(
        cert.verify(&commitment, &beacon),
        Verdict::Rejected(RejectReason::NotAQuorum)
    );
}
