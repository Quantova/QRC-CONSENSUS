//! Committee entitlement is the gate. A validator that is not on the committee
//! is rejected even when its module lattice signature is perfectly valid, because
//! aggregation and verification both bind an attestation to the committee
//! commitment, not to a bare signature.

use qtv_attest::aggregate::aggregate;
use qtv_attest::verify::RejectReason;
use qtv_attest::{
    Attester, Beacon, Block, Certificate, CommitteeCommitment, Envelope, Parent, Verdict,
};

fn committee_of_four() -> Vec<Attester> {
    (1..=4).map(|id| Attester::new(id, 100)).collect()
}

#[test]
fn an_off_committee_signer_is_rejected_even_with_a_valid_signature() {
    let members = committee_of_four();
    let refs: Vec<&Attester> = members.iter().collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);
    let commitment = CommitteeCommitment::from_attesters(0, &refs);

    // An outsider with a genuine key that is not listed in the commitment.
    let outsider = Attester::new(99, 100);
    let outsider_att = outsider.attest(1, 0, block, &beacon);
    assert!(
        outsider_att.signature_verifies(outsider.attest_public_key()),
        "the outsider signature is valid on its own"
    );

    // Aggregation admits the three insiders and silently drops the outsider.
    let mut atts: Vec<_> = members[..3]
        .iter()
        .map(|a| a.attest(1, 0, block, &beacon))
        .collect();
    atts.push(outsider_att.clone());
    let cert = aggregate(1, 0, block, &commitment, &beacon, &atts).expect("quorum");
    assert_eq!(cert.attesters(), vec![1, 2, 3]);

    // A certificate that carries the outsider is rejected outright, valid
    // signature and all.
    let envelope = Envelope::new(1, 0, block, &commitment);
    let tainted = Certificate::new(
        envelope,
        vec![
            members[0].attest(1, 0, block, &beacon),
            members[1].attest(1, 0, block, &beacon),
            outsider_att,
        ],
    );
    assert_eq!(
        tainted.verify(&commitment, &beacon),
        Verdict::Rejected(RejectReason::NotOnCommittee)
    );
}
