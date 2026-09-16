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

#[test]
fn a_count_quorum_of_small_seats_cannot_finalize_without_the_stake_behind_it() {
    let members: Vec<Attester> = vec![
        Attester::new(1, 10),
        Attester::new(2, 10),
        Attester::new(3, 10),
        Attester::new(4, 970),
    ];
    let refs: Vec<&Attester> = members.iter().collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);
    let commitment = CommitteeCommitment::from_attesters(0, &refs);

    let atts: Vec<_> = members[..3]
        .iter()
        .map(|a| a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon))
        .collect();

    assert!(
        aggregate(1, 1, 0, block, &commitment, &beacon, &atts, 3).is_none(),
        "three of four seats holding three percent of the stake must not aggregate a certificate"
    );

    let envelope = Envelope::new(1, 0, block, &commitment);
    let cert = Certificate::new(envelope, atts);
    assert_eq!(
        cert.verify(1, &commitment, &beacon, 3),
        Verdict::Rejected(RejectReason::NotAQuorum),
        "a seat majority without a stake supermajority is not finality"
    );

    let whole: Vec<_> = members
        .iter()
        .map(|a| a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon))
        .collect();
    assert!(
        aggregate(1, 1, 0, block, &commitment, &beacon, &whole, 3).is_some(),
        "the same seats with the large holder behind them do finalize"
    );
}
