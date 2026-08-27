// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Determinism. The same attestations aggregate into the same certificate, and

use qtv_attest::aggregate::aggregate;
use qtv_attest::{Attester, Beacon, Block, CommitteeCommitment, Parent};

fn committee_of_four() -> Vec<Attester> {
    (1..=4).map(|id| Attester::new(id, 100)).collect()
}

#[test]
fn the_same_attestations_produce_the_same_certificate() {
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);

    let first = committee_of_four();
    let first_refs: Vec<&Attester> = first.iter().collect();
    let commitment_a = CommitteeCommitment::from_attesters(0, &first_refs);
    let atts_a: Vec<_> = first[..3]
        .iter()
        .map(|a| a.attest(1, 1, 0, 0, commitment_a.digest(), block, &beacon))
        .collect();
    let cert_a = aggregate(1, 1, 0, block, &commitment_a, &beacon, &atts_a, 3).expect("quorum");

    // A wholly fresh construction of the same committee and attestations.
    let second = committee_of_four();
    let second_refs: Vec<&Attester> = second.iter().collect();
    let commitment_b = CommitteeCommitment::from_attesters(0, &second_refs);
    let atts_b: Vec<_> = second[..3]
        .iter()
        .map(|a| a.attest(1, 1, 0, 0, commitment_b.digest(), block, &beacon))
        .collect();
    let cert_b = aggregate(1, 1, 0, block, &commitment_b, &beacon, &atts_b, 3).expect("quorum");

    assert_eq!(commitment_a.digest(), commitment_b.digest());
    assert_eq!(cert_a.digest(), cert_b.digest());
}

#[test]
fn the_certificate_is_independent_of_attestation_order() {
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);
    let members = committee_of_four();
    let refs: Vec<&Attester> = members.iter().collect();
    let commitment = CommitteeCommitment::from_attesters(0, &refs);

    let a1 = members[0].attest(1, 1, 0, 0, commitment.digest(), block, &beacon);
    let a2 = members[1].attest(1, 1, 0, 0, commitment.digest(), block, &beacon);
    let a3 = members[2].attest(1, 1, 0, 0, commitment.digest(), block, &beacon);

    let forward = aggregate(1, 
        1,
        0,
        block,
        &commitment,
        &beacon,
        &[a1.clone(), a2.clone(), a3.clone()],
        3,
    )
    .expect("quorum");
    let reverse = aggregate(1, 1, 0, block, &commitment, &beacon, &[a3, a2, a1], 3).expect("quorum");

    assert_eq!(forward.attesters(), reverse.attesters());
    assert_eq!(forward.digest(), reverse.digest());
}
