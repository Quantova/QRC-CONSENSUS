// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_attest::aggregate::aggregate;
use qtv_attest::{Attester, Beacon, Block, CommitteeCommitment, Parent};

#[test]
fn a_certificate_verifies_at_a_slot_beyond_the_default() {
    let slots = 4096;
    let members: Vec<Attester> = (1..=4)
        .map(|id| Attester::with_slots(id, 100, slots))
        .collect();
    let refs: Vec<&Attester> = members.iter().collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);
    let slot = 4000;

    let budget = members.len() as u64;
    let commitment = CommitteeCommitment::from_attesters_with_budget(slot, &refs, budget);

    let atts: Vec<_> = members
        .iter()
        .map(|a| a.attest(1, 1, slot, 0, commitment.digest(), block, &beacon))
        .collect();

    assert_eq!(atts[0].membership.path.siblings.len(), 12);

    let cert = aggregate(1, 1, slot, block, &commitment, &beacon, &atts, 3).expect("quorum forms");
    assert!(cert.verify(1, &commitment, &beacon, 3).is_verified());
    assert_eq!(cert.attesters(), vec![1, 2, 3, 4]);
}
