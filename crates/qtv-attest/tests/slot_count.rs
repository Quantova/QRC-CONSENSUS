//! The one time slot count is a construction parameter, not a fixed ceiling. The

use qtv_attest::aggregate::aggregate;
use qtv_attest::{Attester, Beacon, Block, CommitteeCommitment, Parent};

#[test]
fn a_certificate_verifies_at_a_slot_beyond_the_default() {
    // Four members over a tree of four thousand and ninety six slots, so a slot far
    // past the sixty four default is a real slot the tree serves.
    let slots = 4096;
    let members: Vec<Attester> = (1..=4)
        .map(|id| Attester::with_slots(id, 100, slots))
        .collect();
    let refs: Vec<&Attester> = members.iter().collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);
    let slot = 4000;

    // A budget that saturates every member share, so each member draw is below its
    // threshold at this slot and the whole committee is entitled, independent of the
    // slot's random output. This isolates the slot count from the sortition odds.
    let budget = members.len() as u64;
    let commitment = CommitteeCommitment::from_attesters_with_budget(slot, &refs, budget);

    let atts: Vec<_> = members
        .iter()
        .map(|a| a.attest(1, slot, block, &beacon))
        .collect();

    // The authentication path is the log of the padded leaf count, twelve here, so
    // the reveal at a slot past the default authenticates through the deeper tree.
    assert_eq!(atts[0].membership.path.siblings.len(), 12);

    let cert = aggregate(1, slot, block, &commitment, &beacon, &atts).expect("quorum forms");
    assert!(cert.verify(&commitment, &beacon).is_verified());
    assert_eq!(cert.attesters(), vec![1, 2, 3, 4]);
}
