//! Conformance vector for the attributable sortition faults. The one time

use qtv_sampler::beacon::Beacon;
use qtv_sampler::evidence::{DoubleDraw, OutOfPosition};
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::sortition::{verify_selection, Credential};
use qtv_sampler::validator::SamplerValidator;

const SATURATING_BUDGET: u64 = 100;

#[test]
fn two_draws_for_one_slot_are_provable() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();
    let slot = 2;

    // The account's genuine committed draw for the slot, and a second draw that
    // carries a different preimage for the same slot, the forged extra output. The
    // second is exactly what the enforcement rejects at verification.
    let honest = v.reveal(slot);
    let mut forged = v.reveal(slot);
    forged.preimage = v.reveal(9).preimage;
    assert_ne!(honest, forged);

    let fault = DoubleDraw {
        root,
        slot,
        first: honest,
        second: forged,
    };
    // Any node proves the fault from the registered root and the two credentials.
    assert!(fault.is_proven());
}

#[test]
fn an_honest_single_reveal_is_not_a_double_draw() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();
    let slot = 2;
    // Revealing the same slot twice is the identical credential, so it is not two
    // distinct draws and no fault is raised.
    let fault = DoubleDraw {
        root,
        slot,
        first: v.reveal(slot),
        second: v.reveal(slot),
    };
    assert!(!fault.is_proven());
}

#[test]
fn a_preimage_out_of_position_is_provable() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();

    // The genuine leaf for position 3, reused for slot 7. The credential still
    // authenticates at its real position 3, so a node proves it was used off
    // position.
    let credential = v.reveal(3);
    let fault = OutOfPosition {
        root,
        credential,
        used_slot: 7,
    };
    assert!(fault.is_proven());
}

#[test]
fn a_fabricated_out_of_position_over_a_foreign_leaf_is_not_proven() {
    // A reporter cannot frame an account with a preimage that is not the account's
    // committed leaf: the credential must authenticate to the registered root at
    // its claimed position, which only the account's real leaf does.
    let v = SamplerValidator::new(1, 100);
    let other = SamplerValidator::new(2, 100);
    let root = v.root();

    // Someone else's leaf, or junk, does not authenticate to v's root.
    let foreign = other.reveal(3);
    let fault = OutOfPosition {
        root,
        credential: foreign,
        used_slot: 7,
    };
    assert!(!fault.is_proven());

    let junk = Credential {
        position: 3,
        preimage: [0x55; 32],
        path: v.reveal(3).path,
    };
    let fault = OutOfPosition {
        root,
        credential: junk,
        used_slot: 7,
    };
    assert!(!fault.is_proven());
}

#[test]
fn the_forged_second_draw_is_both_rejected_and_provable() {
    // The link between the enforcement and the evidence. The forged second draw is
    // rejected by verification, the budget of one, and the same pair is provable as
    // an attributable fault, the slashing hook.
    let v = SamplerValidator::new(1, 100);
    let beacon = Beacon::genesis();
    let root = v.root();
    let slot = 5;

    let honest = v.reveal(slot);
    let mut forged = v.reveal(slot);
    forged.preimage = v.reveal(1).preimage;

    // Rejected at verification.
    assert!(verify_selection(
        &root,
        &beacon,
        DOMAIN_COMMITTEE,
        slot,
        100,
        100,
        SATURATING_BUDGET,
        &honest,
    ));
    assert!(!verify_selection(
        &root,
        &beacon,
        DOMAIN_COMMITTEE,
        slot,
        100,
        100,
        SATURATING_BUDGET,
        &forged,
    ));

    // Provable as a fault.
    let fault = DoubleDraw {
        root,
        slot,
        first: honest,
        second: forged,
    };
    assert!(fault.is_proven());
}

#[test]
fn honest_committee_participation_raises_no_fault() {
    use qtv_sampler::committee::Registry;

    let reg = Registry::new(vec![
        SamplerValidator::new(1, 100),
        SamplerValidator::new(2, 100),
        SamplerValidator::new(3, 100),
    ])
    .with_budget(SATURATING_BUDGET);
    let beacon = Beacon::genesis();

    // Each member's honest reveal for a slot is its committed leaf at that slot, so
    // no out of position fault stands against any of them.
    for slot in 0..4u64 {
        let committee = reg.sample_committee(&beacon, slot);
        for m in &committee.members {
            let root = reg.registration(m.id).unwrap().root;
            let fault = OutOfPosition {
                root,
                credential: m.credential.clone(),
                used_slot: slot,
            };
            assert!(!fault.is_proven(), "honest reveal flagged at slot {slot}");
        }
    }
}
