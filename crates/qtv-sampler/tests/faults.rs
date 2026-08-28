// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sampler::beacon::Beacon;
use qtv_sampler::evidence::{DoubleDraw, OutOfPosition};
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::sortition::{verify_membership, verify_selection, Credential};
use qtv_sampler::validator::SamplerValidator;

const SATURATING_BUDGET: u64 = 100;

#[test]
fn a_forged_second_draw_over_a_genuine_reveal_is_not_a_fault() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();
    let slot = 2;

    let honest = v.reveal(slot);
    let mut forged = v.reveal(slot);
    forged.preimage = v.reveal(9).preimage;
    assert_ne!(honest, forged);

    let fault = DoubleDraw {
        root,
        slot,
        first: honest.clone(),
        second: forged.clone(),
    };
    assert!(!fault.is_proven());

    let swapped = DoubleDraw {
        root,
        slot,
        first: forged,
        second: honest,
    };
    assert!(!swapped.is_proven());
}

#[test]
fn an_honest_single_reveal_is_not_a_double_draw() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();
    let slot = 2;
    let fault = DoubleDraw {
        root,
        slot,
        first: v.reveal(slot),
        second: v.reveal(slot),
    };
    assert!(!fault.is_proven());
}

#[test]
fn a_double_draw_needs_two_distinct_authenticating_openings() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();
    let slot = 2;

    let genuine = v.reveal(slot);
    assert!(verify_membership(&root, slot, &genuine));

    for other in [0u64, 1, 3, 9, 40] {
        let mut alt = v.reveal(slot);
        alt.preimage = v.reveal(other).preimage;
        assert!(!verify_membership(&root, slot, &alt));
    }

    let both_authenticate = DoubleDraw {
        root,
        slot,
        first: genuine.clone(),
        second: genuine,
    };
    assert!(!both_authenticate.is_proven());
}

#[test]
fn a_preimage_out_of_position_is_provable() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();

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
    let v = SamplerValidator::new(1, 100);
    let other = SamplerValidator::new(2, 100);
    let root = v.root();

    let foreign = other.reveal(3);
    let fault = OutOfPosition {
        root,
        credential: foreign,
        used_slot: 7,
    };
    assert!(!fault.is_proven());

    let junk = Credential {
        position: 3,
        preimage: [85; 32],
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
fn the_forged_second_draw_is_rejected_at_verification_and_frames_no_one() {
    let v = SamplerValidator::new(1, 100);
    let beacon = Beacon::genesis();
    let root = v.root();
    let slot = 5;

    let honest = v.reveal(slot);
    let mut forged = v.reveal(slot);
    forged.preimage = v.reveal(1).preimage;

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

    let fault = DoubleDraw {
        root,
        slot,
        first: honest,
        second: forged,
    };
    assert!(!fault.is_proven());
}

#[test]
fn honest_committee_participation_raises_no_fault() {
    use qtv_sampler::committee::Registry;

    let reg = Registry::new(vec![
        SamplerValidator::new(1, 100),
        SamplerValidator::new(2, 100),
        SamplerValidator::new(3, 100),
    ])
    .with_budget(SATURATING_BUDGET)
    .with_floor(0);
    let beacon = Beacon::genesis();

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
