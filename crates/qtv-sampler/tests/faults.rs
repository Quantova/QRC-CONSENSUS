// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sampler::beacon::Beacon;
use qtv_sampler::evidence::DoubleDraw;
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::sortition::{verify_membership, verify_selection};
use qtv_sampler::validator::SamplerValidator;

const SATURATING_BUDGET: u64 = 100;

#[test]
fn a_forged_second_draw_over_a_genuine_reveal_is_not_a_fault() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();
    let slot = 2;

    let honest = v
        .reveal(slot)
        .expect("the position is within the committed slots");
    let mut forged = v
        .reveal(slot)
        .expect("the position is within the committed slots");
    forged.preimage = v
        .reveal(9)
        .expect("the position is within the committed slots")
        .preimage;
    assert_ne!(honest, forged);

    let fault = DoubleDraw {
        root,
        holder: v.id,
        slot,
        first: honest.clone(),
        second: forged.clone(),
    };
    assert!(!fault.is_proven());

    let swapped = DoubleDraw {
        root,
        holder: v.id,
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
        holder: v.id,
        slot,
        first: v
            .reveal(slot)
            .expect("the position is within the committed slots"),
        second: v
            .reveal(slot)
            .expect("the position is within the committed slots"),
    };
    assert!(!fault.is_proven());
}

#[test]
fn a_double_draw_needs_two_distinct_authenticating_openings() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();
    let slot = 2;

    let genuine = v
        .reveal(slot)
        .expect("the position is within the committed slots");
    assert!(verify_membership(&root, v.id, slot, &genuine));

    for other in [0u64, 1, 3, 9, 40] {
        let mut alt = v
            .reveal(slot)
            .expect("the position is within the committed slots");
        alt.preimage = v
            .reveal(other)
            .expect("the position is within the committed slots")
            .preimage;
        assert!(!verify_membership(&root, v.id, slot, &alt));
    }

    let both_authenticate = DoubleDraw {
        root,
        holder: v.id,
        slot,
        first: genuine.clone(),
        second: genuine,
    };
    assert!(!both_authenticate.is_proven());
}

#[test]
fn the_forged_second_draw_is_rejected_at_verification_and_frames_no_one() {
    let v = SamplerValidator::new(1, 100);
    let beacon = Beacon::genesis();
    let root = v.root();
    let slot = 5;

    let honest = v
        .reveal(slot)
        .expect("the position is within the committed slots");
    let mut forged = v
        .reveal(slot)
        .expect("the position is within the committed slots");
    forged.preimage = v
        .reveal(1)
        .expect("the position is within the committed slots")
        .preimage;

    assert!(verify_selection(
        &root,
        v.id,
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
        v.id,
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
        holder: v.id,
        slot,
        first: honest,
        second: forged,
    };
    assert!(!fault.is_proven());
}
