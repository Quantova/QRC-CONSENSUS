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
