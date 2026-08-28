// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::Registry;
use qtv_sampler::onetime::{derive_preimage, Root};
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::sortition::{sortition_output, verify_membership, verify_selection, Credential};
use qtv_sampler::validator::{Registration, SamplerValidator};

const SATURATING_BUDGET: u64 = 100;

#[test]
fn the_draw_is_a_deterministic_hash_with_no_randomizer() {
    let v = SamplerValidator::new(1, 2_000);
    let beacon = Beacon::genesis();

    let first = v.reveal(0);
    let second = v.reveal(0);
    assert_eq!(first, second, "the reveal is fixed for a slot");

    let out_a = first.output(&beacon, DOMAIN_COMMITTEE, 0);
    let out_b = sortition_output(&first.preimage, &beacon, DOMAIN_COMMITTEE, 0);
    assert_eq!(out_a, out_b, "the output recomputes from public values");
}

#[test]
fn the_committed_leaf_is_the_only_valid_draw_for_a_slot() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();
    let slot = 4;

    let honest = v.reveal(slot);
    assert!(
        verify_membership(&root, slot, &honest),
        "the committed leaf authenticates"
    );

    for k in 0u64..256 {
        let forged = Credential {
            position: slot,
            preimage: derive_preimage(&[171; 32], k),
            path: honest.path.clone(),
        };
        if forged.preimage == honest.preimage {
            continue;
        }
        assert!(
            !verify_membership(&root, slot, &forged),
            "a second, different preimage for the slot was accepted at k={k}"
        );
    }
}

#[test]
fn a_second_draw_revealed_for_one_slot_is_rejected() {
    let v = SamplerValidator::new(1, 100);
    let beacon = Beacon::genesis();
    let root = v.root();
    let slot = 2;

    let honest = v.reveal(slot);
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

    let mut second = v.reveal(slot);
    second.preimage = v.reveal(7).preimage;
    assert!(!verify_selection(
        &root,
        &beacon,
        DOMAIN_COMMITTEE,
        slot,
        100,
        100,
        SATURATING_BUDGET,
        &second,
    ));
}

#[test]
fn a_preimage_used_out_of_its_position_is_rejected() {
    let v = SamplerValidator::new(1, 100);
    let beacon = Beacon::genesis();
    let root = v.root();

    let out_of_place = v.reveal_out_of_position(3, 7);
    assert!(!verify_selection(
        &root,
        &beacon,
        DOMAIN_COMMITTEE,
        7,
        100,
        100,
        SATURATING_BUDGET,
        &out_of_place,
    ));

    let in_place = v.reveal(3);
    assert!(verify_selection(
        &root,
        &beacon,
        DOMAIN_COMMITTEE,
        3,
        100,
        100,
        SATURATING_BUDGET,
        &in_place,
    ));
}

#[test]
fn a_draw_against_a_root_not_in_the_registry_is_rejected() {
    let reg = Registry::new(vec![
        SamplerValidator::new(1, 100),
        SamplerValidator::new(2, 100),
    ])
    .with_budget(SATURATING_BUDGET)
    .with_floor(0);
    let beacon = Beacon::genesis();

    let outsider = SamplerValidator::new(3, 100);
    let cred = outsider.reveal(0);

    assert!(
        reg.registration(3).is_none(),
        "outsider has no registration"
    );

    let fake_root = Root {
        digest: [17; 32],
        slots: outsider.slots(),
    };
    assert!(!verify_selection(
        &fake_root,
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        100,
        100,
        SATURATING_BUDGET,
        &cred,
    ));

    let member_one_root = reg.registration(1).unwrap().root;
    assert!(!verify_selection(
        &member_one_root,
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        100,
        100,
        SATURATING_BUDGET,
        &cred,
    ));

    let own = Registration::of(&outsider);
    assert!(verify_selection(
        &own.root,
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        100,
        100,
        SATURATING_BUDGET,
        &cred,
    ));
}
