// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Conformance vector for the attributable sortition faults. The one time
//! construction makes an honest account's draw for a slot unique, so evidence any
//! node checks stands from the account's registered root alone. The slash, a full
//! burn of the bond and a permanent ban, is applied by the consensus and economics
//! layer; here the evidence is made checkable.
//!
//! The attributable fault is a preimage used out of its position. A double draw
//! needs two distinct openings that both authenticate for one slot, and the one
//! time root binds a single opening per slot, so a genuine reveal cannot be paired
//! with fabricated bytes to frame its author. An honest account triggers neither.

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

    // The account's genuine committed draw for the slot, and a fabricated second
    // draw that carries a preimage from another slot, so it does not authenticate
    // at this slot.
    let honest = v.reveal(slot);
    let mut forged = v.reveal(slot);
    forged.preimage = v.reveal(9).preimage;
    assert_ne!(honest, forged);

    // A genuine reveal paired with bytes that do not authenticate is not two draws.
    let fault = DoubleDraw {
        root,
        slot,
        first: honest.clone(),
        second: forged.clone(),
    };
    assert!(!fault.is_proven());

    // The pair fails either way round, so a lone genuine reveal never frames its
    // author.
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
fn a_double_draw_needs_two_distinct_authenticating_openings() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();
    let slot = 2;

    // Each side of the check is satisfiable by a real opening: the committed reveal
    // authenticates to the root at the slot.
    let genuine = v.reveal(slot);
    assert!(verify_membership(&root, slot, &genuine));

    // The one time root binds a single opening for the slot, so no other preimage
    // authenticates at it and no distinct second opening can be produced.
    for other in [0u64, 1, 3, 9, 40] {
        let mut alt = v.reveal(slot);
        alt.preimage = v.reveal(other).preimage;
        assert!(!verify_membership(&root, slot, &alt));
    }

    // When both openings authenticate, the pair is accepted only when the two
    // draws differ; the same opening twice is one draw, so it stands as no fault.
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
    // The budget of one is enforced at verification: the forged second draw is
    // rejected there, and it is not turned into a slashable fault against the
    // author of the genuine reveal it was pinned to.
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

    // Not a provable fault: the forged half does not authenticate to the root.
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
