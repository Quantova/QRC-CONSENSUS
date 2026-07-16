//! Conformance vectors for the grinding budget of the one time key sortition.
//! These make the budget of one draw per bonded account per slot a tested fact,
//! not an assertion, and they are the first thing proven because the budget is the
//! whole security. Each vector is a property any node rechecks from public values.
//!
//! The four facts pinned here:
//!
//! - the draw is a deterministic hash with no randomizer, so there is nothing to
//!   re roll and any node recomputes the same output;
//! - a second draw revealed for one slot from one account is rejected, because a
//!   committed root has exactly one authenticatable leaf at a position;
//! - a preimage used out of its position is rejected;
//! - a draw against a root that is not the account's registered one is rejected.

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::Registry;
use qtv_sampler::onetime::{derive_preimage, Root};
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::sortition::{sortition_output, verify_membership, verify_selection, Credential};
use qtv_sampler::validator::{Registration, SamplerValidator};

// A budget that saturates a single account's stake share, so a genuinely revealed
// draw is always below threshold. This isolates the position and root checks from
// the stake threshold.
const SATURATING_BUDGET: u64 = 100;

#[test]
fn the_draw_is_a_deterministic_hash_with_no_randomizer() {
    // The output for a slot is a fixed function of the committed preimage and the
    // beacon. Revealing twice and hashing twice gives the identical output, so
    // there is no randomizer to vary and nothing to search over.
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
    // The budget of one, stated as a search: the honest committed leaf is the only
    // preimage that authenticates at the slot position in the registered root.
    // Every other candidate preimage is rejected, so the account has exactly one
    // valid draw for the slot.
    let v = SamplerValidator::new(1, 100);
    let root = v.root();
    let slot = 4;

    let honest = v.reveal(slot);
    assert!(
        verify_membership(&root, slot, &honest),
        "the committed leaf authenticates"
    );

    // Try many alternative preimages at the same position and path. None can be a
    // second valid draw, since two preimages authenticating at one position to one
    // root would be a SHA3 collision.
    for k in 0u64..256 {
        let forged = Credential {
            position: slot,
            preimage: derive_preimage(&[0xAB; 32], k),
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
    // An account reveals its honest draw for a slot, then tries to substitute a
    // draw carrying a different position's preimage for the same slot to get a
    // second output. The substitute fails verification, so only the one committed
    // draw stands.
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

    // The account swaps in the preimage from a different leaf while claiming the
    // same slot, hunting for a lower output. The path no longer authenticates at
    // the slot, so the second draw is rejected.
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
    // The account presents the genuine leaf for position 3 but claims slot 7. The
    // preimage sits at position 3 in the root, so it does not authenticate at slot
    // 7, and the position check rejects it outright.
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

    // The same leaf used at its own position 3 does verify, proving it is a
    // genuine committed leaf and the rejection was purely about the position.
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
    // The registry holds accounts 1 and 2. A verifier looks up the account's
    // registered root; an account that is not registered has no root to check
    // against, so its draw is rejected for want of a registration.
    let reg = Registry::new(vec![
        SamplerValidator::new(1, 100),
        SamplerValidator::new(2, 100),
    ])
    .with_budget(SATURATING_BUDGET)
    .with_floor(0);
    let beacon = Beacon::genesis();

    let outsider = SamplerValidator::new(3, 100);
    let cred = outsider.reveal(0);

    // Account 3 is not registered.
    assert!(
        reg.registration(3).is_none(),
        "outsider has no registration"
    );

    // Against a fabricated root that is not in the registry the draw fails the
    // Merkle recomputation.
    let fake_root = Root {
        digest: [0x11; 32],
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

    // And against a registered but wrong account's root it also fails, so a draw
    // is bound to exactly the root it was committed under.
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

    // The outsider's own root, were it registered, is the only one that verifies.
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
