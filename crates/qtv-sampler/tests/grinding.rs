//! The acceptance bar for the one time key sortition: the grinding budget is

use qtv_sampler::beacon::Beacon;
use qtv_sampler::onetime::derive_preimage;
use qtv_sampler::params::{DOMAIN_COMMITTEE, DOMAIN_LEADER};
use qtv_sampler::sortition::{leader_score, verify_membership, verify_selection, Credential};
use qtv_sampler::validator::SamplerValidator;

// A budget that saturates a single account's stake share, so a genuinely revealed
// draw always clears the threshold. This isolates the membership binding from the
// stake weighting.
const SATURATING_BUDGET: u64 = 100;

// How wide the adversary is allowed to search. A budget of one means that however
// wide the search grows, exactly one candidate for a slot ever authenticates.
const SEARCH: u64 = 8192;

#[test]
fn the_grinding_budget_is_exactly_one_valid_draw_per_slot() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();
    let slot = 4;

    let honest = v.reveal(slot);
    assert!(verify_membership(&root, slot, &honest));

    let mut forgeries_accepted = 0u64;

    // Vary the preimage across a wide search, keeping the honest path and slot.
    for k in 0..SEARCH {
        let cand = Credential {
            position: slot,
            preimage: derive_preimage(&[0xa5; 32], k),
            path: honest.path.clone(),
        };
        if cand.preimage == honest.preimage {
            continue;
        }
        if verify_membership(&root, slot, &cand) {
            forgeries_accepted += 1;
        }
    }

    // Vary the path siblings, keeping the honest preimage. A forged path cannot
    // re-root the committed leaf to the registered digest.
    for k in 0..SEARCH {
        let mut path = honest.path.clone();
        for (i, sib) in path.siblings.iter_mut().enumerate() {
            *sib = derive_preimage(&[0x3c; 32], k.wrapping_add(i as u64 + 1));
        }
        if path == honest.path {
            continue;
        }
        let cand = Credential {
            position: slot,
            preimage: honest.preimage,
            path,
        };
        if verify_membership(&root, slot, &cand) {
            forgeries_accepted += 1;
        }
    }

    let total_valid = 1 + forgeries_accepted; // the honest reveal plus any forgery
    assert_eq!(total_valid, 1, "more than one draw authenticated for the slot");
}

#[test]
fn no_authenticating_credential_beats_the_honest_output() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();
    let beacon = Beacon::genesis();
    let slot = 9;

    let honest = v.reveal(slot);
    let honest_value = honest.value(&beacon, DOMAIN_LEADER, slot);

    let mut a_lower_forgery_exists = false;
    let mut lowest_authenticating = honest_value;

    for k in 0..SEARCH {
        let cand = Credential {
            position: slot,
            preimage: derive_preimage(&[0x77; 32], k),
            path: honest.path.clone(),
        };
        if cand.preimage == honest.preimage {
            continue;
        }
        let value = cand.value(&beacon, DOMAIN_LEADER, slot);
        if verify_membership(&root, slot, &cand) {
            if value < lowest_authenticating {
                lowest_authenticating = value;
            }
        } else if value < honest_value {
            // The adversary can compute lower outputs at will, it just cannot make
            // one authenticate. This proves the motive is real and the search wide.
            a_lower_forgery_exists = true;
        }
    }

    assert!(
        a_lower_forgery_exists,
        "search too narrow to find a lower forged output"
    );
    assert_eq!(
        lowest_authenticating, honest_value,
        "an authenticating credential produced a lower output than the honest draw"
    );
}

#[test]
fn an_alternate_key_cannot_stand_in_for_the_bonded_root() {
    let bonded = SamplerValidator::new(1, 100);
    let alternate = SamplerValidator::new(1_000_001, 100);
    let beacon = Beacon::genesis();
    let root = bonded.root();
    let slot = 3;

    let alt = alternate.reveal(slot);
    assert!(
        verify_membership(&alternate.root(), slot, &alt),
        "the alternate key is genuine against its own root"
    );
    assert!(
        !verify_membership(&root, slot, &alt),
        "the alternate key authenticated against the bonded root"
    );
    assert!(!verify_selection(
        &root,
        &beacon,
        DOMAIN_COMMITTEE,
        slot,
        100,
        100,
        SATURATING_BUDGET,
        &alt,
    ));

    let honest = bonded.reveal(slot);
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
}

#[test]
fn a_second_independent_draw_costs_a_second_bonded_root() {
    let beacon = Beacon::genesis();
    let slot = 6;

    let a = SamplerValidator::new(1, 100);
    let b = SamplerValidator::new(2, 100);

    assert_ne!(a.root(), b.root(), "two bonds carry two roots");
    assert_eq!(
        a.reveal(slot),
        a.reveal(slot),
        "one root re-reveals the identical draw"
    );

    let value_a = a.reveal(slot).value(&beacon, DOMAIN_COMMITTEE, slot);
    let value_b = b.reveal(slot).value(&beacon, DOMAIN_COMMITTEE, slot);
    assert_ne!(
        value_a, value_b,
        "the second draw is an independent hash under the second root"
    );
}

#[test]
fn effort_does_not_change_the_draw() {
    let v = SamplerValidator::new(1, 2_000);
    let beacon = Beacon::genesis();
    let slot = 11;

    let first = v.reveal(slot).value(&beacon, DOMAIN_COMMITTEE, slot);
    for _ in 0..SEARCH {
        let again = v.reveal(slot).value(&beacon, DOMAIN_COMMITTEE, slot);
        assert_eq!(again, first, "recomputation changed the draw");
    }
}

#[test]
fn a_member_cannot_grind_a_lower_leadership_score() {
    let v = SamplerValidator::new(1, 100);
    let root = v.root();
    let beacon = Beacon::genesis();
    let slot = 2;

    let honest = v.reveal(slot);
    let honest_score = leader_score(&honest.output(&beacon, DOMAIN_LEADER, slot), 100);

    for k in 0..SEARCH {
        let cand = Credential {
            position: slot,
            preimage: derive_preimage(&[0xd2; 32], k),
            path: honest.path.clone(),
        };
        if cand.preimage == honest.preimage {
            continue;
        }
        let cand_score = leader_score(&cand.output(&beacon, DOMAIN_LEADER, slot), 100);
        if cand_score < honest_score {
            assert!(
                !verify_membership(&root, slot, &cand),
                "a lower-scoring credential authenticated and could seize leadership"
            );
        }
    }
}
