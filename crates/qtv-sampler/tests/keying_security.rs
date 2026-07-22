//! The one time sortition key rests on a secret the validator alone holds, not on

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::Registry;
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::sortition::{verify_membership, verify_selection};
use qtv_sampler::validator::{sortition_tree_seed, Registration, SamplerValidator};

const SATURATING_BUDGET: u64 = 100;

#[test]
fn the_tree_seed_is_a_function_of_the_secret_alone_not_the_id() {
    // The derived tree seed does not depend on the id: the same secret under two
    // different ids yields the identical seed and the identical committed root.
    let secret = [0x21u8; 32];
    let a = SamplerValidator::from_secret(1, &secret, 100);
    let b = SamplerValidator::from_secret(999_999, &secret, 100);
    assert_eq!(a.root(), b.root(), "the id is not an input to the key material");

    // And the id tells a would be attacker nothing: one id under two secrets gives
    // two unrelated roots, so a root cannot be recomputed from the public id.
    let c = SamplerValidator::from_secret(1, &[0x22u8; 32], 100);
    assert_ne!(a.root(), c.root());
}

#[test]
fn the_published_root_reveals_neither_the_secret_nor_the_seed() {
    // The tree seed is a one way image of the secret, and the root is a one way
    // image of the seed. Neither public value equals the secret material behind it,
    // so the secret cannot be read off a commitment.
    let secret = [0x33u8; 32];
    let seed = sortition_tree_seed(&secret);
    assert_ne!(seed, secret, "the tree seed must not be the secret");

    let v = SamplerValidator::from_secret(7, &secret, 100);
    let reg = Registration::of(&v);
    assert_ne!(reg.root.digest, secret, "the root must not be the secret");
    assert_ne!(reg.root.digest, seed, "the root must not be the seed");
}

#[test]
fn two_independent_secrets_are_independent() {
    let a = SamplerValidator::from_secret(1, &[0x01u8; 32], 100);
    let b = SamplerValidator::from_secret(2, &[0x02u8; 32], 100);

    // Distinct commitments.
    assert_ne!(a.root(), b.root());
    assert_ne!(sortition_tree_seed(&[0x01u8; 32]), sortition_tree_seed(&[0x02u8; 32]));

    // A reveal from one does not authenticate against the other's root.
    let slot = 3;
    let ra = a.reveal(slot);
    let rb = b.reveal(slot);
    assert!(verify_membership(&a.root(), slot, &ra));
    assert!(verify_membership(&b.root(), slot, &rb));
    assert!(!verify_membership(&b.root(), slot, &ra));
    assert!(!verify_membership(&a.root(), slot, &rb));
}

#[test]
fn a_party_with_only_the_public_root_cannot_produce_a_valid_reveal() {
    // The victim publishes its root as a commitment. An impostor knows the root but
    // not the secret. The best it can do is bind its own secret behind its own tree
    // and reveal from that, which authenticates to its own root, never the victim's.
    let victim = SamplerValidator::from_secret(1, &[0xa1u8; 32], 100);
    let victim_root = victim.root();
    let beacon = Beacon::genesis();
    let slot = 5;

    let impostor = SamplerValidator::from_secret(1, &[0xb2u8; 32], 100);
    let forged = impostor.reveal(slot);

    // Same id, same weight, same slot, but the reveal is bound to the impostor's own
    // tree, so it does not authenticate to the victim's committed root.
    assert!(!verify_membership(&victim_root, slot, &forged));
    assert!(!verify_selection(
        &victim_root,
        &beacon,
        DOMAIN_COMMITTEE,
        slot,
        100,
        100,
        SATURATING_BUDGET,
        &forged,
    ));

    // The victim, holding the secret, produces the only reveal that authenticates.
    let honest = victim.reveal(slot);
    assert!(verify_selection(
        &victim_root,
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
fn the_committee_is_not_computable_in_advance_without_the_secrets() {
    // The committee for a slot is decided by each member's one time output, which is
    // a hash of its committed preimage. The preimage comes from the secret derived
    // tree, so a party without the secrets cannot compute the outputs and cannot
    // know the committee ahead of the reveal.
    //
    // Two validators identical in every public field, id, stake, weight, differ only
    // in their secret. Their outputs for one beacon and slot differ, so the public
    // fields do not determine the draw: only the secret does.
    let beacon = Beacon::genesis();
    let slot = 9;

    let one = SamplerValidator::from_secret(1, &[0x10u8; 32], 100);
    let two = SamplerValidator::from_secret(1, &[0x20u8; 32], 100);

    let out_one = one.reveal(slot).value(&beacon, DOMAIN_COMMITTEE, slot);
    let out_two = two.reveal(slot).value(&beacon, DOMAIN_COMMITTEE, slot);
    assert_ne!(
        out_one, out_two,
        "the draw is fixed by the secret, so public fields cannot predict it"
    );

    // A verifier holding only the registration, id, root and weight, has no way to
    // produce the preimage the output is computed from; the registration carries the
    // root but not the seed or any preimage.
    let reg = Registration::of(&one);
    assert_eq!(reg.id, 1);
    assert_eq!(reg.weight, 100);
    // The registration is only a commitment; there is no preimage in it to hash.
    let _ = reg.root;
}

#[test]
fn the_draw_still_functions_and_an_honest_validator_is_selected() {
    // With real per secret keys the sortition still works: a staked, honest validator
    // is drawn into the committee and can be elected leader against its own root.
    let validators = vec![
        SamplerValidator::from_secret(1, &[0x71u8; 32], 2_000),
        SamplerValidator::from_secret(2, &[0x72u8; 32], 2_000),
        SamplerValidator::from_secret(3, &[0x73u8; 32], 2_000),
    ];
    let reg = Registry::new(validators).with_budget(SATURATING_BUDGET).with_floor(0);
    let beacon = Beacon::genesis();
    let slot = 1;

    let committee = reg.sample_committee(&beacon, slot);
    assert!(!committee.is_empty(), "an honest committee was drawn");
    let leader = reg.elect_leader(&committee, &beacon, slot).expect("a leader is elected");
    assert!(committee.contains(leader.id));

    // The leader's credential authenticates to its own registered root.
    let root = reg.registration(leader.id).unwrap().root;
    assert!(verify_membership(&root, slot, &leader.credential));
}
