//! A selected validator produces a proof that verifies, and a validator that is
//! not entitled cannot produce a passing proof. Verification uses only the public
//! key, the public stake, and the beacon, never the secret key.

use qtv_sampler::beacon::Beacon;
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::sortition::{draw, verify_selection};
use qtv_sampler::validator::SamplerValidator;

// A budget that saturates the single validator's stake share, so a valid draw is
// always admitted.
const SATURATING_BUDGET: u64 = 4;

#[test]
fn selected_validator_proof_verifies() {
    let v = SamplerValidator::new(1, 100);
    let beacon = Beacon::genesis();
    let d = draw(&v, &beacon, DOMAIN_COMMITTEE, 0);
    assert!(verify_selection(
        v.public_key(),
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        100,
        100,
        SATURATING_BUDGET,
        &d,
    ));
}

#[test]
fn a_prover_is_never_entitled() {
    // A prover holds zero weight, so no draw is ever below its threshold and no
    // membership proof passes, whatever the total and budget.
    let p = SamplerValidator::prover(9);
    let beacon = Beacon::genesis();
    let d = draw(&p, &beacon, DOMAIN_COMMITTEE, 0);
    assert!(!verify_selection(
        p.public_key(),
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        0,
        100,
        SATURATING_BUDGET,
        &d,
    ));
}

#[test]
fn an_unentitled_validator_has_a_genuine_but_failing_proof() {
    // One tiny stake among a large total. The draw is a genuine verifiable
    // random output, shown by its passing under a budget that saturates the
    // share, yet it fails the real stake weighted membership check. Because the
    // function is deterministic the validator cannot grind a lower output.
    let v = SamplerValidator::new(1, 1);
    let total = 1_000_000;
    let beacon = Beacon::genesis();
    let d = draw(&v, &beacon, DOMAIN_COMMITTEE, 0);

    let genuine = verify_selection(
        v.public_key(),
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        1,
        total,
        total, // budget == total saturates the share, so a valid draw passes
        &d,
    );
    let entitled = verify_selection(
        v.public_key(),
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        1,
        total,
        1, // the real budget: the sliver threshold is not met
        &d,
    );
    assert!(genuine, "the proof is a valid verifiable random output");
    assert!(!entitled, "the validator is not entitled at its true stake");
}

#[test]
fn a_tampered_proof_does_not_verify() {
    let v = SamplerValidator::new(1, 100);
    let beacon = Beacon::genesis();
    let mut d = draw(&v, &beacon, DOMAIN_COMMITTEE, 0);
    d.proof[0] ^= 1;
    assert!(!verify_selection(
        v.public_key(),
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        100,
        100,
        SATURATING_BUDGET,
        &d,
    ));
}

#[test]
fn another_key_does_not_verify_the_draw() {
    let v = SamplerValidator::new(1, 100);
    let other = SamplerValidator::new(2, 100);
    let beacon = Beacon::genesis();
    let d = draw(&v, &beacon, DOMAIN_COMMITTEE, 0);
    assert!(!verify_selection(
        other.public_key(),
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        100,
        100,
        SATURATING_BUDGET,
        &d,
    ));
}
