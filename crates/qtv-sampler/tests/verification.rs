//! A selected account produces a credential that verifies against its registered
//! root, and an account that is not entitled cannot produce a passing credential.
//! Verification uses only the registered root, the public stake, and the beacon,
//! never a secret.

use qtv_sampler::beacon::Beacon;
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::sortition::verify_selection;
use qtv_sampler::validator::SamplerValidator;

// A budget that saturates the single account's stake share, so a valid draw is
// always admitted.
const SATURATING_BUDGET: u64 = 4;

#[test]
fn selected_account_credential_verifies() {
    let v = SamplerValidator::new(1, 100);
    let beacon = Beacon::genesis();
    let cred = v.reveal(0);
    assert!(verify_selection(
        &v.root(),
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        100,
        100,
        SATURATING_BUDGET,
        &cred,
    ));
}

#[test]
fn a_prover_is_never_entitled() {
    // A prover holds zero weight, so no output is ever below its threshold and no
    // membership credential passes, whatever the total and budget.
    let p = SamplerValidator::prover(9);
    let beacon = Beacon::genesis();
    let cred = p.reveal(0);
    assert!(!verify_selection(
        &p.root(),
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        0,
        100,
        SATURATING_BUDGET,
        &cred,
    ));
}

#[test]
fn an_unentitled_account_has_a_genuine_but_failing_credential() {
    // One tiny stake among a large total. The credential is a genuine one time
    // reveal, shown by its passing under a budget that saturates the share, yet it
    // fails the real stake weighted membership check. Because the output is a fixed
    // hash the account cannot grind a lower one.
    let v = SamplerValidator::new(1, 1);
    let total = 1_000_000;
    let beacon = Beacon::genesis();
    let cred = v.reveal(0);

    let genuine = verify_selection(
        &v.root(),
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        1,
        total,
        total, // budget == total saturates the share, so a valid draw passes
        &cred,
    );
    let entitled = verify_selection(
        &v.root(),
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        1,
        total,
        1, // the real budget: the sliver threshold is not met
        &cred,
    );
    assert!(genuine, "the credential is a valid one time reveal");
    assert!(!entitled, "the account is not entitled at its true stake");
}

#[test]
fn a_tampered_preimage_does_not_verify() {
    let v = SamplerValidator::new(1, 100);
    let beacon = Beacon::genesis();
    let mut cred = v.reveal(0);
    cred.preimage[0] ^= 1;
    // A preimage that is not the committed leaf fails the Merkle check against the
    // registered root, so the credential no longer authenticates.
    assert!(!verify_selection(
        &v.root(),
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        100,
        100,
        SATURATING_BUDGET,
        &cred,
    ));
}

#[test]
fn another_root_does_not_verify_the_credential() {
    let v = SamplerValidator::new(1, 100);
    let other = SamplerValidator::new(2, 100);
    let beacon = Beacon::genesis();
    let cred = v.reveal(0);
    // The credential authenticates to its own account's root, not another's.
    assert!(!verify_selection(
        &other.root(),
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        100,
        100,
        SATURATING_BUDGET,
        &cred,
    ));
}
