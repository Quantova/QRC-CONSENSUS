// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sampler::beacon::Beacon;
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::sortition::verify_selection;
use qtv_sampler::validator::SamplerValidator;

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
        total,
        &cred,
    );
    let entitled = verify_selection(&v.root(), &beacon, DOMAIN_COMMITTEE, 0, 1, total, 1, &cred);
    assert!(genuine, "the credential is a valid one time reveal");
    assert!(!entitled, "the account is not entitled at its true stake");
}

#[test]
fn a_tampered_preimage_does_not_verify() {
    let v = SamplerValidator::new(1, 100);
    let beacon = Beacon::genesis();
    let mut cred = v.reveal(0);
    cred.preimage[0] ^= 1;
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
