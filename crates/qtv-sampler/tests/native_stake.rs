// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Only native stake counts. A bridged origin tagged holding is rejected as
//! weight however large its amount, so it never lifts a validator into the
//! committee and never lifts the total weight.

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::Registry;
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::sortition::verify_selection;
use qtv_sampler::stake::{OriginTag, Stake};
use qtv_sampler::validator::SamplerValidator;

const TAG: OriginTag = OriginTag {
    chain: 1,
    asset: 42,
};

#[test]
fn a_bridged_holding_is_never_selected() {
    let v = SamplerValidator::with_stake(1, Stake::bridged(1_000_000, TAG));
    assert_eq!(v.weight(), 0);
    let beacon = Beacon::genesis();
    let cred = v.reveal(0);
    // Even a budget as large as the whole bridged amount cannot admit a zero
    // weight holding.
    assert!(!verify_selection(
        &v.root(),
        &beacon,
        DOMAIN_COMMITTEE,
        0,
        v.weight(),
        1_000_000,
        1_000_000,
        &cred,
    ));
}

#[test]
fn a_bridged_validator_stays_out_of_the_committee() {
    let reg = Registry::new(vec![
        SamplerValidator::new(1, 100),
        SamplerValidator::with_stake(2, Stake::bridged(1_000_000, TAG)),
    ])
    .with_budget(50)
    .with_floor(0);
    // The bridged holding does not count toward the total weight.
    assert_eq!(reg.total_weight(), 100);
    let committee = reg.sample_committee(&Beacon::genesis(), 0);
    assert!(committee.contains(1));
    assert!(!committee.contains(2));
}

#[test]
fn the_same_amount_held_native_is_valid_weight() {
    let native = SamplerValidator::new(1, 1_000_000);
    assert_eq!(native.weight(), 1_000_000);
}
