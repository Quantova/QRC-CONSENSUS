// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::Registry;
use qtv_sampler::params::MIN_SELF_STAKE;
use qtv_sampler::validator::SamplerValidator;

#[test]
fn a_below_floor_account_is_never_in_the_committee() {
    let reg = Registry::new(vec![
        SamplerValidator::new(1, MIN_SELF_STAKE),
        SamplerValidator::new(2, MIN_SELF_STAKE - 1),
    ])
    .with_budget(1_000);
    for slot in 0..32 {
        let committee = reg.sample_committee(&Beacon::genesis(), slot);
        assert!(
            !committee.ids().contains(&2),
            "a below floor account entered the committee at slot {slot}"
        );
    }
}

#[test]
fn an_account_at_the_floor_is_eligible() {
    let reg = Registry::new(vec![SamplerValidator::new(1, MIN_SELF_STAKE)]).with_budget(1_000);
    let committee = reg.sample_committee(&Beacon::genesis(), 0);
    assert!(
        committee.ids().contains(&1),
        "an at floor account was rejected"
    );
}

#[test]
fn a_below_floor_account_does_not_count_in_the_weight_or_totals() {
    let reg = Registry::new(vec![
        SamplerValidator::new(1, MIN_SELF_STAKE),
        SamplerValidator::new(2, MIN_SELF_STAKE - 1),
    ]);
    assert_eq!(reg.total_weight(), MIN_SELF_STAKE);
    assert_eq!(reg.weights(), vec![MIN_SELF_STAKE]);
}

#[test]
fn the_default_registry_has_the_floor_on() {
    let reg = Registry::new(vec![SamplerValidator::new(1, MIN_SELF_STAKE - 1)]).with_budget(1_000);
    assert_eq!(reg.floor(), MIN_SELF_STAKE);
    let committee = reg.sample_committee(&Beacon::genesis(), 0);
    assert!(
        committee.ids().is_empty(),
        "the default floor did not reject a below floor account"
    );
}
