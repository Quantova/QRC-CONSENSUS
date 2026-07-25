// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Conformance vector for the minimum self stake floor. The floor is load bearing
//! for the leadership neutrality proof, not only for the break even economics,
//! because the proof is exact only while every account's stake fraction sits above
//! the floating point cliff near u equal to one, and the floor is what holds it
//! there. So a below floor account must be rejected from the committee, and this
//! vector pins that as a tested fact. These registries do not override the floor,
//! so they prove it defaults on in production and nobody has to remember to enable
//! it. The proof and its epsilon are in PROOF-leadership-neutrality.md.

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::Registry;
use qtv_sampler::params::MIN_SELF_STAKE;
use qtv_sampler::validator::SamplerValidator;

#[test]
fn a_below_floor_account_is_never_in_the_committee() {
    // One account at the floor and one a single unit below it, with a saturating
    // budget so eligibility is the only gate. Over many slots the below floor account
    // never appears, so the floor rejects it and not by chance.
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
    // An account exactly at the floor is admitted under a saturating budget, so the
    // floor rejects below it and not at it.
    let reg = Registry::new(vec![SamplerValidator::new(1, MIN_SELF_STAKE)]).with_budget(1_000);
    let committee = reg.sample_committee(&Beacon::genesis(), 0);
    assert!(
        committee.ids().contains(&1),
        "an at floor account was rejected"
    );
}

#[test]
fn a_below_floor_account_does_not_count_in_the_weight_or_totals() {
    // Only the at floor account counts toward the total weight and the weights, so
    // the base the thresholds and the leadership shares divide by is the eligible
    // stake alone.
    let reg = Registry::new(vec![
        SamplerValidator::new(1, MIN_SELF_STAKE),
        SamplerValidator::new(2, MIN_SELF_STAKE - 1),
    ]);
    assert_eq!(reg.total_weight(), MIN_SELF_STAKE);
    assert_eq!(reg.weights(), vec![MIN_SELF_STAKE]);
}

#[test]
fn the_default_registry_has_the_floor_on() {
    // The floor defaults on, so a registry built the ordinary way rejects a below
    // floor account with no override, which is what makes the neutrality proof hold
    // in production rather than only when someone remembers to enable the floor.
    let reg = Registry::new(vec![SamplerValidator::new(1, MIN_SELF_STAKE - 1)]).with_budget(1_000);
    assert_eq!(reg.floor(), MIN_SELF_STAKE);
    let committee = reg.sample_committee(&Beacon::genesis(), 0);
    assert!(
        committee.ids().is_empty(),
        "the default floor did not reject a below floor account"
    );
}
