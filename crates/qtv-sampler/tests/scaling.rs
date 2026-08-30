// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::Registry;
use qtv_sampler::params::{
    finality_threshold, ADVERSARY_STAKE_DEN, ADVERSARY_STAKE_NUM, COMMITTEE_BUDGET,
};
use qtv_sampler::sortition::{expected_committee, expected_committee_size};
use qtv_sampler::validator::SamplerValidator;

const STAKE: u64 = 5_000;

#[test]
fn the_committee_stays_bounded_by_the_budget_as_the_set_grows_a_thousandfold() {
    let budget = COMMITTEE_BUDGET;
    for multiple in [1u64, 2, 10, 100, 1000] {
        let n = (budget * multiple) as usize;
        let weights = vec![STAKE; n];
        let size = expected_committee_size(&weights, budget);
        assert!(
            size <= budget as f64 + 1e-6,
            "a set of {n} never draws more than the budget, drew {size}"
        );
        assert!(
            (size - budget as f64).abs() < 1.0,
            "a set of {n} draws essentially the budget {budget}, drew {size}"
        );
    }
}

#[test]
fn a_thousandfold_larger_set_finalises_with_the_same_size_committee() {
    let budget = COMMITTEE_BUDGET;
    let five_hundred = expected_committee_size(&vec![STAKE; budget as usize], budget);
    let half_a_million = expected_committee_size(&vec![STAKE; (budget * 1000) as usize], budget);
    assert!(
        (five_hundred - half_a_million).abs() < 1.0,
        "committee at 500 was {five_hundred}, at 500k was {half_a_million}, they must match"
    );
}

#[test]
fn the_threshold_is_a_two_thirds_supermajority_the_adversary_cannot_span() {
    let budget = COMMITTEE_BUDGET;
    let weights = vec![STAKE; (budget * 20) as usize];
    let expected = expected_committee(&weights, budget);
    assert_eq!(expected, budget);
    let tau = finality_threshold(expected);
    assert_eq!(tau, budget * 2 / 3 + 1);
    let adversary = expected * ADVERSARY_STAKE_NUM / ADVERSARY_STAKE_DEN;
    let honest = expected - adversary;
    assert!(
        adversary < tau,
        "the adversary expectation must fall below the threshold"
    );
    assert!(
        2 * tau - expected > adversary,
        "two agreeing sets share more than the adversary can hold"
    );
    assert!(tau <= honest, "the honest set must reach the threshold");
}

#[test]
fn a_real_sortition_draw_stays_bounded_far_below_a_large_set() {
    let budget = 200u64;
    let n = 10_000usize;
    let validators: Vec<SamplerValidator> = (0..n)
        .map(|i| SamplerValidator::with_slots(i as u64 + 1, STAKE, 1))
        .collect();
    let reg = Registry::new(validators).with_budget(budget).with_floor(0);
    let committee = reg.sample_committee(&Beacon::genesis(), 0);
    assert!(
        committee.len() < (budget as f64 * 1.5) as usize,
        "a real draw of {} is near the budget {budget}",
        committee.len()
    );
    assert!(
        committee.len() > (budget as f64 * 0.5) as usize,
        "a real draw of {} is near the budget {budget}",
        committee.len()
    );
    assert!(
        committee.len() < n / 10,
        "a real draw of {} is far below the set of {n}",
        committee.len()
    );
}
