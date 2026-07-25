// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A prover holds zero votes and is never in a committee. Provers are excluded
//! from the draw and never counted in the weights, so no beacon and no budget
//! can place one in the committee.

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::Registry;
use qtv_sampler::validator::SamplerValidator;

#[test]
fn a_prover_is_never_in_the_committee() {
    let reg = Registry::new(vec![
        SamplerValidator::new(1, 100),
        SamplerValidator::new(2, 100),
        SamplerValidator::prover(3),
    ])
    .with_budget(50)
    .with_floor(0);
    let beacon = Beacon::genesis();
    for slot in 0..3 {
        let committee = reg.sample_committee(&beacon, slot);
        assert!(!committee.contains(3), "prover appeared at slot {slot}");
        assert!(committee.contains(1));
        assert!(committee.contains(2));
    }
}

#[test]
fn a_prover_is_not_counted_in_the_weights() {
    let reg = Registry::new(vec![
        SamplerValidator::new(1, 100),
        SamplerValidator::prover(2),
    ])
    .with_floor(0);
    assert_eq!(reg.total_weight(), 100);
    assert_eq!(reg.weights(), vec![100]);
}
