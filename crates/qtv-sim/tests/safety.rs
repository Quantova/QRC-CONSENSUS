// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sim::fault::FaultConfig;
use qtv_sim::sim::Simulation;

const ROUNDS: u64 = 8;
const SEED: u64 = 12648430;

#[test]
fn beyond_tolerance_stalls_without_conflicting_finality() {
    let set = FaultConfig::new().conflicting(2).conflicting(3).build(4);
    let sim = Simulation::new(set, 4, SEED);
    for outcome in sim.run(ROUNDS) {
        assert!(!outcome.finalized());
        assert!(outcome.certificate.is_none());
        assert!(outcome.final_block().is_none());
    }
}

#[test]
fn equivocator_is_flagged_for_slashing() {
    let set = FaultConfig::new().equivocating(2).build(4);
    let sim = Simulation::new(set, 4, SEED);
    for outcome in sim.run(ROUNDS) {
        assert!(outcome.finalized());
        assert!(outcome.slashed.contains(&2));
    }
}

#[test]
fn same_seed_and_faults_give_identical_results() {
    let config = FaultConfig::new().offline(0).equivocating(2);
    let first = Simulation::new(config.build(4), 4, 4660).run(16);
    let second = Simulation::new(config.build(4), 4, 4660).run(16);
    assert_eq!(first, second);
}
