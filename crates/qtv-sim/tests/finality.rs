// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sim::fault::FaultConfig;
use qtv_sim::round::canonical_block;
use qtv_sim::sim::Simulation;
use qtv_sim::validator::ValidatorSet;

const ROUNDS: u64 = 8;
const SEED: u64 = 12648430;

#[test]
fn honest_supermajority_finalizes_each_round() {
    let sim = Simulation::new(ValidatorSet::new(4), 4, SEED);
    for outcome in sim.run(ROUNDS) {
        assert!(outcome.finalized());
        assert!(outcome.slashed.is_empty());
        let cert = outcome.certificate.expect("certificate present");
        assert!(cert.valid);
        assert!(cert.weight >= 3);
        assert_eq!(
            outcome.final_block(),
            Some(canonical_block(outcome.height, outcome.seed))
        );
    }
}

#[test]
fn tolerated_offline_still_finalizes() {
    let set = FaultConfig::new().offline(0).build(4);
    let sim = Simulation::new(set, 4, SEED);
    for outcome in sim.run(ROUNDS) {
        assert!(outcome.finalized());
        assert!(outcome.slashed.is_empty());
        assert_ne!(outcome.proposer, Some(0));
        assert!(outcome.certificate.unwrap().weight >= 3);
    }
}
