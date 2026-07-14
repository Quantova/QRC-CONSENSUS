//! Deterministic multi round driver. The beacon of one round seeds the next,
//! so a run is fully determined by the validator set, the committee size and
//! the initial seed.

use crate::round::{run_round, RoundOutcome};
use crate::validator::ValidatorSet;

#[derive(Clone, Debug)]
pub struct Simulation {
    pub set: ValidatorSet,
    pub committee_size: usize,
    pub seed: u64,
}

impl Simulation {
    pub fn new(set: ValidatorSet, committee_size: usize, seed: u64) -> Self {
        Simulation {
            set,
            committee_size,
            seed,
        }
    }

    pub fn run(&self, rounds: u64) -> Vec<RoundOutcome> {
        let mut seed = self.seed;
        let mut out = Vec::with_capacity(rounds as usize);
        for height in 0..rounds {
            let outcome = run_round(&self.set, height, seed, self.committee_size);
            seed = outcome.next_seed;
            out.push(outcome);
        }
        out
    }
}
