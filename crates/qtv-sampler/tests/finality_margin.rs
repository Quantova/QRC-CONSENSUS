// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::Registry;
use qtv_sampler::params::{finality_threshold, COMMITTEE_BUDGET};
use qtv_sampler::sortition::expected_committee;
use qtv_sampler::validator::SamplerValidator;

const STAKE: u64 = 5_000;
const SET: usize = 5_000;
const SLOTS: u64 = 256;

fn realized_draws() -> (u64, Vec<u64>) {
    let validators: Vec<SamplerValidator> = (0..SET)
        .map(|i| SamplerValidator::with_slots(i as u64 + 1, STAKE, SLOTS))
        .collect();
    let registry = Registry::new(validators)
        .with_budget(COMMITTEE_BUDGET)
        .with_floor(0);
    let beacon = Beacon::genesis();
    let expected = expected_committee(&vec![STAKE; SET], COMMITTEE_BUDGET);
    let draws = (0..SLOTS)
        .map(|slot| registry.sample_committee(&beacon, slot).len() as u64)
        .collect();
    (expected, draws)
}

fn fork_feasible(total: u64, adversary: u64, tau: u64) -> bool {
    adversary + total >= 2 * tau
}

#[test]
fn pinning_tau_to_the_expected_size_is_fork_feasible_when_the_draw_over_draws() {
    let (expected, draws) = realized_draws();
    let tau = finality_threshold(expected);
    let mut over_draw_seen = false;
    let mut feasible_slots = 0u64;
    for &total in &draws {
        if total > expected {
            over_draw_seen = true;
        }
        let adversary = total / 3;
        if fork_feasible(total, adversary, tau) {
            feasible_slots += 1;
        }
    }
    assert!(over_draw_seen, "the sweep must exercise an over draw of the expected size");
    assert!(
        feasible_slots > 0,
        "a threshold pinned to the expected size leaves fork feasible slots under an over draw"
    );
}

#[test]
fn deriving_tau_from_the_realized_draw_closes_the_fork_at_every_adversary_share() {
    let (expected, draws) = realized_draws();
    for pct in [10u64, 20, 30, 33] {
        for &total in &draws {
            let tau = finality_threshold(expected.max(total));
            let adversary = total * pct / 100;
            assert!(
                !fork_feasible(total, adversary, tau),
                "draw {total} at {pct}% adversary must not admit two conflicting certificates, tau {tau}"
            );
        }
    }
}

#[test]
fn a_draw_smaller_than_expected_keeps_the_expected_floor_and_stays_safe() {
    let (expected, draws) = realized_draws();
    let mut under_draw_seen = false;
    for &total in &draws {
        if total < expected {
            under_draw_seen = true;
            let tau = finality_threshold(expected.max(total));
            assert_eq!(
                tau,
                finality_threshold(expected),
                "an under draw must not lower the threshold below the expected floor"
            );
            assert!(
                !fork_feasible(total, total / 3, tau),
                "an under draw at a third adversary must stay safe under the floor"
            );
        }
    }
    assert!(under_draw_seen, "the sweep must exercise an under draw of the expected size");
}
