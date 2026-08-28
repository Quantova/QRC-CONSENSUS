// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sampler::sortition::is_selected;

fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(11400714819323198485);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(13787848793156543929);
    z = (z ^ (z >> 27)).wrapping_mul(10723151780598845931);
    z ^ (z >> 31)
}

const DRAWS: u32 = 40_000;

fn frequency(weight: u64, total: u64, budget: u64, seed: u64) -> f64 {
    let mut state = seed;
    let mut hits = 0u32;
    for _ in 0..DRAWS {
        let value = next(&mut state);
        if is_selected(value, weight, total, budget) {
            hits += 1;
        }
    }
    hits as f64 / DRAWS as f64
}

#[test]
fn selection_frequency_matches_the_stake_share() {
    let low = frequency(1_000, 4_000, 1, 4369);
    let high = frequency(3_000, 4_000, 1, 8738);
    assert!((low - 0.25).abs() < 0.02, "low share was {low}");
    assert!((high - 0.75).abs() < 0.02, "high share was {high}");
    assert!(high > low);
}

#[test]
fn frequency_is_proportional_to_stake() {
    let total = 10;
    let budget = 2;
    let f1 = frequency(1, total, budget, 161);
    let f2 = frequency(2, total, budget, 162);
    let f3 = frequency(3, total, budget, 163);
    let f4 = frequency(4, total, budget, 164);
    assert!(f1 < f2 && f2 < f3 && f3 < f4);
    assert!((f2 / f1 - 2.0).abs() < 0.1, "f2/f1 was {}", f2 / f1);
    assert!((f3 / f1 - 3.0).abs() < 0.15, "f3/f1 was {}", f3 / f1);
    assert!((f4 / f1 - 4.0).abs() < 0.2, "f4/f1 was {}", f4 / f1);
}

#[test]
fn a_saturating_stake_is_always_selected() {
    let f = frequency(100, 100, 1, 9);
    assert_eq!(f, 1.0);
}
