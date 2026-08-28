// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sampler::beacon::Beacon;
use qtv_sampler::params::DOMAIN_LEADER;
use qtv_sampler::sortition::{leader_score, output_value, Credential};
use qtv_sampler::validator::SamplerValidator;

struct Candidate {
    weight: u64,
    is_attacker: bool,
    credential: Credential,
}

fn candidate(id: u64, weight: u64, is_attacker: bool) -> Candidate {
    let v = SamplerValidator::new(id, weight);
    Candidate {
        weight,
        is_attacker,
        credential: v.reveal(0),
    }
}

fn beacon_at(i: u64) -> Beacon {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    seed[8..16].copy_from_slice(b"LEADERSH");
    Beacon::from_seed(seed)
}

const DRAWS: u64 = 6_000;

fn attacker_leadership_weighted(cands: &[Candidate]) -> f64 {
    let mut wins = 0u64;
    for i in 0..DRAWS {
        let beacon = beacon_at(i);
        let mut best: Option<(f64, usize)> = None;
        for (idx, c) in cands.iter().enumerate() {
            let output = c.credential.output(&beacon, DOMAIN_LEADER, 0);
            let score = leader_score(&output, c.weight);
            let take = match best {
                None => true,
                Some((bs, _)) => score < bs,
            };
            if take {
                best = Some((score, idx));
            }
        }
        if cands[best.unwrap().1].is_attacker {
            wins += 1;
        }
    }
    wins as f64 / DRAWS as f64
}

fn attacker_leadership_unweighted(cands: &[Candidate]) -> f64 {
    let mut wins = 0u64;
    for i in 0..DRAWS {
        let beacon = beacon_at(i);
        let mut best: Option<(u64, usize)> = None;
        for (idx, c) in cands.iter().enumerate() {
            let value = output_value(&c.credential.output(&beacon, DOMAIN_LEADER, 0));
            let take = match best {
                None => true,
                Some((bv, _)) => value < bv,
            };
            if take {
                best = Some((value, idx));
            }
        }
        if cands[best.unwrap().1].is_attacker {
            wins += 1;
        }
    }
    wins as f64 / DRAWS as f64
}

#[test]
fn splitting_does_not_raise_leadership_probability() {
    let honest = 1_000u64;
    let attacker = 1_000u64;
    let share = attacker as f64 / (honest + attacker) as f64;

    let whole = vec![candidate(1, honest, false), candidate(2, attacker, true)];

    let mut split = vec![candidate(1, honest, false)];
    for k in 0..10 {
        split.push(candidate(100 + k, attacker / 10, true));
    }

    let whole_freq = attacker_leadership_weighted(&whole);
    let split_freq = attacker_leadership_weighted(&split);

    assert!(
        (whole_freq - share).abs() < 0.04,
        "whole leadership {whole_freq} strayed from the share {share}"
    );
    assert!(
        (split_freq - share).abs() < 0.04,
        "split leadership {split_freq} strayed from the share {share}"
    );
    assert!(
        split_freq <= whole_freq + 0.03,
        "splitting raised leadership from {whole_freq} to {split_freq}"
    );
}

#[test]
fn finer_splitting_still_does_not_raise_leadership() {
    let honest = 1_000u64;
    let attacker = 1_000u64;
    let share = attacker as f64 / (honest + attacker) as f64;

    let whole = vec![candidate(1, honest, false), candidate(2, attacker, true)];
    let mut fine = vec![candidate(1, honest, false)];
    for k in 0..40 {
        fine.push(candidate(200 + k, attacker / 40, true));
    }

    let whole_freq = attacker_leadership_weighted(&whole);
    let fine_freq = attacker_leadership_weighted(&fine);

    assert!((fine_freq - share).abs() < 0.04, "fine split {fine_freq}");
    assert!(
        fine_freq <= whole_freq + 0.03,
        "fine splitting raised leadership from {whole_freq} to {fine_freq}"
    );
}

#[test]
fn the_naive_lowest_output_rule_is_beaten_by_splitting() {
    let honest = 1_000u64;
    let attacker = 1_000u64;
    let share = attacker as f64 / (honest + attacker) as f64;

    let whole = vec![candidate(1, honest, false), candidate(2, attacker, true)];
    let mut split = vec![candidate(1, honest, false)];
    for k in 0..10 {
        split.push(candidate(100 + k, attacker / 10, true));
    }

    let whole_naive = attacker_leadership_unweighted(&whole);
    let split_naive = attacker_leadership_unweighted(&split);

    assert!(
        (whole_naive - share).abs() < 0.04,
        "whole naive {whole_naive}"
    );
    assert!(
        split_naive > share + 0.15,
        "splitting did not beat the naive rule, split {split_naive} share {share}"
    );
}
