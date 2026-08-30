// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::same_item_push)]

use qtv_sampler::sortition::leader_score;

fn output(prefix: u64) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[..8].copy_from_slice(&prefix.to_be_bytes());
    o[8] = 154;
    o[16] = 60;
    o[24] = 241;
    o
}

#[test]
fn the_score_is_exactly_minus_log_u_over_w() {
    for prefix in [1u64, 7, 1 << 20, 1 << 40, u64::MAX / 7, u64::MAX / 3] {
        let o = output(prefix);
        let base = leader_score(&o, 1);
        assert!(
            base.is_finite() && base > 0.0,
            "base score must be finite positive"
        );
        for w in [2u64, 100, 1_000, 999_983] {
            let s = leader_score(&o, w);
            let reconstructed = s * w as f64;
            assert!(
                (reconstructed - base).abs() <= 1e-9 * base.max(1.0),
                "score at w={w} is not exactly base over w"
            );
        }
    }
}

fn leadership_probability_by_integration(weights: &[f64], i: usize) -> f64 {
    let total: f64 = weights.iter().sum();
    let w_i = weights[i];
    let dt = 1.0 / (total * 4_000.0);
    let t_max = 40.0 / total;
    let mut integral = 0.0f64;
    let mut t = 0.0f64;
    while t < t_max {
        let mid = t + dt / 2.0;
        integral += w_i * (-total * mid).exp() * dt;
        t += dt;
    }
    integral
}

#[test]
fn leadership_probability_integrates_to_stake_share() {
    let weights = vec![1_000.0, 1_000.0];
    let p = leadership_probability_by_integration(&weights, 1);
    assert!(
        (p - 0.5).abs() < 1e-6,
        "integrated probability {p} strayed from the share"
    );
}

#[test]
fn splitting_is_neutral_by_the_model_with_no_draws() {
    let whole = vec![1_000.0, 1_000.0];
    let whole_attacker = leadership_probability_by_integration(&whole, 1);

    let mut split = vec![1_000.0];
    for _ in 0..10 {
        split.push(100.0);
    }
    let split_attacker: f64 = (1..split.len())
        .map(|i| leadership_probability_by_integration(&split, i))
        .sum();

    assert!(
        (whole_attacker - 0.5).abs() < 1e-6,
        "whole {whole_attacker}"
    );
    assert!(
        (split_attacker - 0.5).abs() < 1e-6,
        "split {split_attacker}"
    );
    assert!(
        (whole_attacker - split_attacker).abs() < 1e-6,
        "splitting changed leadership from {whole_attacker} to {split_attacker}"
    );
}

#[test]
fn finer_splitting_is_still_neutral_by_the_model() {
    let mut fine = vec![1_000.0];
    for _ in 0..40 {
        fine.push(25.0);
    }
    let fine_attacker: f64 = (1..fine.len())
        .map(|i| leadership_probability_by_integration(&fine, i))
        .sum();
    assert!(
        (fine_attacker - 0.5).abs() < 1e-6,
        "fine split {fine_attacker}"
    );
}

#[test]
fn the_minimum_stake_winning_window_sits_above_the_float_cliff() {
    let supply = 4_571_429u64;
    let min_stake = 2_000u64;
    let f = min_stake as f64 / supply as f64;
    let cliff = 2f64.powi(-53);
    assert!(
        f > cliff * 1e6,
        "min stake window is not far above the float cliff"
    );

    let u_edge = 1.0 - f;
    assert!(u_edge < 1.0, "winning window edge collapsed to one");
    let score_edge = -u_edge.ln() / min_stake as f64;
    assert!(
        score_edge.is_finite() && score_edge > 0.0,
        "edge score collapsed to zero, the cliff triggered"
    );

    let u_half = 1.0 - f / 2.0;
    assert!(
        u_half > u_edge && u_half < 1.0,
        "half window did not resolve"
    );
    let score_half = -u_half.ln() / min_stake as f64;
    assert!(
        score_half < score_edge,
        "window is not resolved into distinct scores"
    );
}
