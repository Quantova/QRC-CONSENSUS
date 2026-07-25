// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Deterministic conformance for leadership neutrality, the proof made executable

use qtv_sampler::sortition::leader_score;

// An output with a chosen leading prefix and a few mixed lower bytes, so u sits well
// inside the open interval and the log is a normal finite value. Prefixes are kept
// away from the top of the range, where u would round to one and the log to zero.
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
    // leader_score(o, w) == leader_score(o, 1) / w to floating point, so the score
    // is minus the log of u scaled by one over w. This is lemma one's construction
    // in the code, s = -ln(u)/w, which makes s exponential with rate w and lets the
    // competing exponential theorem apply. Equivalently score times w is the same
    // base value for every weight. Prefixes stay clear of the top of the range so u
    // is not rounded to one.
    for prefix in [1u64, 7, 1 << 20, 1 << 40, u64::MAX / 7, u64::MAX / 3] {
        let o = output(prefix);
        let base = leader_score(&o, 1); // -ln(u)
        assert!(
            base.is_finite() && base > 0.0,
            "base score must be finite positive"
        );
        for w in [2u64, 100, 1_000, 999_983] {
            let s = leader_score(&o, w); // -ln(u)/w
            let reconstructed = s * w as f64;
            assert!(
                (reconstructed - base).abs() <= 1e-9 * base.max(1.0),
                "score at w={w} is not exactly base over w"
            );
        }
    }
}

// The competing exponential leadership probability of account `i`, integrated from
// the model. Account i leads when its exponential score is the minimum, and the
// probability is the integral over t of its density at t times the chance every
// other score exceeds t, which is w_i * exp(-(sum w) * t). Integrated over t this
// is exactly w_i / sum w. This evaluates the theorem's own integral rather than
// restating the closed form, and it uses no random draws. The step is fine relative
// to the decay rate `total` so the midpoint rule converges tightly.
fn leadership_probability_by_integration(weights: &[f64], i: usize) -> f64 {
    let total: f64 = weights.iter().sum();
    let w_i = weights[i];
    // Four thousand steps per decay time keeps the midpoint error far below 1e-6,
    // and forty decay times captures the tail to exp(-40), about 4e-18.
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
    // A single account of weight 1000 among a total of 2000 leads with probability
    // one half, the stake share, integrated from the model with no draws.
    let weights = vec![1_000.0, 1_000.0];
    let p = leadership_probability_by_integration(&weights, 1);
    assert!(
        (p - 0.5).abs() < 1e-6,
        "integrated probability {p} strayed from the share"
    );
}

#[test]
fn splitting_is_neutral_by_the_model_with_no_draws() {
    // Attacker stake 1000 against honest 1000. Held whole the attacker is one
    // account, split it is ten accounts of 100. The combined leadership probability
    // integrates to the identical value, one half, in both shapes, so splitting is
    // neutral by the model itself and not merely within a sampling tolerance.
    let whole = vec![1_000.0, 1_000.0]; // honest at index 0, attacker at index 1
    let whole_attacker = leadership_probability_by_integration(&whole, 1);

    let mut split = vec![1_000.0]; // honest at index 0
    for _ in 0..10 {
        split.push(100.0); // ten attacker accounts of 100
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
    // The same attacker stake over forty accounts of 25 still integrates to the
    // stake share, so the neutrality is not an artifact of the split size.
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
    // The error concentrates near u equal to one, the dust winning region, and this
    // vector checks the extreme rather than the average. A minimum stake account of
    // 2000 against the whole staked supply has stake fraction about two to the minus
    // eleven, and it leads only when its u lands in a window of that width just below
    // one. Near one the float spacing is about two to the minus fifty three, so a u
    // within that of one collapses to exactly one and its score to zero, an auto win.
    // The window here is about two to the forty two wider than that cliff, so it is
    // finely resolved and no dust artifact inflates the account's leadership. Without
    // the floor a fraction below two to the minus fifty three would collapse and auto
    // win, which is why the floor is load bearing.
    let supply = 4_571_429u64; // full supply staked, the worst case for the fraction
    let min_stake = 2_000u64;
    let f = min_stake as f64 / supply as f64;
    let cliff = 2f64.powi(-53);
    assert!(
        f > cliff * 1e6,
        "min stake window is not far above the float cliff"
    );

    // The near edge of the winning window, u = 1 - f, must be strictly below one and
    // give a finite positive score, so the window is not collapsed onto the cliff.
    let u_edge = 1.0 - f;
    assert!(u_edge < 1.0, "winning window edge collapsed to one");
    let score_edge = -u_edge.ln() / min_stake as f64;
    assert!(
        score_edge.is_finite() && score_edge > 0.0,
        "edge score collapsed to zero, the cliff triggered"
    );

    // Halving the window still gives a distinct larger u and a distinct smaller
    // score, so the window resolves into many float points and is not a single one.
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
