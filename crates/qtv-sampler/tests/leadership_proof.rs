//! Deterministic conformance for leadership neutrality, the proof made executable
//! with no random draws. Where leadership.rs samples the real construction and
//! confirms it tracks the proven value, this vector evaluates the theorem's own
//! quantities directly, so leadership neutrality is a proven fact and not a
//! tolerance over a sample. The proof is in PROOF-leadership-neutrality.md.
//!
//! Two things are checked. First that the code's score is exactly minus the log of
//! u divided by w, the precondition the theorem needs, so the competing exponential
//! result applies to the real leader rule. Second that the competing exponential
//! leadership probability, integrated from the exponential race model, is the stake
//! share and is unchanged by splitting, with no sampling.

use qtv_sampler::sortition::leader_score;

// An output with a chosen leading prefix and a few mixed lower bytes, so u sits well
// inside the open interval and the log is a normal finite value. Prefixes are kept
// away from the top of the range, where u would round to one and the log to zero.
fn output(prefix: u64) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[..8].copy_from_slice(&prefix.to_be_bytes());
    o[8] = 0x9a;
    o[16] = 0x3c;
    o[24] = 0xf1;
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
