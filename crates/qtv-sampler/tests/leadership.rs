//! Conformance vector for stake neutral leadership. Committee membership is stake

use qtv_sampler::beacon::Beacon;
use qtv_sampler::params::DOMAIN_LEADER;
use qtv_sampler::sortition::{leader_score, output_value, Credential};
use qtv_sampler::validator::SamplerValidator;

// A leader candidate: its native weight and its fixed one time credential for the
// slot. The credential is beacon independent, so it is revealed once and reused
// while only the output varies with the beacon.
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

// A well mixed beacon for draw index `i`. SHAKE diffuses the seed into the output,
// so writing the index into the seed gives independent draws across beacons.
fn beacon_at(i: u64) -> Beacon {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&i.to_le_bytes());
    seed[8..16].copy_from_slice(b"LEADERSH");
    Beacon::from_seed(seed)
}

const DRAWS: u64 = 6_000;

// The fraction of draws whose leader is an attacker account, under the stake
// weighted exponential race over the whole candidate set.
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

// The same measurement under the naive rule, the lowest raw output leads with no
// stake weighting. This is the rule the design warns against.
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
    // Honest stake 1000 held as one account, attacker stake 1000. The attacker's
    // fair leadership share is 1000 / 2000 = 0.5 in both shapes. Every candidate is
    // in the leader race, isolating the leader rule from committee membership.
    let honest = 1_000u64;
    let attacker = 1_000u64;
    let share = attacker as f64 / (honest + attacker) as f64;

    // Whole: the attacker is one account of weight 1000.
    let whole = vec![candidate(1, honest, false), candidate(2, attacker, true)];

    // Split: the same attacker stake spread over ten accounts of weight 100.
    let mut split = vec![candidate(1, honest, false)];
    for k in 0..10 {
        split.push(candidate(100 + k, attacker / 10, true));
    }

    let whole_freq = attacker_leadership_weighted(&whole);
    let split_freq = attacker_leadership_weighted(&split);

    // Both track the stake share, and splitting does not raise the probability.
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
    // The attacker stake spread even thinner, over forty accounts of weight 25,
    // still does not buy more leadership than holding it whole.
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
    // The demonstration that the weighting is necessary. Under the naive rule,
    // where the lowest raw output leads with no stake weighting, ten small accounts
    // get ten independent chances at a low output, so the attacker leads far more
    // often than its 0.5 stake share. This is the soft spot the exponential race
    // closes.
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

    // Whole is fair even under the naive rule, since both sides are one account of
    // equal weight.
    assert!(
        (whole_naive - share).abs() < 0.04,
        "whole naive {whole_naive}"
    );
    // Splitting clearly beats the naive rule, well above the fair share.
    assert!(
        split_naive > share + 0.15,
        "splitting did not beat the naive rule, split {split_naive} share {share}"
    );
}
