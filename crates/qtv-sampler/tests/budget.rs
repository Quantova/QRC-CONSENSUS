//! The committee size respects the budget bound. The budget is the target

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::Registry;
use qtv_sampler::sortition::{expected_committee_size, is_selected};
use qtv_sampler::validator::SamplerValidator;

fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[test]
fn expected_committee_size_equals_the_budget() {
    let weights = vec![200u64; 50];
    let budget = 20;
    let size = expected_committee_size(&weights, budget);
    assert!((size - budget as f64).abs() < 1e-9, "size was {size}");
}

#[test]
fn a_budget_above_the_set_yields_the_set_and_no_more() {
    // Every share saturates, so the expected size is the set, not beyond it.
    let weights = vec![1u64; 8];
    let size = expected_committee_size(&weights, 100);
    assert!((size - 8.0).abs() < 1e-9, "size was {size}");
}

#[test]
fn mean_committee_size_stays_near_the_budget() {
    let n = 100usize;
    let weight = 100u64;
    let total = weight * n as u64;
    let budget = 30u64;
    let rounds = 400u32;
    let mut state = 0xDEAD_BEEF;
    let mut sum = 0u64;
    for _ in 0..rounds {
        let mut size = 0u64;
        for _ in 0..n {
            let value = next(&mut state);
            if is_selected(value, weight, total, budget) {
                size += 1;
            }
        }
        assert!(size <= n as u64);
        sum += size;
    }
    let mean = sum as f64 / rounds as f64;
    assert!((mean - budget as f64).abs() < 3.0, "mean was {mean}");
}

#[test]
fn a_real_committee_never_exceeds_the_validator_set() {
    let reg = Registry::new(vec![
        SamplerValidator::new(1, 100),
        SamplerValidator::new(2, 100),
        SamplerValidator::new(3, 100),
    ])
    .with_budget(2);
    let committee = reg.sample_committee(&Beacon::genesis(), 0);
    assert!(committee.len() <= 3);
}

#[test]
fn a_generous_real_budget_selects_the_whole_set() {
    let reg = Registry::new(vec![
        SamplerValidator::new(1, 100),
        SamplerValidator::new(2, 100),
    ])
    .with_budget(50);
    let committee = reg.sample_committee(&Beacon::genesis(), 0);
    assert_eq!(committee.len(), 2);
}
