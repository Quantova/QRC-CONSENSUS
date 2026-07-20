//! Finality cost does not grow as validators join. The committee that finalises a block is a
//! sortition sample bounded by the budget, not the whole validator set. The work a certificate
//! carries is proportional to the committee, so it stays flat however large the set grows. This is
//! the property that keeps throughput and finality from degrading as the network decentralises: five
//! hundred validators and five hundred thousand finalise with the same size committee.

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::Registry;
use qtv_sampler::params::COMMITTEE_BUDGET;
use qtv_sampler::sortition::expected_committee_size;
use qtv_sampler::validator::SamplerValidator;

/// Every validator equally staked, above the two thousand floor.
const STAKE: u64 = 5_000;

#[test]
fn the_committee_stays_bounded_by_the_budget_as_the_set_grows_a_thousandfold() {
    // The validator set grows by three orders of magnitude, from the budget to a thousand times it.
    // The expected committee size, the number of members a certificate must carry, stays pinned at
    // the budget the whole way, so the finality work does not grow with the set.
    let budget = COMMITTEE_BUDGET;
    for multiple in [1u64, 2, 10, 100, 1000] {
        let n = (budget * multiple) as usize;
        let weights = vec![STAKE; n];
        let size = expected_committee_size(&weights, budget);
        assert!(
            size <= budget as f64 + 1e-6,
            "a set of {n} never draws more than the budget, drew {size}"
        );
        assert!(
            (size - budget as f64).abs() < 1.0,
            "a set of {n} draws essentially the budget {budget}, drew {size}"
        );
    }
}

#[test]
fn a_thousandfold_larger_set_finalises_with_the_same_size_committee() {
    // Concretely: half a million validators finalise with the same size committee as five hundred, so
    // the certificate, its verification cost, and its bandwidth are identical at both scales.
    let budget = COMMITTEE_BUDGET;
    let five_hundred = expected_committee_size(&vec![STAKE; budget as usize], budget);
    let half_a_million = expected_committee_size(&vec![STAKE; (budget * 1000) as usize], budget);
    assert!(
        (five_hundred - half_a_million).abs() < 1.0,
        "committee at 500 was {five_hundred}, at 500k was {half_a_million}, they must match"
    );
}

#[test]
fn a_real_sortition_draw_stays_bounded_far_below_a_large_set() {
    // The analytic bound is one thing; confirm the actual sortition draw is bounded too. Draw a real
    // committee from a large set and check it sits near the budget and far below the set. One slot
    // trees keep the set cheap to build, the tree is the membership proof and does not affect the
    // stake weighted draw.
    let budget = 200u64;
    let n = 10_000usize;
    let validators: Vec<SamplerValidator> = (0..n)
        .map(|i| SamplerValidator::with_slots(i as u64 + 1, STAKE, 1))
        .collect();
    let reg = Registry::new(validators).with_budget(budget).with_floor(0);
    let committee = reg.sample_committee(&Beacon::genesis(), 0);
    assert!(
        committee.len() < (budget as f64 * 1.5) as usize,
        "a real draw of {} is near the budget {budget}",
        committee.len()
    );
    assert!(
        committee.len() > (budget as f64 * 0.5) as usize,
        "a real draw of {} is near the budget {budget}",
        committee.len()
    );
    assert!(
        committee.len() < n / 10,
        "a real draw of {} is far below the set of {n}",
        committee.len()
    );
}
