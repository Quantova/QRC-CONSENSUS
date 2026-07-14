//! The same beacon and keys give the same committee and the same leader. The
//! draws are a deterministic function of the key and the beacon input, so two
//! nodes sampling the same slot agree exactly, and a different beacon changes the
//! draws.

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::{Committee, Registry};
use qtv_sampler::validator::SamplerValidator;

fn registry() -> Registry {
    Registry::new(vec![
        SamplerValidator::new(1, 100),
        SamplerValidator::new(2, 100),
    ])
    .with_budget(10)
}

// The ids paired with their draw outputs, the full observable committee.
fn fingerprint(c: &Committee) -> Vec<(u64, [u8; 32])> {
    c.members.iter().map(|m| (m.id, m.draw.output)).collect()
}

#[test]
fn same_beacon_and_keys_give_the_same_committee() {
    let reg = registry();
    let beacon = Beacon::genesis();
    let a = reg.sample_committee(&beacon, 5);
    let b = reg.sample_committee(&beacon, 5);
    assert_eq!(fingerprint(&a), fingerprint(&b));
}

#[test]
fn same_beacon_and_keys_give_the_same_leader() {
    let reg = registry();
    let beacon = Beacon::genesis();
    let committee = reg.sample_committee(&beacon, 5);
    let first = reg.elect_leader(&committee, &beacon, 5).unwrap();
    let second = reg.elect_leader(&committee, &beacon, 5).unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(first.draw.output, second.draw.output);
}

#[test]
fn a_different_beacon_changes_the_draws() {
    let reg = registry();
    let genesis = Beacon::genesis();
    let next = genesis.advance(&[3u8; 32], 1);
    let a = reg.sample_committee(&genesis, 0);
    let b = reg.sample_committee(&next, 0);
    // The generous budget admits the whole set under either beacon, but the
    // verifiable random outputs differ.
    assert_eq!(a.ids(), b.ids());
    assert_ne!(fingerprint(&a), fingerprint(&b));
}
