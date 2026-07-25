// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The same beacon and roots give the same committee and the same leader. The

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::{Committee, Registry};
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::validator::SamplerValidator;

fn registry() -> Registry {
    Registry::new(vec![
        SamplerValidator::new(1, 100),
        SamplerValidator::new(2, 100),
    ])
    .with_budget(10)
    .with_floor(0)
}

// The ids paired with their committee outputs over the beacon, the full
// observable committee. The output binds the beacon, so it distinguishes draws
// under different beacons even though the committed preimage is the same.
fn fingerprint(c: &Committee, beacon: &Beacon, slot: u64) -> Vec<(u64, [u8; 32])> {
    c.members
        .iter()
        .map(|m| (m.id, m.credential.output(beacon, DOMAIN_COMMITTEE, slot)))
        .collect()
}

#[test]
fn same_beacon_and_roots_give_the_same_committee() {
    let reg = registry();
    let beacon = Beacon::genesis();
    let a = reg.sample_committee(&beacon, 5);
    let b = reg.sample_committee(&beacon, 5);
    assert_eq!(fingerprint(&a, &beacon, 5), fingerprint(&b, &beacon, 5));
}

#[test]
fn same_beacon_and_roots_give_the_same_leader() {
    let reg = registry();
    let beacon = Beacon::genesis();
    let committee = reg.sample_committee(&beacon, 5);
    let first = reg.elect_leader(&committee, &beacon, 5).unwrap();
    let second = reg.elect_leader(&committee, &beacon, 5).unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(first.credential.preimage, second.credential.preimage);
}

#[test]
fn a_different_beacon_changes_the_outputs() {
    let reg = registry();
    let genesis = Beacon::genesis();
    let next = genesis.advance(&[3u8; 32], 1);
    let a = reg.sample_committee(&genesis, 0);
    let b = reg.sample_committee(&next, 0);
    // The generous budget admits the whole set under either beacon, but the
    // deterministic outputs differ because they bind the beacon.
    assert_eq!(a.ids(), b.ids());
    assert_ne!(fingerprint(&a, &genesis, 0), fingerprint(&b, &next, 0));
}
