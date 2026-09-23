// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sampler::beacon::Beacon;
use qtv_sampler::onetime::{derive_preimage, leaf_hash, node_hash, PREIMAGE_BYTES};
use qtv_sampler::params::{DOMAIN_COMMITTEE, DOMAIN_LEADER};
use qtv_sampler::sortition::sortition_output;
use qtv_sampler::validator::SamplerValidator;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn sortition_output_matches_its_pinned_vector() {
    let mut preimage = [0u8; PREIMAGE_BYTES];
    for (i, b) in preimage.iter_mut().enumerate() {
        *b = i as u8;
    }
    let beacon = Beacon::from_seed([0x5a; 32]);
    assert_eq!(
        hex(&sortition_output(&preimage, &beacon, DOMAIN_COMMITTEE, 7)),
        "8dccc94e8e67c5ffd803e27f793d85258352d91b9e2539523c213da035a880db"
    );
    assert_eq!(
        hex(&sortition_output(&preimage, &beacon, DOMAIN_LEADER, 7)),
        "2072d3db5f8df5014aa878ada3e03495fb0196ab9b246c114797b975f1ea34b4"
    );
}

#[test]
fn tree_hashing_matches_its_pinned_vectors() {
    let dp = derive_preimage(&[9u8; 32], 5);
    assert_eq!(
        hex(&dp),
        "1c14fc752fccbc70a12bcab853174024d134aaa97aeffe98cbd55be97a6a6fc4"
    );
    assert_eq!(
        hex(&leaf_hash(5, &dp)),
        "8e149bf9c77bb58fb7d9ec278517fc9c79de7a62f8853319b17f33666acf851f"
    );
    assert_eq!(
        hex(&node_hash(&[1u8; 32], &[2u8; 32])),
        "73e0e8a47eace0b1a76675ccfc9b9280c18b25d61dbb0ab9c05a71c8b50fd1a2"
    );
}

#[test]
fn a_committed_root_matches_its_pinned_vector() {
    let secret = [0x11u8; 32];
    let v = SamplerValidator::from_secret(1, &secret, 100);
    assert_eq!(
        hex(&v.root().digest),
        "7d2caa17f268148ffee8adedb97a00707259bae153a3a0a2d95402f25d3a7d15"
    );
    let other = SamplerValidator::from_secret(2, &secret, 100);
    assert_ne!(
        v.root().digest,
        other.root().digest,
        "one secret under two ids commits to two different roots"
    );
}
