// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Wire format vectors for the one time key sortition. The sortition output, the
//! preimage derivation, the leaf and node hashes, and a committed root are pinned
//! to fixed bytes, so the on chain format is locked and cannot drift.

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
        hex(&leaf_hash(&dp)),
        "aa4be6d87dc78f568141746867d3e5f5a8ce9d62c3fa16fe5efdd523334e4f8c"
    );
    assert_eq!(
        hex(&node_hash(&[1u8; 32], &[2u8; 32])),
        "73e0e8a47eace0b1a76675ccfc9b9280c18b25d61dbb0ab9c05a71c8b50fd1a2"
    );
}

#[test]
fn a_committed_root_matches_its_pinned_vector() {
    // The committed root under a fixed validator secret. The secret is an explicit
    // known input here, not a function of the id, so this vector locks the whole
    // path from a validator's secret through the domain separated tree seed to the
    // published root.
    let secret = [0x11u8; 32];
    let v = SamplerValidator::from_secret(1, &secret, 100);
    assert_eq!(
        hex(&v.root().digest),
        "592d119920d539bdaf1bb6cfcd76001370bb0c13549953d28e6b7e9291046680"
    );
}
