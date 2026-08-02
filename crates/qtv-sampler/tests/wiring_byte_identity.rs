// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use q_vrf::{keygen, verify};

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::{CommitteeView, PublishedReveal};
use qtv_sampler::params::{DOMAIN_COMMITTEE, DOMAIN_LEADER};
use qtv_sampler::sortition::sortition_output;
use qtv_sampler::validator::{sortition_tree_seed, Registration, SamplerValidator, DEFAULT_SLOTS};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn secrets() -> [(u64, [u8; 32], u64); 5] {
    [
        (1, [0x11u8; 32], 100),
        (2, [0x22u8; 32], 300),
        (3, [0x33u8; 32], 50),
        (4, [0x44u8; 32], 900),
        (5, [0x55u8; 32], 250),
    ]
}

fn roster() -> Vec<SamplerValidator> {
    secrets()
        .iter()
        .map(|(id, secret, stake)| SamplerValidator::from_secret(*id, secret, *stake))
        .collect()
}

fn beacon() -> Beacon {
    Beacon::from_seed([0x5au8; 32])
}

const ROOTS: [&str; 5] = [
    "592d119920d539bdaf1bb6cfcd76001370bb0c13549953d28e6b7e9291046680",
    "30a2c177d347f2378dad84e0b30ae6e3de039eae9c96deaf3377c6582a31af85",
    "62869efa05fab3903f82d1d15d14ea280a494ed3386f01127bb4c52520d00a3e",
    "53cdea20d025cc8dac4b8c1535673ece92cb822b6d0e7d008ca4830a5c6c5e6a",
    "be0f7dbe7255b1835e40c843f7c00243d19622b9f1141f2ad172b62af536db47",
];

#[test]
fn committed_roots_are_byte_identical_to_the_pre_wiring_baseline() {
    for (v, want) in roster().iter().zip(ROOTS.iter()) {
        assert_eq!(hex(&v.root().digest), *want, "root drifted for id {}", v.id);
    }
}

#[test]
fn sortition_output_is_byte_identical_to_the_pre_wiring_baseline() {
    let mut preimage = [0u8; 32];
    for (i, b) in preimage.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    let b = beacon();
    assert_eq!(
        hex(&sortition_output(&preimage, &b, DOMAIN_COMMITTEE, 9)),
        "7e9b15c50982b8f4f7dc538f2830913169eba8a26c8487f8df54fa9e465dad63",
        "committee sortition output drifted"
    );
    assert_eq!(
        hex(&sortition_output(&preimage, &b, DOMAIN_LEADER, 9)),
        "7160d9010f906d99cdf2b26562d5cae4ab3f25da1a3032e293dea12ab6ac852a",
        "leader sortition output drifted"
    );
}

#[test]
fn credentials_and_values_are_byte_identical_to_the_pre_wiring_baseline() {
    let set = roster();
    let b = beacon();

    let c1 = set[0].reveal(4);
    assert_eq!(
        hex(&c1.to_bytes()),
        "040000000000000023fe3ff11ac0d84a61aeec6c11687df5d7815d2e25f3a74dc72802c3f4accefa03a09b6fce4de247cfb3cbd84c0a8b99169b527f6dd1fd6a5e4e5685ce63ece5be5ad9dc25d719767e6d5d134747333b477c0b7ec2cc87baddf25a0c83080377f8e6e76f4ecf9f3cc7ecf1202e3cf3b0423b441123d57707bcfd7bf478efacacebb3b1e6c131bc282d2a519320043508db89352a8cd672d70c4c7a320e261c1e3996e8c06e8397d221e9864e8aaf74893c4dab8de8b3bfd8701fe69293a263b18be46e0237349a521969070009f126f9201fdb7d00a5855b36e6ac253f678ac0",
        "credential bytes drifted for id 1 slot 4"
    );
    assert_eq!(c1.value(&b, DOMAIN_COMMITTEE, 4), 8463245084084038997);
    assert_eq!(c1.value(&b, DOMAIN_LEADER, 4), 4132736013311636499);

    let c4 = set[3].reveal(7);
    assert_eq!(
        hex(&c4.to_bytes()),
        "0700000000000000b0704b63a0f49e4f071437cfa82dc87f5c943bb2d33fdbcbbc8633ccc4e24667871907ca907a570e2699847275862a831dc6ca47f81e2f330eddf961cf68a55c851cd53f31ddc963462e296124095a814a2a55c12adf04c811f5cfbb6df5e9cce73e001fab7b96015ef3570cc3ac99f330ab2c3c61eccd4973da39bab65e8cb7a7df025f0fcfda6f3135c857653f14c69e7e82afc671fbf1ae663d0981d388171499c3a8a1480ab7749339d1da55dbbddb8c04faf9aa0a105409763636f7298899b9563c6cc11a23066f7fe824ce8661f43ec754ccd332c5825de1bfae23f5f9",
        "credential bytes drifted for id 4 slot 7"
    );
    assert_eq!(c4.value(&b, DOMAIN_COMMITTEE, 7), 6689513396938958186);
    assert_eq!(c4.value(&b, DOMAIN_LEADER, 7), 1943409400247528846);
}

#[test]
fn committee_membership_and_leaders_are_byte_identical_to_the_pre_wiring_baseline() {
    let set = roster();
    let b = beacon();
    let view = CommitteeView::new(set.iter().map(Registration::of).collect())
        .with_budget(3)
        .with_floor(0);

    let expected: [(u64, &str, u64); 3] = [(0, "4,5", 4), (1, "4,5", 4), (7, "4", 4)];
    for (slot, want_ids, want_leader) in expected {
        let published: Vec<PublishedReveal> = set
            .iter()
            .map(|v| PublishedReveal::new(v.id, v.reveal(slot)))
            .collect();
        let committee = view.form_committee(&b, slot, &published);
        let ids: Vec<String> = committee.ids().iter().map(|i| i.to_string()).collect();
        assert_eq!(ids.join(","), want_ids, "committee drifted at slot {slot}");
        assert_eq!(
            view.elect_leader(&committee, &b, slot).map(|l| l.id),
            Some(want_leader),
            "leader drifted at slot {slot}"
        );
    }
}

#[test]
fn the_sortition_credential_is_the_q_vrf_proof_over_the_committed_tree() {
    let (id, secret, stake) = secrets()[0];
    let v = SamplerValidator::from_secret(id, &secret, stake);

    let seed = sortition_tree_seed(&secret);
    let (sk, pk) = keygen(seed, DEFAULT_SLOTS);

    assert_eq!(
        pk.root().digest,
        v.root().digest,
        "the q-vrf public key root differs from the registered sortition root"
    );

    for slot in 0..DEFAULT_SLOTS {
        let cred = v.reveal(slot);
        let (y, proof) = sk.eval_and_prove(slot);
        assert_eq!(
            cred.preimage, proof.preimage,
            "the reveal preimage is not the q-vrf proof preimage at slot {slot}"
        );
        assert_eq!(
            cred.path, proof.path,
            "the reveal path is not the q-vrf proof path at slot {slot}"
        );
        assert!(
            verify(&pk, slot, &y, &proof),
            "the q-vrf transcript for the sortition credential failed to verify at slot {slot}"
        );
    }
}
