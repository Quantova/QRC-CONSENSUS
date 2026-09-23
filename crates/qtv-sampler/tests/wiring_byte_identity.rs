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
    "7d2caa17f268148ffee8adedb97a00707259bae153a3a0a2d95402f25d3a7d15",
    "790a26d3445036e4d995ca1c93288386f32bb674ee478415a44b16e2dfe41c88",
    "60c1220aaea330618d791533ada293610701f31592cb72dee39f9e1c4b36a7c1",
    "abeedee12d8d79e17bac14e8416f1abb52c91480323e3b9fe3c1caa12f360c2d",
    "6a4239aa091517febfa13c8630cef2fb17aba2f02425dde3fd83916e7b6873e9",
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
        "040000000000000023fe3ff11ac0d84a61aeec6c11687df5d7815d2e25f3a74dc72802c3f4accefa44e482bed7634293ec6ec93c22b1676b5e2a8c77a179e82450d2315443f60d83a81b20049a8cdbf099a23fc94a4483079b4a46f8f8fd4d417dd4b4c6a7bd5d7199b58a7feae0bbdc1bea1ebfdc24ce946245db33977f8ed9ec397aca80da89cdec0ea5f80da137369d83830ba8a22eb3407d2dbf774cc9900025251722e5e58f6309204a266748da67bb2434bb5258ffd7e2131e35bce27a2ab40f4e90b6f088987423306b0afac5c4a0bb0c9d342235c9c76676c413eeb958599ad7dc280ae0",
        "credential bytes drifted for id 1 slot 4"
    );
    assert_eq!(c1.value(&b, DOMAIN_COMMITTEE, 4), 8463245084084038997);
    assert_eq!(c1.value(&b, DOMAIN_LEADER, 4), 4132736013311636499);

    let c4 = set[3].reveal(7);
    assert_eq!(
        hex(&c4.to_bytes()),
        "0700000000000000b0704b63a0f49e4f071437cfa82dc87f5c943bb2d33fdbcbbc8633ccc4e24667bbd7e1086502d2ad6f4f2e1c9aeba7a2e710fb45d3acc5fcb0979ef4cf16f663c32ce5663e64fb5bbaa22c0ccb6b4fcc4871a7cac273f5439f0ba43eecb86ef16cd8dc8b9ec88c20ba64afdc28b5e8133f97a25742e407e75c73f5103b4fde8ccfcb43af3d0ed39a2ab82d5c5a9b7f7173f528f1f3a36822a482421c5c0b64666a0f3c414bc9302ddf9f83a1e0350b993292cf823829820fc8966de62e8953f9b205a8e5cd059e40cd99eef95fb4eb277435c228fdee97c929396001f3feaced",
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
    let (sk, pk) = keygen(seed, DEFAULT_SLOTS, id);

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
            verify(&pk, id, slot, &y, &proof),
            "the q-vrf transcript for the sortition credential failed to verify at slot {slot}"
        );
    }
}
