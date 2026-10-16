// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::{CommitteeView, PublishedReveal};
use qtv_sampler::onetime::Root;
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::sortition::{bound_sortition_output, sortition_output, DrawMode};
use qtv_sampler::validator::{Registration, SamplerValidator};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn root(fill: u8) -> Root {
    Root {
        digest: [fill; 32],
        slots: 64,
    }
}

fn beacon() -> Beacon {
    Beacon::from_seed([3u8; 32])
}

#[test]
fn the_bound_and_unbound_draw_outputs_match_their_vectors() {
    assert_eq!(
        hex(&bound_sortition_output(
            7,
            &root(9),
            &[5u8; 32],
            &beacon(),
            DOMAIN_COMMITTEE,
            11
        )),
        "f2064ba24c72815f985170290efda3ce9bcaad9408b50b6508f98bba46c53031"
    );
    assert_eq!(
        hex(&sortition_output(
            &[5u8; 32],
            &beacon(),
            DOMAIN_COMMITTEE,
            11
        )),
        "1f4a292c2e7be87375df3fcc20e0fd00b66d4c77f48d9bd74947f30da8f4febd"
    );
}

#[test]
fn every_beacon_rule_matches_its_vector() {
    let b = beacon();
    assert_eq!(
        hex(b
            .advance_from_bound_reveals(11, &[(1, [1u8; 32]), (2, [2u8; 32]), (3, [3u8; 32])])
            .seed()),
        "107a44c2de4e0ba259aa9444e7547206ec231721c7a36399c5d3c7bc82745245"
    );
    assert_eq!(
        hex(b.advance_from_reveals(11, &[[1u8; 32], [2u8; 32]]).seed()),
        "ea2f00844dd01d4f99bad95b7ff8f5d1aaff29952937efcc28385c6c65a5fb50"
    );
    assert_eq!(
        hex(b.advance_fixed(11).seed()),
        "1c58b0c3c9e1497515b1f180cc91b151d2f83b99f5ba888bbf8e5c249cad6192"
    );
}

#[test]
fn the_full_committee_rotation_matches_its_vector() {
    let regs: Vec<Registration> = (1..=6u64)
        .map(|id| Registration {
            id,
            root: root(id as u8),
            weight: 2_000 * id,
        })
        .collect();
    let view = CommitteeView::new(regs).with_mode(DrawMode::Full);
    let leaders: Vec<u64> = (0..12u64)
        .map(|slot| view.rotation_leader(5, slot).expect("a leader"))
        .collect();
    assert_eq!(leaders, vec![3, 6, 3, 5, 4, 6, 3, 4, 4, 5, 5, 6]);
}

#[test]
fn the_bound_leader_and_next_beacon_match_their_vectors() {
    let vals: Vec<SamplerValidator> = (1..=6u64)
        .map(|id| SamplerValidator::new(id, 2_000 * id))
        .collect();
    let regs: Vec<Registration> = vals.iter().map(Registration::of).collect();
    let view = CommitteeView::new(regs).with_mode(DrawMode::Bound);
    let published: Vec<PublishedReveal> = vals
        .iter()
        .map(|v| PublishedReveal::new(v.id, v.reveal(4).expect("a held slot")))
        .collect();
    let committee = view.form_committee(&beacon(), 4, &published);
    assert_eq!(committee.ids(), vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(
        view.elect_leader(&committee, &beacon(), 4)
            .expect("a leader")
            .id,
        5
    );
    assert_eq!(
        hex(committee.next_beacon(&beacon(), 4).seed()),
        "c5f1a197d7b9dcad3d851c5a0fecee60920d5c33e710c627d9f81b4bc332d445"
    );
}

#[test]
fn a_reveal_list_with_a_repeated_or_surplus_entry_forms_no_committee() {
    let vals: Vec<SamplerValidator> = (1..=3u64)
        .map(|id| SamplerValidator::new(id, 2_000))
        .collect();
    let regs: Vec<Registration> = vals.iter().map(Registration::of).collect();
    let view = CommitteeView::new(regs).with_mode(DrawMode::Bound);
    let one = PublishedReveal::new(1, vals[0].reveal(0).expect("a held slot"));
    let repeated = vec![one.clone(), one.clone()];
    assert!(view.form_committee(&beacon(), 0, &repeated).is_empty());
    let surplus = vec![one; 4];
    assert!(view.form_committee(&beacon(), 0, &surplus).is_empty());
}
