// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_attest::aggregate::aggregate;
use qtv_attest::verify::RejectReason;
use qtv_attest::{
    Attester, Beacon, Block, Certificate, CommitteeCommitment, Envelope, Parent, Verdict,
};
use qtv_sampler::committee::verify_leader;
use qtv_sampler::onetime::MerklePath;
use qtv_sampler::sortition::Credential;
use qtv_sampler::validator::SamplerValidator;

const BUDGET: u64 = 4;

const STAKE: u64 = 2_000;

fn committee(members: &[Attester]) -> CommitteeCommitment {
    let refs: Vec<&Attester> = members.iter().collect();
    CommitteeCommitment::from_attesters_with_budget(0, &refs, BUDGET)
}

fn old_style_draw(slot: u64) -> Credential {
    let depth = SamplerValidator::new(999, STAKE).reveal(slot).path.siblings.len();
    Credential {
        position: slot,
        preimage: [171; 32],
        path: MerklePath {
            siblings: vec![[205; 32]; depth],
        },
    }
}

#[test]
fn the_consensus_verification_rejects_an_old_mechanism_membership_draw() {
    let members: Vec<Attester> = (1..=4).map(|id| Attester::new(id, STAKE)).collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);
    let commitment = committee(&members);

    let mut atts: Vec<_> = members[..3]
        .iter()
        .map(|a| a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon))
        .collect();
    let good = Certificate::new(Envelope::new(1, 0, block, &commitment), atts.clone());
    assert_eq!(good.verify(1, &commitment, &beacon, 3), Verdict::Verified);

    atts[0].membership = old_style_draw(0);
    let bad = Certificate::new(Envelope::new(1, 0, block, &commitment), atts);
    assert_eq!(
        bad.verify(1, &commitment, &beacon, 3),
        Verdict::Rejected(RejectReason::NotEntitled)
    );
}

#[test]
fn aggregation_drops_an_old_mechanism_membership_draw() {
    let members: Vec<Attester> = (1..=4).map(|id| Attester::new(id, STAKE)).collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);
    let commitment = committee(&members);

    let genuine: Vec<_> = members[..3]
        .iter()
        .map(|a| a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon))
        .collect();
    assert!(aggregate(1, 1, 0, block, &commitment, &beacon, &genuine, 3).is_some());

    let mut atts = genuine;
    atts[0].membership = old_style_draw(0);
    assert!(aggregate(1, 1, 0, block, &commitment, &beacon, &atts, 3).is_none());
}

#[test]
fn leader_eligibility_rejects_an_old_mechanism_draw() {
    let leader = SamplerValidator::new(1, STAKE);
    let root = leader.root();
    let genuine = leader.reveal(0);
    assert!(verify_leader(&root, 0, &genuine));
    assert!(!verify_leader(&root, 0, &old_style_draw(0)));
}
