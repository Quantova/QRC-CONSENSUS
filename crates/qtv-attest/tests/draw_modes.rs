// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_attest::aggregate::aggregate;
use qtv_attest::{
    equivocators, Attester, Beacon, Block, CommitteeCommitment, ConflictingCertificates,
    EquivocationProof, Justification, Parent, VoteLock,
};
use qtv_crypto::ml_dsa::PublicKey;
use qtv_sampler::committee::{CommitteeView, PublishedReveal};
use qtv_sampler::sortition::DrawMode;
use qtv_sampler::validator::Registration;

fn attesters(n: u64, stake: u64) -> Vec<Attester> {
    (1..=n).map(|id| Attester::new(id, stake)).collect()
}

fn registrations(atts: &[Attester]) -> Vec<Registration> {
    atts.iter()
        .map(|a| Registration {
            id: a.id(),
            root: a.root(),
            weight: a.weight(),
        })
        .collect()
}

fn key_of(atts: &[Attester]) -> impl Fn(u64) -> Option<PublicKey> + '_ {
    move |id| {
        atts.iter()
            .find(|a| a.id() == id)
            .map(|a| *a.attest_public_key())
    }
}

struct Run {
    committee: usize,
    commitment: usize,
    verified: bool,
    registered: bool,
}

fn certify(mode: DrawMode, atts: &[Attester]) -> Run {
    let view = CommitteeView::new(registrations(atts)).with_mode(mode);
    let beacon = Beacon::genesis();
    let slot = 0;
    let published: Vec<PublishedReveal> = atts
        .iter()
        .filter_map(|a| {
            let credential = a.reveal(slot)?;
            view.admits(&beacon, slot, a.id(), &credential)
                .then(|| PublishedReveal::new(a.id(), credential))
        })
        .collect();
    let committee = view.form_committee(&beacon, slot, &published);
    let commitment = CommitteeCommitment::from_view(slot, &view, &committee, key_of(atts))
        .expect("every member has a key");
    let block = Block::new(1, [7u8; 32], Parent::Genesis);
    let voters: Vec<u64> = if mode == DrawMode::Full {
        atts.iter().map(|a| a.id()).collect()
    } else {
        committee.ids()
    };
    let votes: Vec<_> = voters
        .iter()
        .map(|id| {
            atts.iter()
                .find(|a| a.id() == *id)
                .expect("a voter is registered")
                .attest(1, 1, slot, 0, commitment.digest(), block, &beacon)
                .expect("the voter serves this slot")
        })
        .collect();
    let tau = qtv_sampler::params::finality_threshold(commitment.len() as u64);
    let cert = aggregate(1, 1, slot, block, &commitment, &beacon, &votes, tau);
    let verified = cert
        .as_ref()
        .is_some_and(|c| c.verify(1, &commitment, &beacon, tau).is_verified());
    let registered = cert.as_ref().is_some_and(|c| {
        c.verify_registered(1, &view, &beacon, tau, key_of(atts))
            .is_verified()
    });
    Run {
        committee: committee.len(),
        commitment: commitment.len(),
        verified,
        registered,
    }
}

#[test]
fn a_bound_committee_that_is_not_saturated_certifies() {
    let atts = attesters(1_600, 2_000);
    let bound = certify(DrawMode::Bound, &atts);
    assert!(bound.committee < 1_600, "the draw is not saturated");
    assert!(bound.verified && bound.registered);
    let unbound = certify(DrawMode::Unbound, &atts);
    assert!(unbound.committee < 1_600);
    assert!(unbound.verified && unbound.registered);
}

#[test]
fn a_full_committee_needs_two_thirds_of_all_registered_stake() {
    let atts = attesters(40, 2_000);
    let full = certify(DrawMode::Full, &atts);
    assert_eq!(full.commitment, 40);
    assert!(full.verified && full.registered);

    let view = CommitteeView::new(registrations(&atts)).with_mode(DrawMode::Full);
    let beacon = Beacon::genesis();
    let committee = view.form_committee(&beacon, 0, &[]);
    let commitment = CommitteeCommitment::from_view(0, &view, &committee, key_of(&atts))
        .expect("every member has a key");
    let block = Block::new(1, [7u8; 32], Parent::Genesis);
    for signers in [13usize, 26, 27, 40] {
        let votes: Vec<_> = atts[..signers]
            .iter()
            .map(|a| {
                a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon)
                    .expect("the voter serves this slot")
            })
            .collect();
        let cert = aggregate(1, 1, 0, block, &commitment, &beacon, &votes, 1);
        assert_eq!(cert.is_some(), signers * 3 >= 80, "{signers} of 40 signers");
    }
}

#[test]
fn a_full_committee_weighs_split_stake_at_its_raw_share() {
    let atts = attesters(10, 100_000);
    let regs: Vec<Registration> = atts
        .iter()
        .map(|a| Registration {
            id: a.id(),
            root: a.root(),
            weight: if a.id() <= 5 { 50_000 } else { 150_000 },
        })
        .collect();
    let view = CommitteeView::new(regs.clone()).with_mode(DrawMode::Full);
    let raw: u64 = regs.iter().filter(|r| r.id <= 5).map(|r| r.weight).sum();
    let effective: u64 = regs
        .iter()
        .filter(|r| r.id <= 5)
        .map(|r| view.effective_weight(r.weight))
        .sum();
    assert_eq!(raw, effective);
    assert_eq!(view.total_weight(), 1_000_000);
}

#[test]
fn conflicting_certificates_across_views_name_their_signers_and_a_lock_refuses_the_second() {
    let atts = attesters(4, 100);
    let refs: Vec<&Attester> = atts.iter().collect();
    let commitment = CommitteeCommitment::from_attesters(0, &refs);
    let beacon = Beacon::genesis();
    let x = Block::new(1, [1u8; 32], Parent::Genesis);
    let y = Block::new(1, [2u8; 32], Parent::Genesis);
    let vote = |a: &Attester, view: u64, block: Block| {
        a.attest(1, 1, 0, view, commitment.digest(), block, &beacon)
            .expect("the voter serves this slot")
    };
    let votes_x: Vec<_> = atts.iter().map(|a| vote(a, 0, x)).collect();
    let votes_y: Vec<_> = atts.iter().map(|a| vote(a, 1, y)).collect();
    let cert_x = aggregate(1, 1, 0, x, &commitment, &beacon, &votes_x, 3).expect("quorum");
    let cert_y = aggregate(1, 1, 0, y, &commitment, &beacon, &votes_y, 3).expect("quorum");
    let offenders = ConflictingCertificates::new(&cert_x, &cert_y)
        .expect("one height, two blocks")
        .offenders(1, &commitment, &beacon, 3, &commitment, &beacon, 3);
    assert_eq!(offenders, vec![1, 2, 3, 4]);
    assert!(ConflictingCertificates::new(&cert_x, &cert_x).is_none());

    let mut lock = VoteLock::new();
    let first = atts[0].attest_locked(&mut lock, 1, 1, 0, 0, commitment.digest(), x, &beacon, None);
    assert!(first.is_some());
    let unjustified =
        atts[0].attest_locked(&mut lock, 1, 1, 0, 1, commitment.digest(), y, &beacon, None);
    assert!(unjustified.is_none());
    let older = atts[0].attest_locked(&mut lock, 1, 1, 0, 0, commitment.digest(), x, &beacon, None);
    assert!(older.is_some(), "the locked block may be voted again");
    let justification = Justification {
        certificate: &cert_y,
        commitment: &commitment,
        beacon: &beacon,
        tau: 3,
    };
    let justified = atts[0].attest_locked(
        &mut lock,
        1,
        1,
        0,
        1,
        commitment.digest(),
        y,
        &beacon,
        Some(&justification),
    );
    assert!(justified.is_some());
    let stale = atts[0].attest_locked(&mut lock, 1, 1, 0, 0, commitment.digest(), x, &beacon, None);
    assert!(stale.is_none(), "a vote never goes back to an earlier view");
}

#[test]
fn a_later_view_revote_is_not_equivocation_but_a_same_view_double_vote_is() {
    let atts = attesters(6, 100);
    let beacon = Beacon::genesis();
    let x = Block::new(3, [1u8; 32], Parent::Genesis);
    let y = Block::new(3, [2u8; 32], Parent::Genesis);
    let offender = &atts[4];
    let pk = *offender.attest_public_key();
    let vote = |view: u64, block: Block| {
        offender
            .attest(1, 3, 0, view, [0u8; 32], block, &beacon)
            .expect("the voter serves this slot")
    };
    let a = vote(0, x);
    let b = vote(1, y);
    assert!(EquivocationProof::new(a.clone(), b.clone()).is_none());
    assert!(equivocators(1, &[a, b], |_| Some(pk)).is_empty());

    let c = vote(1, x);
    let d = vote(1, y);
    let proof = EquivocationProof::new(c.clone(), d.clone()).expect("same view, two blocks");
    assert!(proof.verifies(1, &pk));
    let padded: Vec<_> = std::iter::repeat_n(c, 5_000).chain([d]).collect();
    assert_eq!(equivocators(1, &padded, |_| Some(pk)), vec![5]);
}

#[test]
fn a_full_committee_admits_no_conflicting_certificates_below_a_third_of_stake() {
    let atts = attesters(30, 2_000);
    let view = CommitteeView::new(registrations(&atts)).with_mode(DrawMode::Full);
    let beacon = Beacon::genesis();
    let committee = view.form_committee(&beacon, 0, &[]);
    let commitment = CommitteeCommitment::from_view(0, &view, &committee, key_of(&atts))
        .expect("every member has a key");
    let x = Block::new(1, [1u8; 32], Parent::Genesis);
    let y = Block::new(1, [2u8; 32], Parent::Genesis);
    let votes = |signers: &[Attester], block: Block| -> Vec<_> {
        signers
            .iter()
            .map(|a| {
                a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon)
                    .expect("the voter serves this slot")
            })
            .collect()
    };
    for adversary in 0..=10usize {
        let (bad, honest) = atts.split_at(adversary);
        let mut forked = false;
        for split in 0..=honest.len() {
            let (left, right) = honest.split_at(split);
            let mut for_x = votes(bad, x);
            for_x.extend(votes(left, x));
            let mut for_y = votes(bad, y);
            for_y.extend(votes(right, y));
            let cx = aggregate(1, 1, 0, x, &commitment, &beacon, &for_x, 1);
            let cy = aggregate(1, 1, 0, y, &commitment, &beacon, &for_y, 1);
            forked |= cx.is_some() && cy.is_some();
        }
        assert_eq!(
            forked,
            adversary * 3 >= 30,
            "{adversary} of 30 equal stakes"
        );
    }
}
