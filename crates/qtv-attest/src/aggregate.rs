// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_bft::block::{Block, Height};

use qtv_sampler::beacon::Beacon;

use crate::attestation::Attestation;
use crate::attester::ValidatorId;
use crate::certificate::{Certificate, Envelope};
use crate::committee::CommitteeCommitment;
use crate::params::COMMITTEE_BUDGET;

pub const MAX_ATTEST_VERIFICATIONS_PER_ROUND: u64 = 4 * COMMITTEE_BUDGET;

pub fn aggregate(
    chain_id: u64,
    height: Height,
    slot: u64,
    block: Block,
    commitment: &CommitteeCommitment,
    beacon: &Beacon,
    attestations: &[Attestation],
    tau: u64,
) -> Option<Certificate> {
    aggregate_metered(
        chain_id,
        height,
        slot,
        block,
        commitment,
        beacon,
        attestations,
        tau,
    )
    .0
}

fn aggregate_metered(
    chain_id: u64,
    height: Height,
    slot: u64,
    block: Block,
    commitment: &CommitteeCommitment,
    beacon: &Beacon,
    attestations: &[Attestation],
    tau: u64,
) -> (Option<Certificate>, u64) {
    let cap = MAX_ATTEST_VERIFICATIONS_PER_ROUND.max(commitment.len() as u64);
    let committee_digest = commitment.digest();

    let mut groups: Vec<(ValidatorId, Vec<&Attestation>)> = Vec::new();
    for att in attestations {
        if att.height != height || att.slot != slot || att.block != block {
            continue;
        }
        if att.committee != committee_digest {
            continue;
        }
        if commitment.member(att.from).is_none() {
            continue;
        }
        match groups.iter_mut().find(|(id, _)| *id == att.from) {
            Some((_, bucket)) => bucket.push(att),
            None => groups.push((att.from, vec![att])),
        }
    }

    let mut admitted: Vec<Attestation> = Vec::new();
    let mut seen: Vec<ValidatorId> = Vec::new();
    let mut verifications: u64 = 0;

    let mut round = 0usize;
    let mut progressed = true;
    while progressed && verifications < cap {
        progressed = false;
        for (id, bucket) in groups.iter() {
            if seen.contains(id) {
                continue;
            }
            let att = match bucket.get(round) {
                Some(a) => *a,
                None => continue,
            };
            progressed = true;
            if verifications >= cap {
                break;
            }
            verifications += 1;
            let member = match commitment.member(*id) {
                Some(m) => m,
                None => continue,
            };
            if !att.signature_verifies(chain_id, &member.attest_pk) {
                continue;
            }
            if !att.is_entitled(
                &member.root,
                beacon,
                member.weight,
                commitment.total_weight,
                commitment.budget,
            ) {
                continue;
            }
            seen.push(*id);
            admitted.push(att.clone());
        }
        round += 1;
    }

    let effective_tau = tau.max(qtv_sampler::params::finality_threshold(
        commitment.len() as u64
    ));
    let cert = if admitted.len() as u64 >= effective_tau {
        let envelope = Envelope::new(height, slot, block, commitment);
        Some(Certificate::new(envelope, admitted))
    } else {
        None
    };
    (cert, verifications)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attester::Attester;
    use qtv_bft::block::Parent;

    const BUDGET: u64 = 4;
    const TAU: u64 = 3;

    fn committee(attesters: &[&Attester]) -> CommitteeCommitment {
        CommitteeCommitment::from_attesters_with_budget(0, attesters, BUDGET)
    }

    #[test]
    fn an_entitled_supermajority_aggregates() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);
        let atts = vec![
            a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            b.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            c.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
        ];
        let cert = aggregate(1, 1, 0, block, &commitment, &beacon, &atts, TAU).expect("quorum");
        assert_eq!(cert.attesters(), vec![1, 2, 3]);
    }

    #[test]
    fn below_the_supermajority_does_not_aggregate() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);
        let atts = vec![
            a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            b.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
        ];
        assert!(aggregate(1, 1, 0, block, &commitment, &beacon, &atts, TAU).is_none());
    }

    #[test]
    fn a_duplicate_signer_counts_once() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);
        let atts = vec![
            a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            b.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
        ];
        assert!(aggregate(1, 1, 0, block, &commitment, &beacon, &atts, TAU).is_none());
    }

    #[test]
    fn a_flood_verifies_at_most_the_capped_number() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let outsider_one = Attester::new(101, 100);
        let outsider_two = Attester::new(102, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);

        let mut atts: Vec<Attestation> = Vec::new();
        for _ in 0..2_000 {
            atts.push(a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));
            atts.push(b.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));
            atts.push(c.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));
            atts.push(d.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));
            atts.push(outsider_one.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));
            atts.push(outsider_two.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));
        }
        let flood = atts.len() as u64;
        assert_eq!(flood, 12_000, "the flood is far larger than the committee");

        let (cert, verifications) =
            aggregate_metered(1, 1, 0, block, &commitment, &beacon, &atts, TAU);

        assert_eq!(
            verifications, 4,
            "each of the four members is verified once, the 12,000 copies add no work"
        );
        assert!(
            verifications < flood,
            "verification does not scale with the flood"
        );
        assert!(
            verifications <= MAX_ATTEST_VERIFICATIONS_PER_ROUND,
            "verifications stay within the hard cap"
        );
        let cert = cert.expect("the honest members inside the flood still form a quorum");
        assert_eq!(cert.attesters(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn a_duplicate_is_verified_once() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);
        let atts = vec![
            a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            b.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            c.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
        ];
        let (cert, verifications) =
            aggregate_metered(1, 1, 0, block, &commitment, &beacon, &atts, TAU);
        assert_eq!(
            verifications, 3,
            "the five copies of signer 1 cost one verification, not five"
        );
        let cert = cert.expect("three distinct signers are a quorum");
        assert_eq!(cert.attesters(), vec![1, 2, 3]);
    }

    #[test]
    fn a_legitimate_quorum_aggregates_unchanged_and_verifies() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);
        let atts = vec![
            a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            b.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            c.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
        ];
        let (cert, verifications) =
            aggregate_metered(1, 1, 0, block, &commitment, &beacon, &atts, TAU);
        assert_eq!(
            verifications, 3,
            "a clean quorum spends no verification beyond its signers"
        );
        let cert = cert.expect("an entitled supermajority aggregates");
        assert_eq!(cert.attesters(), vec![1, 2, 3]);
        assert!(
            cert.verify(1, &commitment, &beacon, TAU).is_verified(),
            "the aggregated certificate passes wire level verification"
        );
    }

    #[test]
    fn an_invalid_signature_is_still_rejected() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);

        let impostor = Attester::from_secret(1, &[7u8; 32], 100);
        assert_ne!(
            impostor.attest_public_key(),
            a.attest_public_key(),
            "the impostor holds a different key under member 1's id"
        );
        let forged = impostor.attest(1, 1, 0, 0, commitment.digest(), block, &beacon);

        let atts_forged = vec![
            forged.clone(),
            b.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            c.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
        ];
        assert!(
            aggregate(1, 1, 0, block, &commitment, &beacon, &atts_forged, TAU).is_none(),
            "the forged signature does not count toward the quorum"
        );

        let atts_genuine = vec![
            a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            b.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            c.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
        ];
        let cert = aggregate(1, 1, 0, block, &commitment, &beacon, &atts_genuine, TAU)
            .expect("the genuine signer completes the quorum");
        assert_eq!(cert.attesters(), vec![1, 2, 3]);
    }

    #[test]
    fn a_forged_front_runner_does_not_censor_the_genuine_signer() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);

        let impostor = Attester::from_secret(1, &[7u8; 32], 100);
        let forged = impostor.attest(1, 1, 0, 0, commitment.digest(), block, &beacon);

        let forgeries = 64u64;
        let mut atts: Vec<Attestation> = (0..forgeries).map(|_| forged.clone()).collect();
        atts.push(a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));
        atts.push(b.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));
        atts.push(c.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));

        let (cert, verifications) =
            aggregate_metered(1, 1, 0, block, &commitment, &beacon, &atts, TAU);

        let cert = cert.expect("the honest quorum finalizes despite the forged front-runners");
        assert_eq!(
            cert.attesters(),
            vec![1, 2, 3],
            "member 1's genuine vote is not censored however many forgeries precede it"
        );
        assert!(
            cert.verify(1, &commitment, &beacon, TAU).is_verified(),
            "the certificate passes wire level verification"
        );
        assert_eq!(
            verifications,
            forgeries + 3,
            "the forgeries are the only extra work and none evicts the genuine signers"
        );
    }

    #[test]
    fn a_same_id_forge_flood_is_bounded_by_the_round_cap() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);

        let impostor = Attester::from_secret(1, &[7u8; 32], 100);
        let forged = impostor.attest(1, 1, 0, 0, commitment.digest(), block, &beacon);
        let flood_size = MAX_ATTEST_VERIFICATIONS_PER_ROUND + 500;
        let atts: Vec<Attestation> = (0..flood_size).map(|_| forged.clone()).collect();

        let (cert, verifications) =
            aggregate_metered(1, 1, 0, block, &commitment, &beacon, &atts, TAU);

        assert!(
            verifications <= MAX_ATTEST_VERIFICATIONS_PER_ROUND,
            "the forge flood is bounded by the round cap, not the size of the flood"
        );
        assert!(
            verifications < flood_size,
            "verification does not scale with the flood"
        );
        assert!(cert.is_none(), "a flood of forgeries forms no certificate");
    }

    #[test]
    fn a_same_id_forge_flood_does_not_starve_other_members() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);

        let impostor = Attester::from_secret(1, &[7u8; 32], 100);
        let forged = impostor.attest(1, 1, 0, 0, commitment.digest(), block, &beacon);
        let flood_size = MAX_ATTEST_VERIFICATIONS_PER_ROUND + 500;
        let mut atts: Vec<Attestation> = (0..flood_size).map(|_| forged.clone()).collect();
        atts.push(b.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));
        atts.push(c.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));
        atts.push(d.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));

        let cert = aggregate(1, 1, 0, block, &commitment, &beacon, &atts, TAU)
            .expect("the genuine members finalize despite a same-id forge flood");
        assert_eq!(
            cert.attesters(),
            vec![2, 3, 4],
            "a flood front-running member 1 does not consume the budget owed to members 2, 3 and 4"
        );
    }

    #[test]
    fn genuine_attestations_cannot_be_rebased_onto_a_forged_smaller_committee() {
        let members: Vec<Attester> = (1..=7).map(|id| Attester::new(id, 100)).collect();
        let refs: Vec<&Attester> = members.iter().collect();
        let beacon = Beacon::genesis();
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let real = committee(&refs);
        let three: Vec<Attestation> = members[..3]
            .iter()
            .map(|a| a.attest(1, 1, 0, 0, real.digest(), block, &beacon))
            .collect();
        assert!(
            aggregate(1, 1, 0, block, &real, &beacon, &three, TAU).is_none(),
            "three of a seven member committee is below the realized floor"
        );
        let forged_refs: Vec<&Attester> = members[..3].iter().collect();
        let forged = committee(&forged_refs);
        assert!(
            aggregate(1, 1, 0, block, &forged, &beacon, &three, TAU).is_none(),
            "attestations bound to the real committee do not verify re based onto a forged smaller committee"
        );
    }

    #[test]
    fn a_members_first_seen_vote_is_admitted_under_any_flood() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);

        let mut atts = vec![
            a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            b.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            c.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
        ];
        let i1 = Attester::from_secret(1, &[7u8; 32], 100);
        let i2 = Attester::from_secret(2, &[8u8; 32], 100);
        let i3 = Attester::from_secret(3, &[9u8; 32], 100);
        for _ in 0..3_000 {
            atts.push(i1.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));
            atts.push(i2.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));
            atts.push(i3.attest(1, 1, 0, 0, commitment.digest(), block, &beacon));
        }

        let cert = aggregate(1, 1, 0, block, &commitment, &beacon, &atts, TAU)
            .expect("a genuine vote seen first for its id finalizes whatever trails it");
        assert_eq!(
            cert.attesters(),
            vec![1, 2, 3],
            "the first round verifies one candidate per member before the cap can bind, so a vote seen first is never evicted"
        );
    }

    #[test]
    fn verify_rejects_a_tau_below_the_realized_committee_floor() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, [9u8; 32], Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);

        let envelope = Envelope::new(1, 0, block, &commitment);
        let two_signers = vec![
            a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            b.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
        ];
        let thin = Certificate::new(envelope, two_signers);
        assert!(
            !thin.verify(1, &commitment, &beacon, 2).is_verified(),
            "two of a realized committee of four cannot finalize even when the caller passes tau = 2"
        );

        let full = aggregate(
            1,
            1,
            0,
            block,
            &commitment,
            &beacon,
            &[
                a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
                b.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
                c.attest(1, 1, 0, 0, commitment.digest(), block, &beacon),
            ],
            TAU,
        )
        .expect("three signers meet the realized-draw floor");
        assert!(full.verify(1, &commitment, &beacon, TAU).is_verified());
    }
}
