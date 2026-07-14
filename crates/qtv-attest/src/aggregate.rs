//! Aggregation of entitled attestations into a stage one certificate. An

use qtv_bft::block::{Block, Height};

use qtv_sampler::beacon::Beacon;

use crate::attestation::Attestation;
use crate::certificate::{Certificate, Envelope};
use crate::committee::CommitteeCommitment;
use crate::params::is_quorum;

/// Aggregate the entitled supermajority of attestations for a decision into a
pub fn aggregate(
    height: Height,
    slot: u64,
    block: Block,
    commitment: &CommitteeCommitment,
    beacon: &Beacon,
    attestations: &[Attestation],
) -> Option<Certificate> {
    let mut admitted: Vec<Attestation> = Vec::new();
    let mut seen: Vec<u64> = Vec::new();
    for att in attestations {
        if att.height != height || att.slot != slot || att.block != block {
            continue;
        }
        let member = match commitment.member(att.from) {
            Some(m) => m,
            None => continue,
        };
        if !att.signature_verifies(&member.attest_pk) {
            continue;
        }
        if !att.is_entitled(
            &member.vrf_pk,
            beacon,
            member.weight,
            commitment.total_weight,
            commitment.budget,
        ) {
            continue;
        }
        if seen.contains(&att.from) {
            continue;
        }
        seen.push(att.from);
        admitted.push(att.clone());
    }
    if is_quorum(seen.len(), commitment.len()) {
        let envelope = Envelope::new(height, slot, block, commitment);
        Some(Certificate::stage_one(envelope, admitted))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attester::Attester;
    use qtv_bft::block::Parent;

    // A budget that saturates every member share, so a valid draw is entitled.
    const BUDGET: u64 = 4;

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
        let block = Block::new(1, 9, Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);
        let atts = vec![
            a.attest(1, 0, block, &beacon),
            b.attest(1, 0, block, &beacon),
            c.attest(1, 0, block, &beacon),
        ];
        let cert = aggregate(1, 0, block, &commitment, &beacon, &atts).expect("quorum");
        assert_eq!(cert.attesters(), vec![1, 2, 3]);
    }

    #[test]
    fn below_the_supermajority_does_not_aggregate() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, 9, Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);
        let atts = vec![
            a.attest(1, 0, block, &beacon),
            b.attest(1, 0, block, &beacon),
        ];
        assert!(aggregate(1, 0, block, &commitment, &beacon, &atts).is_none());
    }

    #[test]
    fn a_duplicate_signer_counts_once() {
        let a = Attester::new(1, 100);
        let b = Attester::new(2, 100);
        let c = Attester::new(3, 100);
        let d = Attester::new(4, 100);
        let beacon = Beacon::genesis();
        let block = Block::new(1, 9, Parent::Genesis);
        let commitment = committee(&[&a, &b, &c, &d]);
        // a attests twice; only two distinct signers, below the quorum of three.
        let atts = vec![
            a.attest(1, 0, block, &beacon),
            a.attest(1, 0, block, &beacon),
            b.attest(1, 0, block, &beacon),
        ];
        assert!(aggregate(1, 0, block, &commitment, &beacon, &atts).is_none());
    }
}
