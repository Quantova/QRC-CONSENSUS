// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sampler::beacon::Beacon;

use crate::attestation::Attestation;
use crate::certificate::{Certificate, Envelope};
use crate::committee::CommitteeCommitment;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    CommitmentMismatch,
    WrongSubject,
    NotOnCommittee,
    BadSignature,
    NotEntitled,
    DuplicateAttester,
    NotAQuorum,
    MixedViews,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Verified,
    Rejected(RejectReason),
}

impl Verdict {
    pub fn is_verified(&self) -> bool {
        matches!(self, Verdict::Verified)
    }
}

impl Certificate {
    pub fn verify(
        &self,
        chain_id: u64,
        commitment: &CommitteeCommitment,
        beacon: &Beacon,
        tau: u64,
    ) -> Verdict {
        verify_body(
            chain_id,
            &self.envelope,
            &self.attestations,
            commitment,
            beacon,
            tau,
        )
    }
}

fn verify_body(
    chain_id: u64,
    envelope: &Envelope,
    attestations: &[Attestation],
    commitment: &CommitteeCommitment,
    beacon: &Beacon,
    tau: u64,
) -> Verdict {
    let committee_digest = commitment.digest();
    if envelope.committee != committee_digest {
        return Verdict::Rejected(RejectReason::CommitmentMismatch);
    }
    // A precommit names the block, not the view it was cast in, so precommits from two
    // views are not one decision. A node locked in one view may unlock onto another value
    // in a later one, and a certificate counting both would finalize a block while a
    // second one gathers its own quorum at the same height. A quorum is one view's.
    let view = attestations.first().map(|att| att.view);
    let mut seen: Vec<u64> = Vec::new();
    for att in attestations {
        if Some(att.view) != view {
            return Verdict::Rejected(RejectReason::MixedViews);
        }
        if att.height != envelope.height || att.slot != envelope.slot || att.block != envelope.block
        {
            return Verdict::Rejected(RejectReason::WrongSubject);
        }
        if att.committee != committee_digest {
            return Verdict::Rejected(RejectReason::CommitmentMismatch);
        }
        let member = match commitment.member(att.from) {
            Some(m) => m,
            None => return Verdict::Rejected(RejectReason::NotOnCommittee),
        };
        if !att.signature_verifies(chain_id, &member.attest_pk) {
            return Verdict::Rejected(RejectReason::BadSignature);
        }
        if !att.is_entitled(
            &member.root,
            beacon,
            member.weight,
            commitment.total_weight,
            commitment.budget,
        ) {
            return Verdict::Rejected(RejectReason::NotEntitled);
        }
        if seen.contains(&att.from) {
            return Verdict::Rejected(RejectReason::DuplicateAttester);
        }
        seen.push(att.from);
    }
    let effective_tau = tau.max(qtv_sampler::params::finality_threshold(
        commitment.len() as u64
    ));
    let seen_stake: u128 = seen
        .iter()
        .map(|id| commitment.stake_of(*id) as u128)
        .fold(0u128, |acc, w| acc.saturating_add(w));
    let committee_stake = commitment.committee_stake() as u128;
    let weight_ok =
        committee_stake == 0 || seen_stake.saturating_mul(3) >= committee_stake.saturating_mul(2);
    if seen.len() as u64 >= effective_tau && weight_ok {
        Verdict::Verified
    } else {
        Verdict::Rejected(RejectReason::NotAQuorum)
    }
}
