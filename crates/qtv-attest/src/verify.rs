// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_sampler::beacon::Beacon;
use qtv_sampler::sortition::DrawMode;

use crate::attestation::{Attestation, ChainBinding};
use crate::attester::ValidatorId;
use crate::certificate::{Certificate, Envelope};
use crate::committee::CommitteeCommitment;
use qtv_crypto::ml_dsa::PublicKey;
use qtv_sampler::committee::{CommitteeView, PublishedReveal};

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
    BadCommitment,
    HeightMismatch,
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
    pub fn verify_with_trusted_commitment(
        &self,
        chain_id: impl Into<ChainBinding>,
        commitment: &CommitteeCommitment,
        beacon: &Beacon,
        tau: u64,
    ) -> Verdict {
        let chain_id: ChainBinding = chain_id.into();
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

impl Certificate {
    pub fn verify_registered(
        &self,
        chain_id: impl Into<ChainBinding>,
        view: &CommitteeView,
        beacon: &Beacon,
        tau: u64,
        attest_key: impl Fn(ValidatorId) -> Option<PublicKey>,
    ) -> Verdict {
        let chain_id: ChainBinding = chain_id.into();
        let reveals: Vec<PublishedReveal> = if self.committee_reveals.is_empty() {
            self.attestations
                .iter()
                .map(|att| PublishedReveal::new(att.from, att.membership.clone()))
                .collect()
        } else {
            self.committee_reveals.clone()
        };
        let committee = view.form_committee(beacon, self.envelope.slot, &reveals);
        let Some(commitment) =
            CommitteeCommitment::from_view(self.envelope.slot, view, &committee, attest_key)
        else {
            return Verdict::Rejected(RejectReason::BadCommitment);
        };
        self.verify_with_trusted_commitment(chain_id, &commitment, beacon, tau)
    }
}

fn verify_body(
    chain_id: impl Into<ChainBinding>,
    envelope: &Envelope,
    attestations: &[Attestation],
    commitment: &CommitteeCommitment,
    beacon: &Beacon,
    tau: u64,
) -> Verdict {
    let chain_id: ChainBinding = chain_id.into();
    let committee_digest = commitment.digest();
    if envelope.committee != committee_digest {
        return Verdict::Rejected(RejectReason::CommitmentMismatch);
    }
    if envelope.slot != commitment.slot {
        return Verdict::Rejected(RejectReason::CommitmentMismatch);
    }
    if commitment.total_weight < commitment.committee_weight()
        || commitment.budget == 0
        || commitment.budget > qtv_sampler::params::COMMITTEE_BUDGET
    {
        return Verdict::Rejected(RejectReason::BadCommitment);
    }
    if envelope.height != envelope.block.height {
        return Verdict::Rejected(RejectReason::HeightMismatch);
    }
    if attestations.len() > commitment.len() {
        return Verdict::Rejected(RejectReason::NotAQuorum);
    }
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
        if seen.contains(&att.from) {
            continue;
        }
        if !att.is_entitled_in(
            commitment.mode,
            &member.root,
            beacon,
            member.weight,
            commitment.total_weight,
            commitment.budget,
        ) {
            return Verdict::Rejected(RejectReason::NotEntitled);
        }
        seen.push(att.from);
    }
    let effective_tau = if commitment.mode == DrawMode::Full {
        1
    } else {
        tau.max(qtv_sampler::params::finality_threshold(
            commitment.len() as u64
        ))
    };
    let seen_stake: u128 = seen
        .iter()
        .map(|id| commitment.stake_of(*id) as u128)
        .fold(0u128, |acc, w| acc.saturating_add(w));
    let committee_stake = commitment.quorum_stake();
    let weight_ok =
        committee_stake > 0 && seen_stake.saturating_mul(3) >= committee_stake.saturating_mul(2);
    if seen.len() as u64 >= effective_tau && weight_ok {
        Verdict::Verified
    } else {
        Verdict::Rejected(RejectReason::NotAQuorum)
    }
}
