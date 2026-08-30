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
    let mut seen: Vec<u64> = Vec::new();
    for att in attestations {
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
    if seen.len() as u64 >= effective_tau {
        Verdict::Verified
    } else {
        Verdict::Rejected(RejectReason::NotAQuorum)
    }
}
