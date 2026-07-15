//! Light client verification. A light client holds only public inputs: the

use qtv_sampler::beacon::Beacon;

use crate::certificate::{Body, Certificate, Envelope, Stage1Body, SuccinctVerifier};
use crate::committee::CommitteeCommitment;
use crate::params::is_quorum;

/// The reason a certificate did not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// The envelope committee digest does not match the given commitment.
    CommitmentMismatch,
    /// An attestation names a different height, slot, or block than the envelope.
    WrongSubject,
    /// A signer is not on the committee.
    NotOnCommittee,
    /// A signature does not verify under the member module lattice key.
    BadSignature,
    /// A membership draw does not prove entitlement under the member stake.
    NotEntitled,
    /// The same signer appears twice.
    DuplicateAttester,
    /// The distinct entitled signers do not form a supermajority.
    NotAQuorum,
    /// The stage two succinct proof failed the seam verifier.
    SuccinctProof,
}

/// The outcome of verifying a certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The certificate finalizes its block.
    Verified,
    /// The certificate does not verify, with the reason.
    Rejected(RejectReason),
    /// A stage two certificate reached without a succinct verifier. The succinct
    StageTwoPending,
}

impl Verdict {
    pub fn is_verified(&self) -> bool {
        matches!(self, Verdict::Verified)
    }
}

impl Certificate {
    /// Verify the certificate against a committee commitment and beacon using
    pub fn verify(&self, commitment: &CommitteeCommitment, beacon: &Beacon) -> Verdict {
        match &self.body {
            Body::Stage1(body) => verify_stage_one(&self.envelope, body, commitment, beacon),
            Body::Stage2(_) => Verdict::StageTwoPending,
        }
    }

    /// Verify the certificate, checking a stage two body through the given
    pub fn verify_with(
        &self,
        commitment: &CommitteeCommitment,
        beacon: &Beacon,
        verifier: &dyn SuccinctVerifier,
    ) -> Verdict {
        match &self.body {
            Body::Stage1(body) => verify_stage_one(&self.envelope, body, commitment, beacon),
            Body::Stage2(body) => {
                if self.envelope.committee != commitment.digest() {
                    Verdict::Rejected(RejectReason::CommitmentMismatch)
                } else if verifier.verify(&self.envelope, body, commitment) {
                    Verdict::Verified
                } else {
                    Verdict::Rejected(RejectReason::SuccinctProof)
                }
            }
        }
    }
}

fn verify_stage_one(
    envelope: &Envelope,
    body: &Stage1Body,
    commitment: &CommitteeCommitment,
    beacon: &Beacon,
) -> Verdict {
    if envelope.committee != commitment.digest() {
        return Verdict::Rejected(RejectReason::CommitmentMismatch);
    }
    let mut seen: Vec<u64> = Vec::new();
    for att in &body.attestations {
        if att.height != envelope.height || att.slot != envelope.slot || att.block != envelope.block
        {
            return Verdict::Rejected(RejectReason::WrongSubject);
        }
        let member = match commitment.member(att.from) {
            Some(m) => m,
            None => return Verdict::Rejected(RejectReason::NotOnCommittee),
        };
        if !att.signature_verifies(&member.attest_pk) {
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
    if is_quorum(seen.len(), commitment.len()) {
        Verdict::Verified
    } else {
        Verdict::Rejected(RejectReason::NotAQuorum)
    }
}
