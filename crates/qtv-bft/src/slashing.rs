// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeMap;

use qtv_crypto::ml_dsa::PublicKey;

use crate::attest::Attestation;
use crate::block::Height;
use crate::equivocation::is_equivocation;
use crate::params::VALIDATOR_STAKE_QTOV;
use crate::validator::{ValidatorId, ValidatorSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquivocationEvidence {
    pub first: Attestation,
    pub second: Attestation,
}

impl EquivocationEvidence {
    pub fn offender(&self) -> ValidatorId {
        self.first.from
    }

    pub fn height(&self) -> Height {
        self.first.height
    }

    /// Well formed evidence is a genuine equivocation, the two attestations sharing a
    pub fn is_valid(&self, public_key: &PublicKey) -> bool {
        is_equivocation(&self.first, &self.second)
            && self.first.verify(public_key)
            && self.second.verify(public_key)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Penalty {
    FullBondAndBan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slash {
    pub validator: ValidatorId,
    pub bond_burned: u64,
    pub penalty: Penalty,
}

/// Turn proven evidence into the attributable slash. The signatures are checked against
pub fn slash_from_evidence(evidence: &EquivocationEvidence, set: &ValidatorSet) -> Option<Slash> {
    let public_key = set.public_key(evidence.offender())?;
    if !evidence.is_valid(public_key) {
        return None;
    }
    Some(Slash {
        validator: evidence.offender(),
        bond_burned: VALIDATOR_STAKE_QTOV,
        penalty: Penalty::FullBondAndBan,
    })
}

/// A streaming detector. It remembers the first attestation each validator makes at each
#[derive(Clone, Debug, Default)]
pub struct EquivocationDetector {
    seen: BTreeMap<(ValidatorId, Height), Attestation>,
}

impl EquivocationDetector {
    pub fn new() -> Self {
        EquivocationDetector::default()
    }

    pub fn observe(&mut self, attestation: &Attestation) -> Option<EquivocationEvidence> {
        let key = (attestation.from, attestation.height);
        match self.seen.get(&key) {
            Some(previous) if is_equivocation(previous, attestation) => Some(EquivocationEvidence {
                first: previous.clone(),
                second: attestation.clone(),
            }),
            Some(_) => None,
            None => {
                self.seen.insert(key, attestation.clone());
                None
            }
        }
    }
}

/// The record of applied slashes: which validators are banned and how much bond was
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SlashLedger {
    slashes: Vec<Slash>,
}

impl SlashLedger {
    pub fn new() -> Self {
        SlashLedger::default()
    }

    pub fn apply(&mut self, slash: Slash) -> bool {
        if self.is_banned(slash.validator) {
            return false;
        }
        self.slashes.push(slash);
        true
    }

    pub fn is_banned(&self, id: ValidatorId) -> bool {
        self.slashes.iter().any(|s| s.validator == id)
    }

    pub fn slashes(&self) -> &[Slash] {
        &self.slashes
    }

    pub fn burned_bond(&self) -> u64 {
        self.slashes.iter().map(|s| s.bond_burned).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, Parent};
    use crate::params::VALIDATOR_STAKE_QTOV;
    use crate::validator::Validator;

    fn att(v: &Validator, height: u64, val: [u8; 32]) -> Attestation {
        Attestation::create(v, height, Block::new(height, val, Parent::Genesis))
    }

    #[test]
    fn an_equivocator_is_detected_and_slashed_end_to_end() {
        let set = ValidatorSet::new(4);
        let offender = set.get(2).unwrap();
        let first = att(offender, 1, [1u8; 32]);
        let second = att(offender, 1, [2u8; 32]);

        let mut detector = EquivocationDetector::new();
        assert!(detector.observe(&first).is_none(), "the first vote is not yet a fault");
        let evidence = detector.observe(&second).expect("the conflicting vote is caught");
        assert_eq!(evidence.offender(), 2);
        assert_eq!(evidence.height(), 1);

        let slash = slash_from_evidence(&evidence, &set).expect("the evidence drives a slash");
        assert_eq!(slash.validator, 2);
        assert_eq!(slash.penalty, Penalty::FullBondAndBan);
        assert_eq!(slash.bond_burned, VALIDATOR_STAKE_QTOV);

        let mut ledger = SlashLedger::new();
        assert!(ledger.apply(slash.clone()));
        assert!(!ledger.apply(slash), "a validator is slashed once");
        assert!(ledger.is_banned(2));
        assert_eq!(ledger.burned_bond(), VALIDATOR_STAKE_QTOV);
    }

    #[test]
    fn an_honest_validator_is_never_slashed() {
        let set = ValidatorSet::new(4);
        let mut detector = EquivocationDetector::new();
        for h in 1..=3u64 {
            assert!(detector.observe(&att(set.get(1).unwrap(), h, [9u8; 32])).is_none());
        }
        let resend = att(set.get(1).unwrap(), 1, [9u8; 32]);
        assert!(detector.observe(&resend).is_none(), "resending one vote is not a fault");
    }

    #[test]
    fn forged_evidence_against_an_honest_validator_does_not_slash() {
        let set = ValidatorSet::new(4);
        let attacker = set.get(3).unwrap();
        let mut first = att(attacker, 1, [1u8; 32]);
        let mut second = att(attacker, 1, [2u8; 32]);
        first.from = 1;
        second.from = 1;

        let mut detector = EquivocationDetector::new();
        assert!(detector.observe(&first).is_none());
        let evidence = detector.observe(&second).expect("the claimed pair is paired");
        assert_eq!(evidence.offender(), 1);

        assert!(!evidence.is_valid(set.public_key(1).unwrap()));
        assert!(
            slash_from_evidence(&evidence, &set).is_none(),
            "an unsigned pair must never slash the named validator"
        );
    }

    #[test]
    fn one_conflicting_signer_is_caught_within_a_stream() {
        let set = ValidatorSet::new(5);
        let mut detector = EquivocationDetector::new();
        let mut ledger = SlashLedger::new();
        let stream = [
            att(set.get(1).unwrap(), 1, [7u8; 32]),
            att(set.get(2).unwrap(), 1, [7u8; 32]),
            att(set.get(4).unwrap(), 1, [7u8; 32]),
            att(set.get(3).unwrap(), 1, [7u8; 32]),
            att(set.get(4).unwrap(), 1, [8u8; 32]),
        ];
        for a in &stream {
            if let Some(evidence) = detector.observe(a) {
                if let Some(slash) = slash_from_evidence(&evidence, &set) {
                    ledger.apply(slash);
                }
            }
        }
        assert_eq!(ledger.slashes().len(), 1);
        assert!(ledger.is_banned(4));
        for honest in [1u64, 2, 3, 5] {
            assert!(!ledger.is_banned(honest));
        }
    }
}
