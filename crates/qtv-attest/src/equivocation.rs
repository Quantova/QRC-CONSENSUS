// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::{HashMap, HashSet};

use qtv_bft::block::Height;
use qtv_bft::committee::View;
use qtv_crypto::ml_dsa::PublicKey;
use qtv_sampler::beacon::Beacon;

use crate::attestation::{Attestation, ChainBinding};
use crate::attester::ValidatorId;
use crate::certificate::Certificate;
use crate::committee::CommitteeCommitment;

pub const MAX_EQUIVOCATION_CANDIDATES: usize = 4 * crate::params::COMMITTEE_BUDGET as usize;

pub const MAX_FAILED_VERIFIES_PER_VALIDATOR: usize = 4;

fn votes_on_a_block(att: &Attestation) -> bool {
    att.block.cost != crate::params::AUXILIARY_SUBJECT_COST
}

fn certificate_view(cert: &Certificate) -> Option<View> {
    let view = cert.attestations.first()?.view;
    cert.attestations
        .iter()
        .all(|a| {
            a.view == view && a.height == cert.envelope.height && a.block == cert.envelope.block
        })
        .then_some(view)
}

pub struct EquivocationProof {
    pub offender: ValidatorId,
    pub height: Height,
    pub view: View,
    pub first: Attestation,
    pub second: Attestation,
}

impl EquivocationProof {
    pub fn new(a: Attestation, b: Attestation) -> Option<EquivocationProof> {
        if a.from != b.from
            || a.height != b.height
            || a.view != b.view
            || a.block == b.block
            || !votes_on_a_block(&a)
            || !votes_on_a_block(&b)
        {
            return None;
        }
        let (first, second) = if a.block.to_bytes() <= b.block.to_bytes() {
            (a, b)
        } else {
            (b, a)
        };
        Some(EquivocationProof {
            offender: first.from,
            height: first.height,
            view: first.view,
            first,
            second,
        })
    }

    pub fn verifies(&self, chain_id: impl Into<ChainBinding>, attest_pk: &PublicKey) -> bool {
        let chain_id: ChainBinding = chain_id.into();
        self.first.from == self.offender
            && self.second.from == self.offender
            && self.first.height == self.height
            && self.second.height == self.height
            && self.first.view == self.view
            && self.second.view == self.view
            && self.first.block != self.second.block
            && votes_on_a_block(&self.first)
            && votes_on_a_block(&self.second)
            && self.first.signature_verifies(chain_id, attest_pk)
            && self.second.signature_verifies(chain_id, attest_pk)
    }
}

pub fn equivocators(
    chain_id: impl Into<ChainBinding>,
    attestations: &[Attestation],
    key_of: impl Fn(ValidatorId) -> Option<PublicKey>,
) -> Vec<ValidatorId> {
    let chain_id: ChainBinding = chain_id.into();
    type Bucket<'a> = (HashSet<Vec<u8>>, Vec<&'a Attestation>);
    let mut groups: HashMap<(ValidatorId, Height, View), Bucket> = HashMap::new();
    for att in attestations.iter().filter(|a| votes_on_a_block(a)) {
        let (blocks, bucket) = groups.entry((att.from, att.height, att.view)).or_default();
        if blocks.insert(att.block.to_bytes()) {
            bucket.push(att);
        }
    }
    let mut keys: Vec<(ValidatorId, Height, View)> = groups
        .iter()
        .filter(|(_, (_, bucket))| bucket.len() >= 2)
        .map(|(key, _)| *key)
        .collect();
    keys.sort_unstable();
    let mut budget = MAX_EQUIVOCATION_CANDIDATES;
    let mut failures: HashMap<ValidatorId, usize> = HashMap::new();
    let mut flagged: Vec<ValidatorId> = Vec::new();
    for key in keys {
        if budget == 0 {
            break;
        }
        if flagged.contains(&key.0) {
            continue;
        }
        if failures.get(&key.0).copied().unwrap_or(0) >= MAX_FAILED_VERIFIES_PER_VALIDATOR {
            continue;
        }
        let Some(pk) = key_of(key.0) else { continue };
        let mut valid = 0usize;
        for att in &groups[&key].1 {
            let failed = failures.entry(key.0).or_insert(0);
            if budget == 0 || valid == 2 || *failed >= MAX_FAILED_VERIFIES_PER_VALIDATOR {
                break;
            }
            budget -= 1;
            if att.signature_verifies(chain_id, &pk) {
                valid += 1;
            } else {
                *failed += 1;
            }
        }
        if valid == 2 {
            flagged.push(key.0);
        }
    }
    flagged.sort_unstable();
    flagged
}

pub struct ConflictingCertificates<'a> {
    pub first: &'a Certificate,
    pub second: &'a Certificate,
}

impl<'a> ConflictingCertificates<'a> {
    pub fn new(first: &'a Certificate, second: &'a Certificate) -> Option<Self> {
        if first.envelope.height != second.envelope.height
            || first.envelope.block == second.envelope.block
            || first.envelope.block.cost == crate::params::AUXILIARY_SUBJECT_COST
            || second.envelope.block.cost == crate::params::AUXILIARY_SUBJECT_COST
        {
            return None;
        }
        match (certificate_view(first), certificate_view(second)) {
            (Some(a), Some(b)) if a == b => {}
            _ => return None,
        }
        Some(ConflictingCertificates { first, second })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn offenders(
        &self,
        chain_id: impl Into<ChainBinding>,
        first_commitment: &CommitteeCommitment,
        first_beacon: &Beacon,
        first_tau: u64,
        second_commitment: &CommitteeCommitment,
        second_beacon: &Beacon,
        second_tau: u64,
    ) -> Vec<ValidatorId> {
        let chain_id: ChainBinding = chain_id.into();
        if !self
            .first
            .verify_with_trusted_commitment(chain_id, first_commitment, first_beacon, first_tau)
            .is_verified()
            || !self
                .second
                .verify_with_trusted_commitment(
                    chain_id,
                    second_commitment,
                    second_beacon,
                    second_tau,
                )
                .is_verified()
        {
            return Vec::new();
        }
        let second = self.second.attesters();
        self.first
            .attesters()
            .into_iter()
            .filter(|id| second.binary_search(id).is_ok())
            .collect()
    }
}
