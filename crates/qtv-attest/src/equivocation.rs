// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_bft::block::Height;
use qtv_crypto::ml_dsa::PublicKey;

use crate::attestation::Attestation;
use crate::attester::ValidatorId;

pub struct EquivocationProof {
    pub offender: ValidatorId,
    pub height: Height,
    pub first: Attestation,
    pub second: Attestation,
}

impl EquivocationProof {
    pub fn new(a: Attestation, b: Attestation) -> Option<EquivocationProof> {
        if a.from != b.from || a.height != b.height || a.block == b.block {
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
            first,
            second,
        })
    }

    pub fn verifies(&self, chain_id: u64, attest_pk: &PublicKey) -> bool {
        self.first.from == self.offender
            && self.second.from == self.offender
            && self.first.height == self.height
            && self.second.height == self.height
            && self.first.block != self.second.block
            && self.first.signature_verifies(chain_id, attest_pk)
            && self.second.signature_verifies(chain_id, attest_pk)
    }
}

pub fn equivocators(
    chain_id: u64,
    attestations: &[Attestation],
    key_of: impl Fn(ValidatorId) -> Option<PublicKey>,
) -> Vec<ValidatorId> {
    let mut flagged: Vec<ValidatorId> = Vec::new();
    for (i, a) in attestations.iter().enumerate() {
        for b in &attestations[i + 1..] {
            if a.from != b.from || a.height != b.height || a.block == b.block {
                continue;
            }
            if flagged.contains(&a.from) {
                continue;
            }
            let Some(pk) = key_of(a.from) else { continue };
            if a.signature_verifies(chain_id, &pk) && b.signature_verifies(chain_id, &pk) {
                flagged.push(a.from);
            }
        }
    }
    flagged.sort_unstable();
    flagged
}
