// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::fmt;

use qtv_crypto::ml_dsa::{keygen, sign, PublicKey, SecretKey, Signature};
use qtv_crypto::sha3::shake256;

pub type ValidatorId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Validator,
    Prover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Honest,
    Byzantine,
    Offline,
}

// Domain tag under which a validator's secret is expanded into the seed of its
// ML-DSA-65 signing key. It is distinct from the sortition tree domain in
// qtv-sampler, so the one secret a validator holds yields two independent derived
// seeds and knowledge of one derived seed or of the public key reveals neither the
// other seed nor the secret.
const SIGNING_KEY_DOMAIN: &[u8] = b"QORUS/validator-keying/v1/ml-dsa-65-signing";

/// Expand a validator's 32 byte secret into the ML-DSA-65 keygen seed. The secret
/// is high entropy material the validator alone holds; the signing key follows from
/// it by a domain separated SHAKE and never leaves the validator. Only the ML-DSA
/// public key is published as a commitment, and it reveals neither this seed nor the
/// secret.
pub fn signing_key_seed(secret: &[u8; 32]) -> [u8; 32] {
    const D: usize = SIGNING_KEY_DOMAIN.len();
    let mut buf = [0u8; D + 32];
    buf[..D].copy_from_slice(SIGNING_KEY_DOMAIN);
    buf[D..].copy_from_slice(secret);
    let mut out = [0u8; 32];
    shake256(&buf, &mut out);
    out
}

#[derive(Clone)]
pub struct Validator {
    pub id: ValidatorId,
    pub role: Role,
    pub fault: Fault,
    pk: PublicKey,
    sk: SecretKey,
}

impl Validator {
    pub fn from_secret(id: ValidatorId, secret: &[u8; 32]) -> Self {
        let (pk, sk) = keygen(&signing_key_seed(secret));
        Validator {
            id,
            role: Role::Validator,
            fault: Fault::Honest,
            pk,
            sk,
        }
    }

    pub fn prover_from_secret(id: ValidatorId, secret: &[u8; 32]) -> Self {
        let mut v = Validator::from_secret(id, secret);
        v.role = Role::Prover;
        v
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.pk
    }

    pub fn is_offline(&self) -> bool {
        self.fault == Fault::Offline
    }

    pub fn is_byzantine(&self) -> bool {
        self.fault == Fault::Byzantine
    }

    pub fn is_honest(&self) -> bool {
        self.fault == Fault::Honest
    }

    pub fn votes(&self) -> u64 {
        match self.role {
            Role::Prover => 0,
            Role::Validator => {
                if self.is_offline() {
                    0
                } else {
                    1
                }
            }
        }
    }

    pub fn sign(&self, message: &[u8], context: &[u8]) -> Signature {
        sign(&self.sk, message, context, &[0u8; 32]).expect("context within bound")
    }
}

impl fmt::Debug for Validator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Validator")
            .field("id", &self.id)
            .field("role", &self.role)
            .field("fault", &self.fault)
            .finish()
    }
}

// Test and simulation fixtures. These construct a validator from a deterministic,
// per id seed so the test suite and the local devnet simulation are reproducible.
// They are compiled only under `cfg(test)` or the `test-fixtures` feature and are
// never part of a node binary: a production validator is always built from a real
// secret through `from_secret`, so no signing key is ever derived from the public id
// on any running path.
#[cfg(any(test, feature = "test-fixtures"))]
const FIXTURE_SECRET_DOMAIN: &[u8] = b"QORUS/TEST-ONLY/insecure-fixture-secret/v1";

/// A deterministic, per id secret for tests and the devnet simulation only. This is
/// the "fixed test seed" the security work permits inside tests; it is not a
/// production derivation and cannot be reached from a node binary.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn fixture_secret(id: ValidatorId) -> [u8; 32] {
    const D: usize = FIXTURE_SECRET_DOMAIN.len();
    let mut buf = [0u8; D + 8];
    buf[..D].copy_from_slice(FIXTURE_SECRET_DOMAIN);
    buf[D..].copy_from_slice(&id.to_le_bytes());
    let mut out = [0u8; 32];
    shake256(&buf, &mut out);
    out
}

#[cfg(any(test, feature = "test-fixtures"))]
impl Validator {
    pub fn new(id: ValidatorId) -> Self {
        Self::from_secret(id, &fixture_secret(id))
    }

    pub fn prover(id: ValidatorId) -> Self {
        Self::prover_from_secret(id, &fixture_secret(id))
    }
}

#[derive(Clone, Debug)]
pub struct ValidatorSet {
    participants: Vec<Validator>,
}

impl ValidatorSet {
    pub fn from_participants(participants: Vec<Validator>) -> Self {
        ValidatorSet { participants }
    }

    pub fn set_fault(&mut self, id: ValidatorId, fault: Fault) {
        if let Some(v) = self.participants.iter_mut().find(|v| v.id == id) {
            v.fault = fault;
        }
    }

    pub fn get(&self, id: ValidatorId) -> Option<&Validator> {
        self.participants.iter().find(|v| v.id == id)
    }

    pub fn voting_ids(&self) -> Vec<ValidatorId> {
        let mut ids: Vec<ValidatorId> = self
            .participants
            .iter()
            .filter(|v| v.role == Role::Validator)
            .map(|v| v.id)
            .collect();
        ids.sort_unstable();
        ids
    }

    pub fn fault_of(&self, id: ValidatorId) -> Fault {
        self.get(id).map(|v| v.fault).unwrap_or(Fault::Honest)
    }

    pub fn is_voting(&self, id: ValidatorId) -> bool {
        matches!(self.get(id), Some(v) if v.role == Role::Validator)
    }

    pub fn public_key(&self, id: ValidatorId) -> Option<&PublicKey> {
        self.get(id).map(|v| v.public_key())
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
impl ValidatorSet {
    pub fn new(count: usize) -> Self {
        let participants = (1..=count as u64).map(Validator::new).collect();
        ValidatorSet { participants }
    }

    pub fn with_prover(mut self) -> Self {
        let id = self.participants.iter().map(|v| v.id).max().unwrap_or(0) + 1;
        self.participants
            .push(Validator::prover_from_secret(id, &fixture_secret(id)));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voting_ids_are_ascending_validators_only() {
        let set = ValidatorSet::new(4).with_prover();
        assert_eq!(set.voting_ids(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn prover_holds_no_vote() {
        let set = ValidatorSet::new(3).with_prover();
        let prover_id = 4;
        assert!(!set.is_voting(prover_id));
        assert_eq!(set.get(prover_id).unwrap().votes(), 0);
    }

    #[test]
    fn offline_validator_holds_no_vote() {
        let mut set = ValidatorSet::new(3);
        set.set_fault(2, Fault::Offline);
        assert_eq!(set.get(2).unwrap().votes(), 0);
        assert_eq!(set.get(1).unwrap().votes(), 1);
    }

    #[test]
    fn keys_are_deterministic_in_the_secret() {
        let secret = [7u8; 32];
        let a = Validator::from_secret(7, &secret);
        let b = Validator::from_secret(7, &secret);
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn two_secrets_commit_two_public_keys() {
        let a = Validator::from_secret(7, &[1u8; 32]);
        let b = Validator::from_secret(7, &[2u8; 32]);
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn the_signing_seed_is_not_the_secret() {
        let secret = [9u8; 32];
        assert_ne!(signing_key_seed(&secret), secret);
    }
}
