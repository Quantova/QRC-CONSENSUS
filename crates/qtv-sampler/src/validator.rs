//! A sampler validator holds a verifiable random function key pair from the

use qtv_crypto::vrf_mldsa::{
    keygen, prove, OUTPUT_BYTES, PROOF_BYTES, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES,
};

use crate::stake::Stake;

pub type ValidatorId = u64;

/// A participant is either a voting validator or a prover that holds no vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Validator,
    Prover,
}

/// The liveness behaviour of a validator in a round. It does not affect
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Honest,
    Offline,
}

/// Domain tag folded into a sortition key seed, separating these keys from any
const KEY_DOMAIN: &[u8; 8] = b"QORUSSMP";

fn key_seed(id: ValidatorId) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&id.to_le_bytes());
    seed[8..16].copy_from_slice(KEY_DOMAIN);
    seed
}

/// A validator with a deterministic verifiable random function key pair, a
#[derive(Clone)]
pub struct SamplerValidator {
    pub id: ValidatorId,
    pub role: Role,
    pub fault: Fault,
    stake: Stake,
    sk: [u8; SECRET_KEY_BYTES],
    pk: [u8; PUBLIC_KEY_BYTES],
}

impl SamplerValidator {
    /// A voting validator with the given native stake amount.
    pub fn new(id: ValidatorId, stake: u64) -> Self {
        let (sk, pk) = keygen(&key_seed(id));
        SamplerValidator {
            id,
            role: Role::Validator,
            fault: Fault::Honest,
            stake: Stake::native(stake),
            sk,
            pk,
        }
    }

    /// A validator holding a custom stake, used to model a bridged holding that
    pub fn with_stake(id: ValidatorId, stake: Stake) -> Self {
        let mut v = SamplerValidator::new(id, 0);
        v.stake = stake;
        v
    }

    /// A prover holds no vote and no stake and is never selected.
    pub fn prover(id: ValidatorId) -> Self {
        let mut v = SamplerValidator::new(id, 0);
        v.role = Role::Prover;
        v
    }

    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.pk
    }

    pub fn stake(&self) -> Stake {
        self.stake
    }

    pub fn is_prover(&self) -> bool {
        self.role == Role::Prover
    }

    pub fn is_offline(&self) -> bool {
        self.fault == Fault::Offline
    }

    /// The native weight this validator brings to sortition. A prover and a
    pub fn weight(&self) -> u64 {
        match self.role {
            Role::Prover => 0,
            Role::Validator => self.stake.weight(),
        }
    }

    /// Evaluate the verifiable random function over the input with the secret
    pub fn evaluate(&self, input: &[u8]) -> ([u8; OUTPUT_BYTES], [u8; PROOF_BYTES]) {
        prove(&self.sk, input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stake::{OriginTag, Stake};

    #[test]
    fn keys_are_deterministic_across_construction() {
        let a = SamplerValidator::new(7, 2_000);
        let b = SamplerValidator::new(7, 2_000);
        assert_eq!(a.public_key(), b.public_key());
    }

    #[test]
    fn prover_weighs_zero() {
        let p = SamplerValidator::prover(9);
        assert!(p.is_prover());
        assert_eq!(p.weight(), 0);
    }

    #[test]
    fn bridged_holding_weighs_zero() {
        let tag = OriginTag { chain: 1, asset: 1 };
        let v = SamplerValidator::with_stake(3, Stake::bridged(1_000_000, tag));
        assert_eq!(v.weight(), 0);
    }

    #[test]
    fn offline_validator_keeps_its_weight_and_candidacy() {
        let mut v = SamplerValidator::new(2, 2_000);
        v.fault = Fault::Offline;
        assert!(v.is_offline());
        assert_eq!(v.weight(), 2_000);
    }
}
