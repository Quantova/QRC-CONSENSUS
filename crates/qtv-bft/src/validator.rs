use core::fmt;

use qtv_crypto::ml_dsa::{keygen, sign, PublicKey, SecretKey, Signature};

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

const KEY_DOMAIN: &[u8; 8] = b"QORUSVAL";

fn key_seed(id: ValidatorId) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&id.to_le_bytes());
    seed[8..16].copy_from_slice(KEY_DOMAIN);
    seed
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
    pub fn new(id: ValidatorId) -> Self {
        let (pk, sk) = keygen(&key_seed(id));
        Validator {
            id,
            role: Role::Validator,
            fault: Fault::Honest,
            pk,
            sk,
        }
    }

    pub fn prover(id: ValidatorId) -> Self {
        let mut v = Validator::new(id);
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

#[derive(Clone, Debug)]
pub struct ValidatorSet {
    participants: Vec<Validator>,
}

impl ValidatorSet {
    pub fn new(count: usize) -> Self {
        let participants = (1..=count as u64).map(Validator::new).collect();
        ValidatorSet { participants }
    }

    pub fn with_prover(mut self) -> Self {
        let id = self.next_prover_id();
        self.participants.push(Validator::prover(id));
        self
    }

    fn next_prover_id(&self) -> ValidatorId {
        self.participants.iter().map(|v| v.id).max().unwrap_or(0) + 1
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
    fn keys_are_deterministic_across_construction() {
        let a = Validator::new(7);
        let b = Validator::new(7);
        assert_eq!(a.public_key(), b.public_key());
    }
}
