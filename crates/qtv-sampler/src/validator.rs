//! A sampler validator is a staking account. It holds a one time key tree, a
//! native stake, and a role. The tree backs the sortition draw: at registration
//! the account commits the tree root and bonds it to its stake, and for a slot it
//! reveals the preimage at that position with the Merkle path to the root. Any
//! node rechecks the reveal against the committed root without a secret.
//!
//! A prover holds no vote and no stake and is never selected. An offline account
//! keeps its stake and its candidacy, since selection does not depend on liveness;
//! if selected it is simply skipped in the round and is never slashed. Only
//! equivocation and the attributable sortition faults are slashable, handled by
//! the consensus and economics layer, not here.

use crate::onetime::{OneTimeTree, Root};
use crate::sortition::Credential;
use crate::stake::Stake;

pub type ValidatorId = u64;

/// The number of slots an account's one time tree serves by default. Each slot is
/// one leaf, and a position past this count is not a slot the tree serves.
pub const DEFAULT_SLOTS: u64 = 64;

/// A participant is either a voting validator or a prover that holds no vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Validator,
    Prover,
}

/// The liveness behaviour of a validator in a round. It does not affect
/// selection: an offline validator is still eligible and, if selected, is skipped
/// rather than slashed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Honest,
    Offline,
}

/// Domain tag folded into a sortition tree seed, separating these seeds from any
/// other key use in the stack.
const SEED_DOMAIN: &[u8; 8] = b"QORUSSMP";

fn tree_seed(id: ValidatorId) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&id.to_le_bytes());
    seed[8..16].copy_from_slice(SEED_DOMAIN);
    seed
}

/// A staking account with a deterministic one time key tree, a native stake, a
/// role, and a liveness mode.
pub struct SamplerValidator {
    pub id: ValidatorId,
    pub role: Role,
    pub fault: Fault,
    stake: Stake,
    tree: OneTimeTree,
}

impl Clone for SamplerValidator {
    fn clone(&self) -> Self {
        // The tree is rebuilt from the same seed and slot count, so a clone
        // commits the same root and reveals the same preimages.
        SamplerValidator {
            id: self.id,
            role: self.role,
            fault: self.fault,
            stake: self.stake,
            tree: OneTimeTree::new(tree_seed(self.id), self.tree.slots()),
        }
    }
}

impl SamplerValidator {
    /// A voting account with the given native stake amount over the default slot
    /// count.
    pub fn new(id: ValidatorId, stake: u64) -> Self {
        Self::with_slots(id, stake, DEFAULT_SLOTS)
    }

    /// A voting account with an explicit slot count, used to size small trees in
    /// tests.
    pub fn with_slots(id: ValidatorId, stake: u64, slots: u64) -> Self {
        SamplerValidator {
            id,
            role: Role::Validator,
            fault: Fault::Honest,
            stake: Stake::native(stake),
            tree: OneTimeTree::new(tree_seed(id), slots),
        }
    }

    /// An account holding a custom stake, used to model a bridged holding that is
    /// never valid as stake.
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

    /// The committed root, the account's on chain identity in the stake registry.
    /// Verification of any draw from this account is against this root.
    pub fn root(&self) -> Root {
        self.tree.root()
    }

    /// The number of slots this account's tree serves.
    pub fn slots(&self) -> u64 {
        self.tree.slots()
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

    /// The native weight this account brings to sortition. A prover and a bridged
    /// holding both weigh zero.
    pub fn weight(&self) -> u64 {
        match self.role {
            Role::Prover => 0,
            Role::Validator => self.stake.weight(),
        }
    }

    /// Reveal the credential for a slot: the account's one time preimage at that
    /// position with the Merkle path to its registered root. This is the account's
    /// single valid draw for the slot; the preimage is fixed by position and the
    /// tree was committed before any beacon, so there is nothing to re roll.
    pub fn reveal(&self, slot: u64) -> Credential {
        Credential {
            position: slot,
            preimage: self.tree.preimage(slot),
            path: self.tree.path(slot),
        }
    }

    /// Reveal a credential for one slot but bind it to another position, forging
    /// an out of position draw. The Merkle path still authenticates the preimage
    /// at its real position `leaf_slot`, so a verifier that checks the position
    /// rejects it and a fault check proves it. Used to test the enforcement.
    pub fn reveal_out_of_position(&self, leaf_slot: u64, claim_slot: u64) -> Credential {
        Credential {
            position: claim_slot,
            preimage: self.tree.preimage(leaf_slot),
            path: self.tree.path(leaf_slot),
        }
    }
}

/// The registered commitment of a staking account: its id, its bonded root, and
/// its native weight. This is the public record a verifier reads from the stake
/// registry to recheck a draw. An account not in the registry has no root, so any
/// draw claiming it is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    pub id: ValidatorId,
    pub root: Root,
    pub weight: u64,
}

impl Registration {
    /// The registration a validator publishes at bonding time.
    pub fn of(validator: &SamplerValidator) -> Self {
        Registration {
            id: validator.id,
            root: validator.root(),
            weight: validator.weight(),
        }
    }
}

/// A forged path, used only in tests to show a preimage that does not sit at its
/// claimed position is rejected.
#[cfg(test)]
pub fn forged_path(depth: usize) -> crate::onetime::MerklePath {
    crate::onetime::MerklePath {
        siblings: vec![[0u8; 32]; depth],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stake::{OriginTag, Stake};

    #[test]
    fn roots_are_deterministic_across_construction() {
        let a = SamplerValidator::new(7, 2_000);
        let b = SamplerValidator::new(7, 2_000);
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn a_clone_commits_the_same_root_and_reveals() {
        let a = SamplerValidator::new(3, 2_000);
        let b = a.clone();
        assert_eq!(a.root(), b.root());
        assert_eq!(a.reveal(4), b.reveal(4));
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

    #[test]
    fn a_reveal_authenticates_to_the_registered_root() {
        let v = SamplerValidator::new(1, 100);
        let reg = Registration::of(&v);
        let cred = v.reveal(5);
        assert!(reg.root.verify_membership(5, &cred.preimage, &cred.path));
    }
}
