//! Attributable sortition faults and the checks any node runs on them. The one
//! time construction makes an honest account's draw for a slot unique, so the two
//! faults that break the budget of one leave evidence on the chain that any node
//! verifies from the account's registered root alone. The consensus and economics
//! layer applies the slash, a hard burn of the whole bond and a permanent ban;
//! here the fault is made provable.
//!
//! The two faults are a preimage used out of its position, and two distinct draws
//! revealed for one slot from one account. Both are checkable from public values.
//! As with double signing in the core, attribution of a credential to an account
//! is the attestation signature's job in the attestation layer; these predicates
//! prove that the draws themselves are a fault.

use crate::onetime::Root;
use crate::sortition::{verify_membership, Credential};

/// Evidence that an account revealed a committed one time leaf out of its
/// position. The preimage authenticates to the account's registered root at its
/// own position P, yet the credential was put forward for slot N with N not equal
/// to P. One leaf serves one slot, so using a committed leaf at another slot is
/// the out of position fault. Any node checks it from the registered root and the
/// two values alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutOfPosition {
    pub root: Root,
    /// A credential whose preimage genuinely sits at position `credential.position`
    /// in the root.
    pub credential: Credential,
    /// The slot the credential was submitted for.
    pub used_slot: u64,
}

impl OutOfPosition {
    /// True when the fault is proven: the preimage authenticates to the root at
    /// its own position, and it was used for a different slot. The first half
    /// shows the leaf is a genuine committed leaf of this account, the second that
    /// it was reused off its position.
    pub fn is_proven(&self) -> bool {
        self.used_slot != self.credential.position
            && self.root.verify_membership(
                self.credential.position,
                &self.credential.preimage,
                &self.credential.path,
            )
    }
}

/// Evidence that an account revealed two distinct draws for one slot. A committed
/// root has exactly one authenticatable leaf at a position, so two distinct
/// credentials put forward for one slot cannot both be the committed one time
/// leaf: the account has equivocated on its single draw for the slot. At least one
/// credential must authenticate to the root at the slot, which shows the pair is a
/// real reveal of this account and not a fabrication over a root that never
/// revealed at the slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoubleDraw {
    pub root: Root,
    pub slot: u64,
    pub first: Credential,
    pub second: Credential,
}

impl DoubleDraw {
    /// True when the fault is proven: two distinct credentials, both put forward
    /// for the slot, with at least one authenticating to the root at the slot. The
    /// one time construction guarantees the other cannot also be the committed
    /// leaf, so the account revealed a second draw beyond its single committed one.
    pub fn is_proven(&self) -> bool {
        self.first != self.second
            && self.first.position == self.slot
            && self.second.position == self.slot
            && (verify_membership(&self.root, self.slot, &self.first)
                || verify_membership(&self.root, self.slot, &self.second))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::SamplerValidator;

    #[test]
    fn an_honest_pair_of_reveals_is_not_a_fault() {
        let v = SamplerValidator::new(1, 100);
        let root = v.root();
        // The same slot revealed twice is the identical credential, no fault.
        let a = v.reveal(4);
        let b = v.reveal(4);
        let dd = DoubleDraw {
            root,
            slot: 4,
            first: a,
            second: b,
        };
        assert!(!dd.is_proven());
    }

    #[test]
    fn a_leaf_reused_at_another_slot_is_an_out_of_position_fault() {
        let v = SamplerValidator::new(1, 100);
        let root = v.root();
        // The genuine leaf for position 3, used at slot 7.
        let credential = v.reveal(3);
        let fault = OutOfPosition {
            root,
            credential,
            used_slot: 7,
        };
        assert!(fault.is_proven());
    }

    #[test]
    fn a_leaf_at_its_own_slot_is_not_an_out_of_position_fault() {
        let v = SamplerValidator::new(1, 100);
        let root = v.root();
        let credential = v.reveal(3);
        let fault = OutOfPosition {
            root,
            credential,
            used_slot: 3,
        };
        assert!(!fault.is_proven());
    }
}
