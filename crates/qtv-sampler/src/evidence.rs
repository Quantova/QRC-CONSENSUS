//! Attributable sortition faults and the checks any node runs on them. The one

use crate::onetime::Root;
use crate::sortition::{verify_membership, Credential};

/// Evidence that an account revealed a committed one time leaf out of its
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutOfPosition {
    pub root: Root,
    /// A credential whose preimage genuinely sits at position `credential.position`
    pub credential: Credential,
    /// The slot the credential was submitted for.
    pub used_slot: u64,
}

impl OutOfPosition {
    /// True when the fault is proven: the preimage authenticates to the root at
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoubleDraw {
    pub root: Root,
    pub slot: u64,
    pub first: Credential,
    pub second: Credential,
}

impl DoubleDraw {
    /// True when the fault is proven: two distinct credentials, both put forward
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
