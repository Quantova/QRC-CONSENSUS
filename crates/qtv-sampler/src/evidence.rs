// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::onetime::Root;
use crate::sortition::{verify_membership, Credential};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutOfPosition {
    pub root: Root,
    pub credential: Credential,
    pub used_slot: u64,
}

impl OutOfPosition {
    pub fn is_proven(&self) -> bool {
        self.used_slot != self.credential.position
            && self.root.verify_membership(
                self.credential.position,
                &self.credential.preimage,
                &self.credential.path,
            )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoubleDraw {
    pub root: Root,
    pub slot: u64,
    pub first: Credential,
    pub second: Credential,
}

impl DoubleDraw {
    pub fn is_proven(&self) -> bool {
        self.first != self.second
            && self.first.position == self.slot
            && self.second.position == self.slot
            && verify_membership(&self.root, self.slot, &self.first)
            && verify_membership(&self.root, self.slot, &self.second)
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
    fn a_genuine_reveal_paired_with_fabricated_bytes_is_not_a_fault() {
        let v = SamplerValidator::new(1, 100);
        let root = v.root();
        let slot = 4;

        let genuine = v.reveal(slot);
        let mut fabricated = v.reveal(slot);
        fabricated.preimage = v.reveal(9).preimage;
        assert_ne!(genuine, fabricated);

        let dd = DoubleDraw {
            root,
            slot,
            first: genuine.clone(),
            second: fabricated.clone(),
        };
        assert!(!dd.is_proven());

        let swapped = DoubleDraw {
            root,
            slot,
            first: fabricated,
            second: genuine,
        };
        assert!(!swapped.is_proven());
    }

    #[test]
    fn a_leaf_reused_at_another_slot_is_an_out_of_position_fault() {
        let v = SamplerValidator::new(1, 100);
        let root = v.root();
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
