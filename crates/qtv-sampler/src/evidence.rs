// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::onetime::Root;
use crate::sortition::{verify_membership, Credential};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DoubleDraw {
    pub root: Root,
    pub holder: u64,
    pub slot: u64,
    pub first: Credential,
    pub second: Credential,
}

impl DoubleDraw {
    pub fn is_proven(&self) -> bool {
        self.first != self.second
            && self.first.position == self.slot
            && self.second.position == self.slot
            && verify_membership(&self.root, self.holder, self.slot, &self.first)
            && verify_membership(&self.root, self.holder, self.slot, &self.second)
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
        let a = v
            .reveal(4)
            .expect("the position is within the committed slots");
        let b = v
            .reveal(4)
            .expect("the position is within the committed slots");
        let dd = DoubleDraw {
            root,
            holder: v.id,
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

        let genuine = v
            .reveal(slot)
            .expect("the position is within the committed slots");
        let mut fabricated = v
            .reveal(slot)
            .expect("the position is within the committed slots");
        fabricated.preimage = v
            .reveal(9)
            .expect("the position is within the committed slots")
            .preimage;
        assert_ne!(genuine, fabricated);

        let dd = DoubleDraw {
            root,
            holder: v.id,
            slot,
            first: genuine.clone(),
            second: fabricated.clone(),
        };
        assert!(!dd.is_proven());

        let swapped = DoubleDraw {
            root,
            holder: v.id,
            slot,
            first: fabricated,
            second: genuine,
        };
        assert!(!swapped.is_proven());
    }
}
