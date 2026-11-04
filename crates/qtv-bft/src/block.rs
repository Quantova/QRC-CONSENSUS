// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::params::VALIDATOR_RESOURCE_BUDGET;

pub type Height = u64;

pub type Value = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Parent {
    Genesis,
    Value(Value),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Block {
    pub height: Height,
    pub val: Value,
    pub parent: Parent,
    pub cost: u64,
}

impl Block {
    pub fn new(height: Height, val: Value, parent: Parent) -> Self {
        Block {
            height,
            val,
            parent,
            cost: 1,
        }
    }

    pub fn with_cost(height: Height, val: Value, parent: Parent, cost: u64) -> Self {
        Block {
            height,
            val,
            parent,
            cost,
        }
    }

    pub const VIEW_CHANGE_SUBJECT_COST: u64 = u64::MAX;

    pub fn within_budget(&self) -> bool {
        self.cost <= VALIDATOR_RESOURCE_BUDGET
    }

    pub fn is_view_change_subject(&self) -> bool {
        self.cost == Block::VIEW_CHANGE_SUBJECT_COST
    }

    pub fn is_admissible(&self) -> bool {
        self.within_budget() || self.is_view_change_subject()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 1 + 32 + 8);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.val);
        match self.parent {
            Parent::Genesis => {
                out.push(0);
                out.extend_from_slice(&[0u8; 32]);
            }
            Parent::Value(v) => {
                out.push(1);
                out.extend_from_slice(&v);
            }
        }
        out.extend_from_slice(&self.cost.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_cost_block_is_within_budget() {
        let b = Block::new(1, [7u8; 32], Parent::Genesis);
        assert!(b.within_budget());
    }

    #[test]
    fn over_budget_block_is_rejected() {
        let b = Block::with_cost(1, [7u8; 32], Parent::Genesis, VALIDATOR_RESOURCE_BUDGET + 1);
        assert!(!b.within_budget());
    }

    #[test]
    fn the_view_change_subject_is_admissible_but_not_a_real_block() {
        let s = Block::with_cost(
            1,
            [7u8; 32],
            Parent::Genesis,
            Block::VIEW_CHANGE_SUBJECT_COST,
        );
        assert!(s.is_view_change_subject());
        assert!(!s.within_budget());
        assert!(s.is_admissible());
    }

    #[test]
    fn a_real_block_is_admissible_and_is_not_a_subject() {
        let b = Block::new(1, [7u8; 32], Parent::Genesis);
        assert!(b.within_budget());
        assert!(!b.is_view_change_subject());
        assert!(b.is_admissible());
    }

    #[test]
    fn a_fake_out_of_budget_tag_is_not_admissible() {
        let fake = Block::with_cost(1, [7u8; 32], Parent::Genesis, VALIDATOR_RESOURCE_BUDGET + 1);
        assert!(!fake.within_budget());
        assert!(!fake.is_view_change_subject());
        assert!(!fake.is_admissible());
        let near = Block::with_cost(
            1,
            [7u8; 32],
            Parent::Genesis,
            Block::VIEW_CHANGE_SUBJECT_COST - 1,
        );
        assert!(!near.is_admissible());
    }

    #[test]
    fn encoding_separates_distinct_blocks() {
        let a = Block::new(1, [7u8; 32], Parent::Genesis);
        let b = Block::new(1, [8u8; 32], Parent::Genesis);
        let c = Block::new(2, [7u8; 32], Parent::Value([7u8; 32]));
        assert_ne!(a.to_bytes(), b.to_bytes());
        assert_ne!(a.to_bytes(), c.to_bytes());
    }
}
