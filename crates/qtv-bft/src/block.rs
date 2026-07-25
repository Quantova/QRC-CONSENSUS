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

    pub fn within_budget(&self) -> bool {
        self.cost <= VALIDATOR_RESOURCE_BUDGET
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
    fn encoding_separates_distinct_blocks() {
        let a = Block::new(1, [7u8; 32], Parent::Genesis);
        let b = Block::new(1, [8u8; 32], Parent::Genesis);
        let c = Block::new(2, [7u8; 32], Parent::Value([7u8; 32]));
        assert_ne!(a.to_bytes(), b.to_bytes());
        assert_ne!(a.to_bytes(), c.to_bytes());
    }
}
