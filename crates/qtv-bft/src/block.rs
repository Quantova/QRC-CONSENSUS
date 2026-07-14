//! A block decides one height. It carries its height, its payload value, the

use crate::params::VALIDATOR_RESOURCE_BUDGET;

pub type Height = u64;
pub type Value = u64;

/// The parent link of a block: the value of the previous finalized block, or
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Parent {
    Genesis,
    Value(Value),
}

/// A proposed block for one height.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Block {
    pub height: Height,
    pub val: Value,
    pub parent: Parent,
    pub cost: u64,
}

impl Block {
    /// A block that carries the unit cost, the honest cost in the model.
    pub fn new(height: Height, val: Value, parent: Parent) -> Self {
        Block {
            height,
            val,
            parent,
            cost: 1,
        }
    }

    /// A block with an explicit cost, used to model a block that exceeds the
    pub fn with_cost(height: Height, val: Value, parent: Parent, cost: u64) -> Self {
        Block {
            height,
            val,
            parent,
            cost,
        }
    }

    /// True when the block cost is within the resource budget. Mirrors
    pub fn within_budget(&self) -> bool {
        self.cost <= VALIDATOR_RESOURCE_BUDGET
    }

    /// Canonical byte encoding, the message an attestation signs and the input
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 * 4);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.val.to_le_bytes());
        match self.parent {
            Parent::Genesis => {
                out.push(0);
                out.extend_from_slice(&0u64.to_le_bytes());
            }
            Parent::Value(v) => {
                out.push(1);
                out.extend_from_slice(&v.to_le_bytes());
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
        let b = Block::new(1, 7, Parent::Genesis);
        assert!(b.within_budget());
    }

    #[test]
    fn over_budget_block_is_rejected() {
        let b = Block::with_cost(1, 7, Parent::Genesis, VALIDATOR_RESOURCE_BUDGET + 1);
        assert!(!b.within_budget());
    }

    #[test]
    fn encoding_separates_distinct_blocks() {
        let a = Block::new(1, 7, Parent::Genesis);
        let b = Block::new(1, 8, Parent::Genesis);
        let c = Block::new(2, 7, Parent::Value(7));
        assert_ne!(a.to_bytes(), b.to_bytes());
        assert_ne!(a.to_bytes(), c.to_bytes());
    }
}
