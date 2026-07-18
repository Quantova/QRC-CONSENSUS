//! A block decides one height. It carries its height, its payload value, the
//! value of the block it descends from, and a cost measured against the
//! resource budget. Mirrors the block records of the formal model, where a
//! block is [height, val, parent] and a parent is either a value or Genesis.

use crate::params::VALIDATOR_RESOURCE_BUDGET;

pub type Height = u64;

/// A block value is a full 256-bit digest, the block header hash itself, not a
/// short fold of it. Attestations and the finality certificate sign over this
/// value, so it must be the full width, or a collision at that width lets a
/// certificate for one header be replayed onto another. Widening from a 64-bit
/// fold to the 32-byte header hash makes forging a certificate a full SHA3-256
/// collision rather than a birthday grind over a short handle.
pub type Value = [u8; 32];

/// The parent link of a block: the value of the previous finalized block, or
/// the Genesis tag at the first height. Mirrors Parents == Vals \cup {Genesis}.
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
    /// resource budget and is therefore unattestable.
    pub fn with_cost(height: Height, val: Value, parent: Parent, cost: u64) -> Self {
        Block {
            height,
            val,
            parent,
            cost,
        }
    }

    /// True when the block cost is within the resource budget. Mirrors
    /// WithinBudget(b) == Cost(b) <= ResourceBound.
    pub fn within_budget(&self) -> bool {
        self.cost <= VALIDATOR_RESOURCE_BUDGET
    }

    /// Canonical byte encoding, the message an attestation signs and the input
    /// the beacon mixes. Deterministic and unambiguous across the fields.
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
