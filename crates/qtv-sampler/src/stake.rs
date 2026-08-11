// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginTag {
    pub chain: u32,
    pub asset: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetOrigin {
    Native,
    Bridged(OriginTag),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stake {
    pub amount: u64,
    pub origin: AssetOrigin,
}

impl Stake {
    pub fn native(amount: u64) -> Self {
        Stake {
            amount,
            origin: AssetOrigin::Native,
        }
    }

    pub fn bridged(amount: u64, tag: OriginTag) -> Self {
        Stake {
            amount,
            origin: AssetOrigin::Bridged(tag),
        }
    }

    pub fn is_valid(&self) -> bool {
        matches!(self.origin, AssetOrigin::Native)
    }

    pub fn weight(&self) -> u64 {
        match self.origin {
            AssetOrigin::Native => self.amount,
            AssetOrigin::Bridged(_) => 0,
        }
    }
}

pub fn total_weight(stakes: &[Stake]) -> u64 {
    stakes.iter().map(Stake::weight).fold(0u64, u64::saturating_add)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: OriginTag = OriginTag { chain: 1, asset: 2 };

    #[test]
    fn native_stake_carries_its_amount() {
        let s = Stake::native(2_000);
        assert!(s.is_valid());
        assert_eq!(s.weight(), 2_000);
    }

    #[test]
    fn bridged_stake_is_rejected_and_weightless() {
        let s = Stake::bridged(1_000_000, TAG);
        assert!(!s.is_valid());
        assert_eq!(s.weight(), 0);
    }

    #[test]
    fn total_weight_counts_native_only() {
        let stakes = [
            Stake::native(100),
            Stake::bridged(9_999, TAG),
            Stake::native(50),
        ];
        assert_eq!(total_weight(&stakes), 150);
    }
}
