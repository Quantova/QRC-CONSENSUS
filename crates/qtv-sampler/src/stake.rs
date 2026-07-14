//! Stake weight for sortition. Only native QTOV secures consensus. An origin
//! tagged bridged asset is second class by protocol law and is never valid as
//! validator stake, so a fault on a foreign chain can never reach consensus.
//! A bridged holding therefore contributes zero weight and is rejected.

/// The origin of a held asset. A bridged asset is identified by the pair of
/// origin chain and origin asset, never by symbol alone, so the same symbol on
/// two chains is two distinct origin tagged kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginTag {
    pub chain: u32,
    pub asset: u32,
}

/// The origin of a staked asset. Only the native asset counts toward stake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetOrigin {
    /// The native QTOV asset, the only asset that secures consensus.
    Native,
    /// An origin tagged bridged asset, never valid as validator stake.
    Bridged(OriginTag),
}

/// A holding a validator offers as stake: an amount and the origin of the asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stake {
    pub amount: u64,
    pub origin: AssetOrigin,
}

impl Stake {
    /// A native stake of the given amount.
    pub fn native(amount: u64) -> Self {
        Stake {
            amount,
            origin: AssetOrigin::Native,
        }
    }

    /// A bridged holding, which is never valid as stake.
    pub fn bridged(amount: u64, tag: OriginTag) -> Self {
        Stake {
            amount,
            origin: AssetOrigin::Bridged(tag),
        }
    }

    /// True only when the origin is native. A bridged asset is rejected.
    pub fn is_valid(&self) -> bool {
        matches!(self.origin, AssetOrigin::Native)
    }

    /// The weight this holding contributes. A bridged asset contributes zero
    /// however large its amount, since only native stake counts.
    pub fn weight(&self) -> u64 {
        match self.origin {
            AssetOrigin::Native => self.amount,
            AssetOrigin::Bridged(_) => 0,
        }
    }
}

/// Total native weight of a set of holdings. Bridged holdings are skipped.
pub fn total_weight(stakes: &[Stake]) -> u64 {
    stakes.iter().map(Stake::weight).sum()
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
