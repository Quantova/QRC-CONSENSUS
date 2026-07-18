//! Equivocation detection. A validator that attests two different blocks at one

use crate::attest::Attestation;
use crate::validator::ValidatorId;

/// True when two attestations are a double signing: same validator, same
pub fn is_equivocation(a: &Attestation, b: &Attestation) -> bool {
    a.from == b.from && a.height == b.height && a.block != b.block
}

/// The validators that double signed at some height, in ascending order. This
pub fn equivocators(attestations: &[Attestation]) -> Vec<ValidatorId> {
    let mut flagged: Vec<ValidatorId> = Vec::new();
    for (i, a) in attestations.iter().enumerate() {
        for b in &attestations[i + 1..] {
            if is_equivocation(a, b) && !flagged.contains(&a.from) {
                flagged.push(a.from);
            }
        }
    }
    flagged.sort_unstable();
    flagged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, Parent};
    use crate::validator::Validator;

    fn att(v: &Validator, height: u64, val: [u8; 32]) -> Attestation {
        Attestation::create(v, height, Block::new(height, val, Parent::Genesis))
    }

    #[test]
    fn double_signing_at_one_height_is_flagged() {
        let v = Validator::new(2);
        let atts = vec![att(&v, 1, [1u8; 32]), att(&v, 1, [2u8; 32])];
        assert_eq!(equivocators(&atts), vec![2]);
    }

    #[test]
    fn a_single_vote_per_height_is_never_flagged() {
        let a = Validator::new(1);
        let b = Validator::new(2);
        let atts = vec![att(&a, 1, [1u8; 32]), att(&b, 1, [1u8; 32]), att(&a, 2, [5u8; 32])];
        assert!(equivocators(&atts).is_empty());
    }

    #[test]
    fn different_heights_are_not_equivocation() {
        let v = Validator::new(3);
        let atts = vec![att(&v, 1, [1u8; 32]), att(&v, 2, [2u8; 32])];
        assert!(equivocators(&atts).is_empty());
    }

    #[test]
    fn no_attestations_means_no_equivocators() {
        assert!(equivocators(&[]).is_empty());
    }
}
