use qtv_crypto::sha3::shake256;

pub const SEED_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Beacon {
    seed: [u8; SEED_BYTES],
}

impl Beacon {
    pub fn genesis() -> Self {
        let mut seed = [0u8; SEED_BYTES];
        shake256(b"QORUS/beacon/genesis", &mut seed);
        Beacon { seed }
    }

    pub fn from_seed(seed: [u8; SEED_BYTES]) -> Self {
        Beacon { seed }
    }

    pub fn seed(&self) -> &[u8; SEED_BYTES] {
        &self.seed
    }

    pub fn advance(&self, cert_digest: &[u8; SEED_BYTES], height: u64) -> Beacon {
        let mut input = [0u8; SEED_BYTES + SEED_BYTES + 8];
        input[..SEED_BYTES].copy_from_slice(&self.seed);
        input[SEED_BYTES..2 * SEED_BYTES].copy_from_slice(cert_digest);
        input[2 * SEED_BYTES..].copy_from_slice(&height.to_le_bytes());
        let mut next = [0u8; SEED_BYTES];
        shake256(&input, &mut next);
        Beacon { seed: next }
    }

    pub fn sortition_input(&self, domain: &[u8], slot: u64) -> Vec<u8> {
        let mut input = Vec::with_capacity(SEED_BYTES + domain.len() + 8);
        input.extend_from_slice(&self.seed);
        input.extend_from_slice(domain);
        input.extend_from_slice(&slot.to_le_bytes());
        input
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{DOMAIN_COMMITTEE, DOMAIN_LEADER};

    #[test]
    fn genesis_is_fixed() {
        assert_eq!(Beacon::genesis(), Beacon::genesis());
    }

    #[test]
    fn advance_depends_on_digest_and_height() {
        let b = Beacon::genesis();
        let d1 = [1u8; SEED_BYTES];
        let d2 = [2u8; SEED_BYTES];
        assert_ne!(b.advance(&d1, 1), b.advance(&d2, 1));
        assert_ne!(b.advance(&d1, 1), b.advance(&d1, 2));
        assert_eq!(b.advance(&d1, 1), b.advance(&d1, 1));
    }

    #[test]
    fn advance_chains_from_the_previous_seed() {
        let d = [7u8; SEED_BYTES];
        let a = Beacon::genesis().advance(&d, 1);
        let b = Beacon::from_seed([9u8; SEED_BYTES]).advance(&d, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn sortition_input_separates_domains_and_slots() {
        let b = Beacon::genesis();
        assert_ne!(
            b.sortition_input(DOMAIN_COMMITTEE, 3),
            b.sortition_input(DOMAIN_LEADER, 3)
        );
        assert_ne!(
            b.sortition_input(DOMAIN_COMMITTEE, 3),
            b.sortition_input(DOMAIN_COMMITTEE, 4)
        );
    }
}
