//! Deterministic hashing for committee sampling and the beacon. Built on

use qtv_crypto::sha3::shake256;

/// Squeeze a 64 bit value from SHAKE256 over the input.
pub fn digest_u64(data: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    shake256(data, &mut out);
    u64::from_le_bytes(out)
}

/// Score a validator against a seed, used to sample the committee. A validator
pub fn score(seed: u64, id: u64) -> u64 {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&seed.to_le_bytes());
    buf[8..].copy_from_slice(&id.to_le_bytes());
    digest_u64(&buf)
}

/// Fold a seed and a byte string into the next 64 bit seed. The beacon of one
pub fn fold(seed: u64, bytes: &[u8]) -> u64 {
    let mut buf = Vec::with_capacity(8 + bytes.len());
    buf.extend_from_slice(&seed.to_le_bytes());
    buf.extend_from_slice(bytes);
    digest_u64(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_deterministic() {
        assert_eq!(digest_u64(b"qorus"), digest_u64(b"qorus"));
        assert_ne!(digest_u64(b"qorus"), digest_u64(b"qorum"));
    }

    #[test]
    fn score_spreads_over_ids() {
        let a = score(42, 1);
        let b = score(42, 2);
        assert_ne!(a, b);
        assert_ne!(score(1, 1), score(2, 1));
    }

    #[test]
    fn fold_depends_on_seed_and_bytes() {
        assert_ne!(fold(1, b"x"), fold(2, b"x"));
        assert_ne!(fold(1, b"x"), fold(1, b"y"));
    }
}
