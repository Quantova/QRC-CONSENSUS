// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::sha3::shake256;

pub fn digest_256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    shake256(data, &mut out);
    out
}

pub fn score(seed: &[u8; 32], id: u64) -> [u8; 32] {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(seed);
    buf[32..].copy_from_slice(&id.to_le_bytes());
    digest_256(&buf)
}

pub fn fold(seed: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + bytes.len());
    buf.extend_from_slice(seed);
    buf.extend_from_slice(bytes);
    digest_256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_deterministic() {
        assert_eq!(digest_256(b"qorus"), digest_256(b"qorus"));
        assert_ne!(digest_256(b"qorus"), digest_256(b"qorum"));
    }

    #[test]
    fn score_spreads_over_ids() {
        let seed = [42u8; 32];
        assert_ne!(score(&seed, 1), score(&seed, 2));
        assert_ne!(score(&[1u8; 32], 1), score(&[2u8; 32], 1));
    }

    #[test]
    fn fold_depends_on_seed_and_bytes() {
        assert_ne!(fold(&[1u8; 32], b"x"), fold(&[2u8; 32], b"x"));
        assert_ne!(fold(&[1u8; 32], b"x"), fold(&[1u8; 32], b"y"));
    }
}
