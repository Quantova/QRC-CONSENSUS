// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::sha3::sha3_256;

pub mod onetime;

use crate::onetime::{MerklePath, OneTimeTree, Root, NODE_BYTES, PREIMAGE_BYTES};

pub const OUTPUT_BYTES: usize = 32;

const DOMAIN_OUTPUT: &[u8] = b"QVRF/hash-vrf/v1/output";

pub type Output = [u8; OUTPUT_BYTES];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    root: Root,
}

impl PublicKey {
    pub fn from_root(root: Root) -> Self {
        PublicKey { root }
    }

    pub fn digest(&self) -> [u8; NODE_BYTES] {
        self.root.digest
    }

    pub fn slots(&self) -> u64 {
        self.root.slots
    }

    pub fn depth(&self) -> usize {
        (self.root.slots as usize)
            .max(1)
            .checked_next_power_of_two()
            .map(|padded| padded.trailing_zeros() as usize)
            .unwrap_or(0)
    }

    pub fn size_bytes(&self) -> usize {
        NODE_BYTES + 8
    }

    pub fn root(&self) -> Root {
        self.root
    }

    pub fn opens(&self, position: u64, preimage: &[u8; PREIMAGE_BYTES], path: &MerklePath) -> bool {
        self.root.verify_membership(position, preimage, path)
    }
}

pub struct SecretKey {
    tree: OneTimeTree,
}

impl SecretKey {
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_root(self.tree.root())
    }

    pub fn slots(&self) -> u64 {
        self.tree.slots()
    }

    pub fn eval(&self, position: u64) -> Output {
        let preimage = self.tree.preimage(position);
        output_from_preimage(position, &preimage)
    }

    pub fn prove(&self, position: u64) -> Proof {
        Proof {
            preimage: self.tree.preimage(position),
            path: self.tree.path(position),
        }
    }

    pub fn eval_and_prove(&self, position: u64) -> (Output, Proof) {
        let preimage = self.tree.preimage(position);
        let path = self.tree.path(position);
        let output = output_from_preimage(position, &preimage);
        (output, Proof { preimage, path })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub preimage: [u8; PREIMAGE_BYTES],
    pub path: MerklePath,
}

impl Proof {
    pub fn size_bytes(&self) -> usize {
        PREIMAGE_BYTES + self.path.siblings.len() * NODE_BYTES
    }
}

pub fn keygen(seed: [u8; 32], epoch_slots: u64) -> (SecretKey, PublicKey) {
    let tree = OneTimeTree::new(seed, epoch_slots);
    let pk = PublicKey::from_root(tree.root());
    (SecretKey { tree }, pk)
}

pub fn output_from_preimage(position: u64, preimage: &[u8; PREIMAGE_BYTES]) -> Output {
    const D: usize = DOMAIN_OUTPUT.len();
    let mut buf = [0u8; D + 8 + PREIMAGE_BYTES];
    buf[..D].copy_from_slice(DOMAIN_OUTPUT);
    buf[D..D + 8].copy_from_slice(&position.to_le_bytes());
    buf[D + 8..].copy_from_slice(preimage);
    sha3_256(&buf)
}

pub fn verify(pk: &PublicKey, position: u64, output: &Output, proof: &Proof) -> bool {
    if !pk
        .root()
        .verify_membership(position, &proof.preimage, &proof.path)
    {
        return false;
    }
    output_from_preimage(position, &proof.preimage) == *output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_eval_prove_verify_round_trip() {
        let (sk, pk) = keygen([3u8; 32], 64);
        for position in 0..64 {
            let (y, proof) = sk.eval_and_prove(position);
            assert!(verify(&pk, position, &y, &proof));
            assert_eq!(sk.eval(position), y);
        }
    }

    #[test]
    fn eval_is_deterministic_in_the_key() {
        let (sk_a, _) = keygen([9u8; 32], 32);
        let (sk_b, _) = keygen([9u8; 32], 32);
        for position in 0..32 {
            assert_eq!(sk_a.eval(position), sk_b.eval(position));
        }
    }

    #[test]
    fn a_different_seed_gives_a_different_key_and_output() {
        let (sk_a, pk_a) = keygen([1u8; 32], 32);
        let (_, pk_b) = keygen([2u8; 32], 32);
        assert_ne!(pk_a, pk_b);
        let (sk_c, _) = keygen([2u8; 32], 32);
        assert_ne!(sk_a.eval(5), sk_c.eval(5));
    }
}
