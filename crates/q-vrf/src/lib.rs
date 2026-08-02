// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Q-VRF: a stateful hash based post quantum verifiable random function.
//!
//! The construction is the one time key Merkle tree that qtv-sampler already uses
//! for committee sortition, packaged behind the standard VRF interface of keygen,
//! eval, prove and verify. Its security rests only on SHA3-256 and SHAKE256, so it
//! stands under quantum adversaries with the usual halving of the preimage margin.
//!
//! The public key is a Merkle root that commits, before any public randomness is
//! drawn, to one leaf per position of the epoch. Each leaf hashes a per position
//! secret preimage derived from the signer seed. Evaluating the VRF at a position
//! returns the hash of that position's preimage. The proof is the preimage together
//! with its Merkle authentication path. Verification recomputes the leaf, folds the
//! path to the committed root and checks the output against the revealed preimage.
//!
//! This is the verifiable random function analog of the stateful hash based
//! signatures XMSS and LMS in NIST SP 800-208. It is one time per position and
//! bounded by the tree size fixed at keygen. A signer must never evaluate a
//! position twice and must build a fresh tree for each epoch. Within those rules it
//! is a legitimate post quantum VRF. It is not a stateless many time VRF and must
//! not be presented as one.

use qtv_crypto::sha3::sha3_256;

pub mod onetime;

use crate::onetime::{MerklePath, OneTimeTree, Root, NODE_BYTES, PREIMAGE_BYTES};

/// Length in bytes of a VRF output.
pub const OUTPUT_BYTES: usize = 32;

/// Domain separator for the output function. It keeps a VRF output distinct from a
/// committed leaf, a Merkle node and any other SHA3 image in the stack.
const DOMAIN_OUTPUT: &[u8] = b"QVRF/hash-vrf/v1/output";

/// A VRF output value.
pub type Output = [u8; OUTPUT_BYTES];

/// The public verification key. It carries the Merkle root digest that commits to
/// the epoch's leaves and the slot count that fixes the tree shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    root: Root,
}

impl PublicKey {
    /// Wrap a committed one time tree root as a public key.
    pub fn from_root(root: Root) -> Self {
        PublicKey { root }
    }

    /// The committed Merkle root digest, thirty two bytes.
    pub fn digest(&self) -> [u8; NODE_BYTES] {
        self.root.digest
    }

    /// The number of positions the key commits to for the epoch.
    pub fn slots(&self) -> u64 {
        self.root.slots
    }

    /// Depth of the authentication path, that is the base two logarithm of the
    /// padded leaf count.
    pub fn depth(&self) -> usize {
        let padded = (self.root.slots as usize).max(1).next_power_of_two();
        padded.trailing_zeros() as usize
    }

    /// Serialized size of the public key: the root digest plus the slot count.
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

/// The secret key: the one time Merkle tree over the epoch positions. Holding it
/// lets the signer evaluate and prove any position exactly once.
pub struct SecretKey {
    tree: OneTimeTree,
}

impl SecretKey {
    /// The public key committed by this secret tree.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_root(self.tree.root())
    }

    /// The number of positions this key serves.
    pub fn slots(&self) -> u64 {
        self.tree.slots()
    }

    /// Evaluate the VRF at a position and return the output value.
    ///
    /// The output is a deterministic function of the position's secret preimage, so
    /// it is fixed the moment the public key is committed. A signer must treat a
    /// position as one time and never evaluate it under two epochs.
    pub fn eval(&self, position: u64) -> Output {
        let preimage = self.tree.preimage(position);
        output_from_preimage(position, &preimage)
    }

    /// Produce the proof for a position: the revealed preimage and its Merkle
    /// authentication path to the committed root.
    pub fn prove(&self, position: u64) -> Proof {
        Proof {
            preimage: self.tree.preimage(position),
            path: self.tree.path(position),
        }
    }

    /// Evaluate and prove in one call, sharing the single preimage derivation.
    pub fn eval_and_prove(&self, position: u64) -> (Output, Proof) {
        let preimage = self.tree.preimage(position);
        let path = self.tree.path(position);
        let output = output_from_preimage(position, &preimage);
        (output, Proof { preimage, path })
    }
}

/// A VRF proof. The preimage is the position's revealed secret and the path is its
/// Merkle authentication path against the committed root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub preimage: [u8; PREIMAGE_BYTES],
    pub path: MerklePath,
}

impl Proof {
    /// Serialized size of the proof: the preimage plus one sibling digest per path
    /// level. This grows only with the base two logarithm of the epoch slot count.
    pub fn size_bytes(&self) -> usize {
        PREIMAGE_BYTES + self.path.siblings.len() * NODE_BYTES
    }
}

/// Generate a key pair. The seed is the signer secret. The slot count fixes how
/// many positions the epoch tree serves and therefore the proof length.
///
/// The returned public key is a binding commitment: once published, the signer can
/// no longer change any position's leaf without breaking the Merkle root, which is
/// what removes the ability to grind a fresh output after public randomness lands.
pub fn keygen(seed: [u8; 32], epoch_slots: u64) -> (SecretKey, PublicKey) {
    let tree = OneTimeTree::new(seed, epoch_slots);
    let pk = PublicKey::from_root(tree.root());
    (SecretKey { tree }, pk)
}

/// The output function. It maps a position and its preimage to the VRF output with
/// domain separation and position binding, so an output is one way in the secret
/// preimage and specific to its position.
pub fn output_from_preimage(position: u64, preimage: &[u8; PREIMAGE_BYTES]) -> Output {
    const D: usize = DOMAIN_OUTPUT.len();
    let mut buf = [0u8; D + 8 + PREIMAGE_BYTES];
    buf[..D].copy_from_slice(DOMAIN_OUTPUT);
    buf[D..D + 8].copy_from_slice(&position.to_le_bytes());
    buf[D + 8..].copy_from_slice(preimage);
    sha3_256(&buf)
}

/// Verify a VRF output and proof against a public key at a position.
///
/// It returns true only when the authentication path folds the committed leaf to
/// the public root at the given position and the output matches the one implied by
/// the revealed preimage. Both checks must pass, so a forged output, a swapped
/// preimage, a tampered path, a foreign key or a shifted position all fail.
pub fn verify(pk: &PublicKey, position: u64, output: &Output, proof: &Proof) -> bool {
    if !pk.root().verify_membership(position, &proof.preimage, &proof.path) {
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
