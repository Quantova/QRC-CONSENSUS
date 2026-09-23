// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::sha3::{sha3_256, shake256};

pub const PREIMAGE_BYTES: usize = 32;

pub const NODE_BYTES: usize = 32;

pub const MAX_SLOTS: u64 = 1 << 16;

const DOMAIN_PREIMAGE: &[u8] = b"QORUS/onetime/preimage";

const DOMAIN_LEAF: &[u8] = b"QORUS/onetime/leaf";

const DOMAIN_NODE: &[u8] = b"QORUS/onetime/node";

const DOMAIN_ROOT: &[u8] = b"QORUS/onetime/root";

const PADDING_PREIMAGE: [u8; PREIMAGE_BYTES] = [0u8; PREIMAGE_BYTES];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Root {
    pub digest: [u8; NODE_BYTES],
    pub slots: u64,
}

impl Root {
    pub fn verify_membership(
        &self,
        holder: u64,
        position: u64,
        preimage: &[u8; PREIMAGE_BYTES],
        path: &MerklePath,
    ) -> bool {
        if position >= self.slots {
            return false;
        }
        let depth = match tree_depth(self.slots) {
            Some(depth) => depth,
            None => return false,
        };
        if path.siblings.len() != depth {
            return false;
        }
        let leaf = leaf_hash(position, preimage);
        bind_root(holder, self.slots, &root_from_path(position, &leaf, path)) == self.digest
    }
}

pub fn bind_root(holder: u64, slots: u64, inner: &[u8; NODE_BYTES]) -> [u8; NODE_BYTES] {
    const D: usize = DOMAIN_ROOT.len();
    let mut buf = [0u8; D + 8 + 8 + NODE_BYTES];
    buf[..D].copy_from_slice(DOMAIN_ROOT);
    buf[D..D + 8].copy_from_slice(&holder.to_le_bytes());
    buf[D + 8..D + 16].copy_from_slice(&slots.to_le_bytes());
    buf[D + 16..].copy_from_slice(inner);
    sha3_256(&buf)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub siblings: Vec<[u8; NODE_BYTES]>,
}

fn wipe(bytes: &mut [u8]) {
    for slot in bytes.iter_mut() {
        *slot = 0;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let _ = core::hint::black_box(bytes);
}

pub fn derive_preimage(seed: &[u8; 32], position: u64) -> [u8; PREIMAGE_BYTES] {
    const D: usize = DOMAIN_PREIMAGE.len();
    let mut input = [0u8; 32 + D + 8];
    input[..32].copy_from_slice(seed);
    input[32..32 + D].copy_from_slice(DOMAIN_PREIMAGE);
    input[32 + D..].copy_from_slice(&position.to_le_bytes());
    let mut out = [0u8; PREIMAGE_BYTES];
    shake256(&input, &mut out);
    wipe(&mut input);
    out
}

pub fn leaf_hash(position: u64, preimage: &[u8; PREIMAGE_BYTES]) -> [u8; NODE_BYTES] {
    const D: usize = DOMAIN_LEAF.len();
    let mut buf = [0u8; D + 8 + PREIMAGE_BYTES];
    buf[..D].copy_from_slice(DOMAIN_LEAF);
    buf[D..D + 8].copy_from_slice(&position.to_le_bytes());
    buf[D + 8..].copy_from_slice(preimage);
    sha3_256(&buf)
}

pub fn node_hash(left: &[u8; NODE_BYTES], right: &[u8; NODE_BYTES]) -> [u8; NODE_BYTES] {
    const D: usize = DOMAIN_NODE.len();
    let mut buf = [0u8; D + 2 * NODE_BYTES];
    buf[..D].copy_from_slice(DOMAIN_NODE);
    buf[D..D + NODE_BYTES].copy_from_slice(left);
    buf[D + NODE_BYTES..].copy_from_slice(right);
    sha3_256(&buf)
}

fn padded_leaves(slots: u64) -> Option<usize> {
    if slots == 0 || slots > MAX_SLOTS {
        return None;
    }
    usize::try_from(slots).ok()?.checked_next_power_of_two()
}

fn tree_depth(slots: u64) -> Option<usize> {
    Some(padded_leaves(slots)?.trailing_zeros() as usize)
}

fn root_from_path(
    mut position: u64,
    leaf: &[u8; NODE_BYTES],
    path: &MerklePath,
) -> [u8; NODE_BYTES] {
    let mut node = *leaf;
    for sib in &path.siblings {
        node = if position & 1 == 0 {
            node_hash(&node, sib)
        } else {
            node_hash(sib, &node)
        };
        position >>= 1;
    }
    node
}

pub struct OneTimeTree {
    seed: [u8; 32],
    slots: u64,
    holder: u64,
    layers: Vec<Vec<[u8; NODE_BYTES]>>,
}

impl Drop for OneTimeTree {
    fn drop(&mut self) {
        wipe(&mut self.seed);
    }
}

impl OneTimeTree {
    pub fn new(seed: [u8; 32], slots: u64, holder: u64) -> Self {
        assert!(slots >= 1, "a one time tree serves at least one slot");
        let padded =
            padded_leaves(slots).expect("a one time tree serves a representable slot count");
        let mut leaves = Vec::with_capacity(padded);
        for position in 0..padded as u64 {
            if position < slots {
                leaves.push(leaf_hash(position, &derive_preimage(&seed, position)));
            } else {
                leaves.push(leaf_hash(position, &PADDING_PREIMAGE));
            }
        }
        let mut layers = vec![leaves];
        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let mut next = Vec::with_capacity(prev.len() / 2);
            for pair in prev.chunks(2) {
                next.push(node_hash(&pair[0], &pair[1]));
            }
            layers.push(next);
        }
        OneTimeTree {
            seed,
            slots,
            holder,
            layers,
        }
    }

    pub fn holder(&self) -> u64 {
        self.holder
    }

    pub fn slots(&self) -> u64 {
        self.slots
    }

    pub fn root(&self) -> Root {
        Root {
            digest: bind_root(self.holder, self.slots, &self.layers.last().unwrap()[0]),
            slots: self.slots,
        }
    }

    pub fn preimage(&self, position: u64) -> Option<[u8; PREIMAGE_BYTES]> {
        if position >= self.slots {
            return None;
        }
        Some(derive_preimage(&self.seed, position))
    }

    pub fn path(&self, position: u64) -> Option<MerklePath> {
        if position >= self.slots {
            return None;
        }
        let mut siblings = Vec::with_capacity(self.layers.len() - 1);
        let mut idx = position as usize;
        for layer in &self.layers[..self.layers.len() - 1] {
            siblings.push(layer[idx ^ 1]);
            idx >>= 1;
        }
        Some(MerklePath { siblings })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOLDER: u64 = 7;

    fn tree(seed_byte: u8, slots: u64) -> OneTimeTree {
        OneTimeTree::new([seed_byte; 32], slots, HOLDER)
    }

    #[test]
    fn a_revealed_preimage_verifies_at_its_position() {
        let t = tree(1, 16);
        let root = t.root();
        for position in 0..16 {
            let preimage = t
                .preimage(position)
                .expect("the position is within the committed slots");
            let path = t
                .path(position)
                .expect("the position is within the committed slots");
            assert!(root.verify_membership(HOLDER, position, &preimage, &path));
        }
    }

    #[test]
    fn a_preimage_at_another_position_is_rejected() {
        let t = tree(1, 16);
        let root = t.root();
        let preimage = t
            .preimage(3)
            .expect("the position is within the committed slots");
        let path = t
            .path(3)
            .expect("the position is within the committed slots");
        assert!(root.verify_membership(HOLDER, 3, &preimage, &path));
        for other in 0..16 {
            if other != 3 {
                assert!(!root.verify_membership(HOLDER, other, &preimage, &path));
            }
        }
    }

    #[test]
    fn a_preimage_from_another_tree_is_rejected() {
        let a = tree(1, 16);
        let b = tree(2, 16);
        let preimage = a
            .preimage(5)
            .expect("the position is within the committed slots");
        let path = a
            .path(5)
            .expect("the position is within the committed slots");
        assert!(a.root().verify_membership(HOLDER, 5, &preimage, &path));
        assert!(!b.root().verify_membership(HOLDER, 5, &preimage, &path));
    }

    #[test]
    fn a_position_past_the_slot_count_is_rejected() {
        let t = tree(1, 3);
        let root = t.root();
        let preimage = t
            .preimage(0)
            .expect("the position is within the committed slots");
        let path = t
            .path(0)
            .expect("the position is within the committed slots");
        assert!(root.verify_membership(HOLDER, 0, &preimage, &path));
        assert!(!root.verify_membership(HOLDER, 3, &preimage, &path));
    }

    #[test]
    fn a_slot_count_past_the_power_of_two_ceiling_is_rejected_not_a_panic() {
        let root = Root {
            digest: [0u8; NODE_BYTES],
            slots: u64::MAX,
        };
        let preimage = [0u8; PREIMAGE_BYTES];
        let path = MerklePath {
            siblings: Vec::new(),
        };
        assert!(!root.verify_membership(HOLDER, 0, &preimage, &path));
    }

    #[test]
    fn a_single_slot_tree_has_the_leaf_as_its_root() {
        let t = tree(1, 1);
        let root = t.root();
        let preimage = t
            .preimage(0)
            .expect("the position is within the committed slots");
        let path = t
            .path(0)
            .expect("the position is within the committed slots");
        assert!(path.siblings.is_empty());
        assert_eq!(root.digest, bind_root(HOLDER, 1, &leaf_hash(0, &preimage)));
        assert!(root.verify_membership(HOLDER, 0, &preimage, &path));
        assert!(
            !root.verify_membership(HOLDER + 1, 0, &preimage, &path),
            "a root opens only under the holder it was built for"
        );
    }

    #[test]
    fn a_tree_built_for_one_holder_opens_for_no_other() {
        let mine = OneTimeTree::new([5u8; 32], 16, 11);
        let root = mine.root();
        let preimage = mine
            .preimage(4)
            .expect("the position is within the committed slots");
        let path = mine
            .path(4)
            .expect("the position is within the committed slots");
        assert!(root.verify_membership(11, 4, &preimage, &path));
        for other in [0u64, 10, 12, u64::MAX] {
            assert!(
                !root.verify_membership(other, 4, &preimage, &path),
                "a credential replayed under another id must not open"
            );
        }
        let theirs = OneTimeTree::new([5u8; 32], 16, 12);
        assert_ne!(
            mine.root().digest,
            theirs.root().digest,
            "the same seed under two ids commits to two different roots"
        );
    }

    #[test]
    fn the_root_is_deterministic_in_the_seed() {
        assert_eq!(tree(7, 32).root(), tree(7, 32).root());
        assert_ne!(tree(7, 32).root(), tree(8, 32).root());
    }

    #[test]
    fn a_wrong_length_path_is_rejected() {
        let t = tree(1, 16);
        let root = t.root();
        let preimage = t
            .preimage(2)
            .expect("the position is within the committed slots");
        let mut path = t
            .path(2)
            .expect("the position is within the committed slots");
        path.siblings.pop();
        assert!(!root.verify_membership(HOLDER, 2, &preimage, &path));
    }
}
