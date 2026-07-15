//! The one time key tree that backs the grinding resistant sortition of

use qtv_crypto::sha3::{sha3_256, shake256};

/// Length of a one time preimage, a leaf hash, an internal node, and a root.
pub const PREIMAGE_BYTES: usize = 32;

/// Length of a Merkle node digest.
pub const NODE_BYTES: usize = 32;

/// Domain tag folded into the SHAKE256 derivation of a slot preimage.
const DOMAIN_PREIMAGE: &[u8] = b"QORUS/onetime/preimage";

/// Domain tag folded into the SHA3-256 hash of a leaf, separating a leaf hash
const DOMAIN_LEAF: &[u8] = b"QORUS/onetime/leaf";

/// Domain tag folded into the SHA3-256 hash of an internal node.
const DOMAIN_NODE: &[u8] = b"QORUS/onetime/node";

/// The fixed preimage that fills padding leaves when the slot count is not a
const PADDING_PREIMAGE: [u8; PREIMAGE_BYTES] = [0u8; PREIMAGE_BYTES];

/// The committed root of an account's one time tree, bonded to its stake at
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Root {
    pub digest: [u8; NODE_BYTES],
    pub slots: u64,
}

impl Root {
    /// True when the preimage sits at the position in this registered root: the
    pub fn verify_membership(
        &self,
        position: u64,
        preimage: &[u8; PREIMAGE_BYTES],
        path: &MerklePath,
    ) -> bool {
        if position >= self.slots {
            return false;
        }
        if path.siblings.len() != tree_depth(self.slots) {
            return false;
        }
        let leaf = leaf_hash(preimage);
        root_from_path(position, &leaf, path) == self.digest
    }
}

/// A Merkle authentication path: the sibling digests from a leaf up to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub siblings: Vec<[u8; NODE_BYTES]>,
}

/// Derive the one time preimage for a slot position from an account secret seed.
pub fn derive_preimage(seed: &[u8; 32], position: u64) -> [u8; PREIMAGE_BYTES] {
    let mut input = Vec::with_capacity(32 + DOMAIN_PREIMAGE.len() + 8);
    input.extend_from_slice(seed);
    input.extend_from_slice(DOMAIN_PREIMAGE);
    input.extend_from_slice(&position.to_le_bytes());
    let mut out = [0u8; PREIMAGE_BYTES];
    shake256(&input, &mut out);
    out
}

/// The Merkle leaf that commits a preimage: SHA3-256 over a leaf domain tag and
pub fn leaf_hash(preimage: &[u8; PREIMAGE_BYTES]) -> [u8; NODE_BYTES] {
    let mut buf = Vec::with_capacity(DOMAIN_LEAF.len() + PREIMAGE_BYTES);
    buf.extend_from_slice(DOMAIN_LEAF);
    buf.extend_from_slice(preimage);
    sha3_256(&buf)
}

/// A Merkle internal node: SHA3-256 over a node domain tag and the two children,
pub fn node_hash(left: &[u8; NODE_BYTES], right: &[u8; NODE_BYTES]) -> [u8; NODE_BYTES] {
    let mut buf = Vec::with_capacity(DOMAIN_NODE.len() + 2 * NODE_BYTES);
    buf.extend_from_slice(DOMAIN_NODE);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    sha3_256(&buf)
}

/// The padded leaf count of a tree serving `slots` slots, the next power of two.
fn padded_leaves(slots: u64) -> usize {
    (slots as usize).max(1).next_power_of_two()
}

/// The depth of a tree serving `slots` slots, the length of every authentication
fn tree_depth(slots: u64) -> usize {
    padded_leaves(slots).trailing_zeros() as usize
}

/// Recompute the Merkle root from a leaf at a position and its authentication
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

/// An account's one time key tree. It holds the secret seed, the slot count, and
pub struct OneTimeTree {
    seed: [u8; 32],
    slots: u64,
    // layers[0] is the padded leaf layer; the last layer is the single root.
    layers: Vec<Vec<[u8; NODE_BYTES]>>,
}

impl OneTimeTree {
    /// Build the tree for an account from its secret seed over `slots` slots. The
    pub fn new(seed: [u8; 32], slots: u64) -> Self {
        assert!(slots >= 1, "a one time tree serves at least one slot");
        let padded = padded_leaves(slots);
        let padding = leaf_hash(&PADDING_PREIMAGE);
        let mut leaves = Vec::with_capacity(padded);
        for position in 0..padded as u64 {
            if position < slots {
                leaves.push(leaf_hash(&derive_preimage(&seed, position)));
            } else {
                leaves.push(padding);
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
            layers,
        }
    }

    /// The number of slots this tree serves.
    pub fn slots(&self) -> u64 {
        self.slots
    }

    /// The committed root, the value the account registers and bonds to its stake.
    pub fn root(&self) -> Root {
        Root {
            digest: self.layers.last().unwrap()[0],
            slots: self.slots,
        }
    }

    /// The one time preimage for a slot position. Panics on a position past the
    pub fn preimage(&self, position: u64) -> [u8; PREIMAGE_BYTES] {
        assert!(
            position < self.slots,
            "position past the committed slot count"
        );
        derive_preimage(&self.seed, position)
    }

    /// The authentication path from the leaf at a slot position up to the root.
    pub fn path(&self, position: u64) -> MerklePath {
        assert!(
            position < self.slots,
            "position past the committed slot count"
        );
        let mut siblings = Vec::with_capacity(self.layers.len() - 1);
        let mut idx = position as usize;
        for layer in &self.layers[..self.layers.len() - 1] {
            siblings.push(layer[idx ^ 1]);
            idx >>= 1;
        }
        MerklePath { siblings }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(seed_byte: u8, slots: u64) -> OneTimeTree {
        OneTimeTree::new([seed_byte; 32], slots)
    }

    #[test]
    fn a_revealed_preimage_verifies_at_its_position() {
        let t = tree(1, 16);
        let root = t.root();
        for position in 0..16 {
            let preimage = t.preimage(position);
            let path = t.path(position);
            assert!(root.verify_membership(position, &preimage, &path));
        }
    }

    #[test]
    fn a_preimage_at_another_position_is_rejected() {
        let t = tree(1, 16);
        let root = t.root();
        let preimage = t.preimage(3);
        let path = t.path(3);
        // The real leaf and path for position 3 do not authenticate at any other
        // position, since the path pairs siblings by the position bits.
        assert!(root.verify_membership(3, &preimage, &path));
        for other in 0..16 {
            if other != 3 {
                assert!(!root.verify_membership(other, &preimage, &path));
            }
        }
    }

    #[test]
    fn a_preimage_from_another_tree_is_rejected() {
        let a = tree(1, 16);
        let b = tree(2, 16);
        let preimage = a.preimage(5);
        let path = a.path(5);
        // Valid against its own root, rejected against a different account's root.
        assert!(a.root().verify_membership(5, &preimage, &path));
        assert!(!b.root().verify_membership(5, &preimage, &path));
    }

    #[test]
    fn a_position_past_the_slot_count_is_rejected() {
        let t = tree(1, 3);
        let root = t.root();
        // Positions 0..3 are real; the padded position 3 is not a slot.
        let preimage = t.preimage(0);
        let path = t.path(0);
        assert!(root.verify_membership(0, &preimage, &path));
        assert!(!root.verify_membership(3, &preimage, &path));
    }

    #[test]
    fn a_single_slot_tree_has_the_leaf_as_its_root() {
        let t = tree(1, 1);
        let root = t.root();
        let preimage = t.preimage(0);
        let path = t.path(0);
        assert!(path.siblings.is_empty());
        assert_eq!(root.digest, leaf_hash(&preimage));
        assert!(root.verify_membership(0, &preimage, &path));
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
        let preimage = t.preimage(2);
        let mut path = t.path(2);
        path.siblings.pop();
        assert!(!root.verify_membership(2, &preimage, &path));
    }
}
