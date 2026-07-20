//! The folding committee certificate. Committee attestations fold up a binary tree that carries

use qtv_crypto::sha3::sha3_256;

/// Domain tag for an internal fold node, so a fold hash can never collide with any other hash.
const NODE_DOMAIN: &[u8] = b"QORUS/fold/node";

/// Hash two children into their parent, binding each child's hash and its cumulative stake, so the
pub fn node_hash(left: &[u8; 32], right: &[u8; 32], left_stake: u64, right_stake: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(NODE_DOMAIN.len() + 64 + 16);
    buf.extend_from_slice(NODE_DOMAIN);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    buf.extend_from_slice(&left_stake.to_le_bytes());
    buf.extend_from_slice(&right_stake.to_le_bytes());
    sha3_256(&buf)
}

/// One step of an opening's path from a leaf toward the root. A sibling is a real neighbour to hash
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Sibling {
        hash: [u8; 32],
        stake: u64,
        /// True when the sibling is on the left, so the node hashes as (sibling, self).
        on_left: bool,
    },
    Carry,
}

/// The authentication of one sampled member: its leaf position, its leaf hash and stake, and the path
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub index: usize,
    pub leaf: [u8; 32],
    pub stake: u64,
    pub path: Vec<Step>,
}

impl Opening {
    /// Recompute the root this opening implies by folding the leaf up its path. A verifier compares
    pub fn recompute_root(&self) -> [u8; 32] {
        let mut hash = self.leaf;
        let mut stake = self.stake;
        for step in &self.path {
            match step {
                Step::Sibling {
                    hash: sib,
                    stake: sib_stake,
                    on_left,
                } => {
                    hash = if *on_left {
                        node_hash(sib, &hash, *sib_stake, stake)
                    } else {
                        node_hash(&hash, sib, stake, *sib_stake)
                    };
                    stake = stake.saturating_add(*sib_stake);
                }
                Step::Carry => {}
            }
        }
        hash
    }
}

/// A folding committee certificate: the fold root, the attested stake it carries, the total committee
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldCertificate {
    pub root: [u8; 32],
    pub attested_stake: u64,
    pub total_stake: u64,
    pub openings: Vec<Opening>,
}

/// Build every level of the fold tree from the leaves up. Level zero is the leaves; each higher level
fn build_levels(leaves: &[([u8; 32], u64)]) -> Vec<Vec<([u8; 32], u64)>> {
    let mut levels = vec![leaves.to_vec()];
    while levels.last().map(|l| l.len()).unwrap_or(0) > 1 {
        let current = levels.last().expect("a level exists");
        let mut up = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                let (l, ls) = current[i];
                let (r, rs) = current[i + 1];
                up.push((node_hash(&l, &r, ls, rs), ls.saturating_add(rs)));
                i += 2;
            } else {
                up.push(current[i]);
                i += 1;
            }
        }
        levels.push(up);
    }
    levels
}

/// The path of steps from a leaf index up to the root, over the built levels.
fn opening_path(levels: &[Vec<([u8; 32], u64)>], mut index: usize) -> Vec<Step> {
    let mut path = Vec::new();
    for level in &levels[..levels.len().saturating_sub(1)] {
        if index % 2 == 0 {
            if index + 1 < level.len() {
                let (hash, stake) = level[index + 1];
                path.push(Step::Sibling {
                    hash,
                    stake,
                    on_left: false,
                });
            } else {
                path.push(Step::Carry);
            }
        } else {
            let (hash, stake) = level[index - 1];
            path.push(Step::Sibling {
                hash,
                stake,
                on_left: true,
            });
        }
        index /= 2;
    }
    path
}

/// The fold root and total attested stake over a set of leaves, each a leaf hash and its stake.
pub fn fold_root(leaves: &[([u8; 32], u64)]) -> ([u8; 32], u64) {
    let levels = build_levels(leaves);
    levels
        .last()
        .and_then(|top| top.first())
        .copied()
        .unwrap_or(([0u8; 32], 0))
}

/// Build a certificate over the attesting leaves and the whole committee stake, opening the members at
pub fn build(
    leaves: &[([u8; 32], u64)],
    total_stake: u64,
    sample: &[usize],
) -> FoldCertificate {
    let levels = build_levels(leaves);
    let (root, attested_stake) = levels
        .last()
        .and_then(|top| top.first())
        .copied()
        .unwrap_or(([0u8; 32], 0));
    let openings = sample
        .iter()
        .filter(|&&i| i < leaves.len())
        .map(|&i| {
            let (leaf, stake) = leaves[i];
            Opening {
                index: i,
                leaf,
                stake,
                path: opening_path(&levels, i),
            }
        })
        .collect();
    FoldCertificate {
        root,
        attested_stake,
        total_stake,
        openings,
    }
}

/// Whether the attested stake is a two thirds supermajority of the committee stake, the quorum the
pub fn meets_quorum(cert: &FoldCertificate) -> bool {
    (cert.attested_stake as u128) * 3 > (cert.total_stake as u128) * 2
}

/// Verify the certificate against the known committee total and the required sample size. Every opening
pub fn verify(cert: &FoldCertificate, committee_total: u64, sample_size: usize) -> bool {
    if cert.total_stake != committee_total {
        return false;
    }
    if cert.openings.len() != sample_size {
        return false;
    }
    if !meets_quorum(cert) {
        return false;
    }
    cert.openings
        .iter()
        .all(|opening| opening.recompute_root() == cert.root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(seed: u8) -> [u8; 32] {
        sha3_256(&[seed])
    }

    fn committee(n: usize) -> Vec<([u8; 32], u64)> {
        (0..n).map(|i| (leaf(i as u8), 1 + (i as u64 % 5))).collect()
    }

    fn total(leaves: &[([u8; 32], u64)]) -> u64 {
        leaves.iter().map(|(_, s)| s).sum()
    }

    #[test]
    fn the_root_is_deterministic_and_binds_the_stakes() {
        let leaves = committee(9);
        let (root_a, stake_a) = fold_root(&leaves);
        let (root_b, stake_b) = fold_root(&leaves);
        assert_eq!(root_a, root_b);
        assert_eq!(stake_a, total(&leaves));
        assert_eq!(stake_a, stake_b);

        // Changing one member's stake changes the root, so the root commits to stakes, not only leaves.
        let mut tampered = leaves.clone();
        tampered[3].1 += 1;
        assert_ne!(fold_root(&tampered).0, root_a);
    }

    #[test]
    fn every_opening_recomputes_the_root_across_sizes() {
        // Includes odd sizes and a power of two, so the carry path is exercised.
        for n in [1usize, 2, 3, 5, 8, 13, 16, 31] {
            let leaves = committee(n);
            let (root, _) = fold_root(&leaves);
            let sample: Vec<usize> = (0..n).collect();
            let cert = build(&leaves, total(&leaves), &sample);
            assert_eq!(cert.root, root);
            for opening in &cert.openings {
                assert_eq!(
                    opening.recompute_root(),
                    root,
                    "opening {} of {} must land on the root",
                    opening.index,
                    n
                );
            }
        }
    }

    #[test]
    fn a_tampered_opening_is_rejected() {
        let leaves = committee(11);
        let sample: Vec<usize> = (0..11).collect();
        let cert = build(&leaves, total(&leaves), &sample);

        // A flipped leaf no longer folds to the root.
        let mut bad_leaf = cert.clone();
        bad_leaf.openings[4].leaf[0] ^= 1;
        assert!(!verify(&bad_leaf, total(&leaves), 11));

        // A lied about sibling stake no longer folds to the root.
        let mut bad_stake = cert.clone();
        if let Step::Sibling { stake, .. } = &mut bad_stake.openings[4].path[0] {
            *stake += 1;
        }
        assert!(!verify(&bad_stake, total(&leaves), 11));

        // The honest certificate verifies.
        assert!(verify(&cert, total(&leaves), 11));
    }

    #[test]
    fn quorum_and_totals_are_enforced() {
        let leaves = committee(12);
        let full = total(&leaves);
        let sample: Vec<usize> = (0..12).collect();

        // A certificate over the whole committee meets quorum.
        let cert = build(&leaves, full, &sample);
        assert!(verify(&cert, full, 12));

        // The same fold claiming a larger committee than actually staked fails the total check.
        assert!(!verify(&cert, full + 1, 12));

        // A fold over a bare majority by stake, not two thirds, fails quorum. Take a subset whose
        // stake is over half but under two thirds of the full committee.
        let mut running = 0u64;
        let mut minority = Vec::new();
        for (i, (_, s)) in leaves.iter().enumerate() {
            if (running + s) as u128 * 3 <= full as u128 * 2 {
                running += s;
                minority.push(i);
            }
            if running as u128 * 2 > full as u128 {
                break;
            }
        }
        let sub_leaves: Vec<([u8; 32], u64)> = minority.iter().map(|&i| leaves[i]).collect();
        let sub_sample: Vec<usize> = (0..sub_leaves.len()).collect();
        let sub = build(&sub_leaves, full, &sub_sample);
        assert!(sub.attested_stake * 2 > full, "the subset is a majority");
        assert!(!meets_quorum(&sub), "but not a two thirds supermajority");
        assert!(!verify(&sub, full, sub_leaves.len()));
    }

    #[test]
    fn a_wrong_sample_size_is_rejected() {
        let leaves = committee(10);
        let full = total(&leaves);
        let cert = build(&leaves, full, &[0, 2, 4]);
        assert!(verify(&cert, full, 3));
        assert!(!verify(&cert, full, 4), "a certificate must carry the expected sample count");
    }
}
