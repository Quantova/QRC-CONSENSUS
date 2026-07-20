//! The folding committee certificate. Committee attestations fold up a binary tree that carries
//! cumulative stake into one constant sized core, the root hash and the attested stake. Each internal
//! node hashes its two children together with their stakes, so the root commits to the whole tree and
//! its stakes at once. Agreement cost does not grow with the set, since each node checks only its two
//! children and an outsider checks only a fixed sample.
//!
//! An outsider verifies by sampling a fixed number of members. For each sampled member the certificate
//! carries an opening, the member's leaf and stake and the authentication path of siblings up to the
//! root. The verifier recomputes that path and checks it lands on the committed root, which proves the
//! member is genuinely in the tree that produced the attested stake. The unsampled members are backed
//! by the stake behind them, a false fold is slashable, so the sample plus staking stands in for
//! checking every member. This closes the gap the prototype left, where the sample proved a member
//! existed but never tied it back to the root.
//!
//! The tree is hash based and quantum safe on hash security alone, and it carries no classical or non
//! finalised cryptography.

use qtv_crypto::sha3::sha3_256;

/// Domain tag for an internal fold node, so a fold hash can never collide with any other hash.
const NODE_DOMAIN: &[u8] = b"QORUS/fold/node";

/// Hash two children into their parent, binding each child's hash and its cumulative stake, so the
/// parent commits to the subtree stakes and not only the leaves.
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
/// against; a carry is a level where the node had no pair and rose unchanged, which happens whenever a
/// level holds an odd number of nodes.
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
/// of steps up to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub index: usize,
    pub leaf: [u8; 32],
    pub stake: u64,
    pub path: Vec<Step>,
}

impl Opening {
    /// Fold the leaf up its path, returning both the root hash it implies and the total stake it
    /// accumulates. A verifier compares the hash against the certificate root, a match proves the leaf
    /// is in that exact tree. The accumulated stake is the whole tree's stake, since the siblings along
    /// a path partition every other leaf, so it also lets the verifier bind the certificate's attested
    /// stake to the fold rather than trusting it as a free number.
    pub fn fold_to_root(&self) -> ([u8; 32], u64) {
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
        (hash, stake)
    }
}

/// A folding committee certificate: the fold root, the attested stake it carries, the total committee
/// stake, and a sample of openings. The root and the two stake figures are the constant sized core;
/// the openings are a fixed sample and do not grow with the committee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldCertificate {
    pub root: [u8; 32],
    pub attested_stake: u64,
    pub total_stake: u64,
    pub openings: Vec<Opening>,
}

/// Build every level of the fold tree from the leaves up. Level zero is the leaves; each higher level
/// folds adjacent pairs and carries a trailing odd node unchanged. The last level holds the single
/// root pair.
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
/// the given sample indices. The attested stake is the fold root's stake, the sum of the leaves.
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
/// certificate must clear to finalise.
pub fn meets_quorum(cert: &FoldCertificate) -> bool {
    (cert.attested_stake as u128) * 3 > (cert.total_stake as u128) * 2
}

/// Verify the certificate against the known committee total and the required sample size. Every opening
/// must recompute to the committed root, the committed total must match the committee, and the attested
/// stake must clear the two thirds quorum. Membership and the block binding of each sampled leaf are
/// checked by the caller against the committee commitment; this fixes the fold and the count.
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
    cert.openings.iter().all(|opening| {
        let (root, stake) = opening.fold_to_root();
        root == cert.root && stake == cert.attested_stake
    })
}

/// Domain tag for deriving the sample from the root.
const SAMPLE_DOMAIN: &[u8] = b"QORUS/fold/sample";

/// Derive the sample of member indices from the fold root, so the sample is fixed only after the
/// prover has committed to the whole tree and cannot cherry pick which members are checked. Each index
/// is drawn from a hash over the root and a counter, reduced modulo the committee size, skipping
/// repeats until `k` distinct indices are drawn, or the whole committee if it is smaller than `k`. The
/// result is sorted so a certificate carries its openings in a canonical order.
pub fn sample_indices(root: &[u8; 32], n: usize, k: usize) -> Vec<usize> {
    if n == 0 {
        return Vec::new();
    }
    let k = k.min(n);
    let mut chosen: Vec<usize> = Vec::with_capacity(k);
    let mut counter: u64 = 0;
    while chosen.len() < k {
        let mut buf = Vec::with_capacity(SAMPLE_DOMAIN.len() + 32 + 8);
        buf.extend_from_slice(SAMPLE_DOMAIN);
        buf.extend_from_slice(root);
        buf.extend_from_slice(&counter.to_le_bytes());
        let digest = sha3_256(&buf);
        let draw = u64::from_le_bytes(digest[..8].try_into().expect("eight bytes")) % (n as u64);
        let idx = draw as usize;
        if !chosen.contains(&idx) {
            chosen.push(idx);
        }
        counter = counter.wrapping_add(1);
    }
    chosen.sort_unstable();
    chosen
}

/// Build a certificate opening exactly the members the root selects, so the sample is sound. The root
/// is computed first, then the sample is derived from it, then those members are opened.
pub fn build_sampled(leaves: &[([u8; 32], u64)], total_stake: u64, k: usize) -> FoldCertificate {
    let (root, _) = fold_root(leaves);
    let sample = sample_indices(&root, leaves.len(), k);
    build(leaves, total_stake, &sample)
}

/// Verify a certificate whose sample is bound to its root. In addition to the fold, quorum, and total
/// checks, the openings must be exactly the members the root selects for the given committee size and
/// sample count, so a prover cannot substitute a favourable sample.
pub fn verify_sampled(
    cert: &FoldCertificate,
    committee_total: u64,
    committee_size: usize,
    k: usize,
) -> bool {
    let expected = sample_indices(&cert.root, committee_size, k);
    let mut got: Vec<usize> = cert.openings.iter().map(|o| o.index).collect();
    got.sort_unstable();
    if got != expected {
        return false;
    }
    verify(cert, committee_total, expected.len())
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
                let (got_root, got_stake) = opening.fold_to_root();
                assert_eq!(got_root, root, "opening {} of {n} must land on the root", opening.index);
                // Every opening's path accumulates the whole tree's stake, which is what lets the
                // certificate bind its attested stake to the fold.
                assert_eq!(
                    got_stake,
                    total(&leaves),
                    "opening {} of {n} must accumulate the total stake",
                    opening.index
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
    fn an_inflated_attested_stake_is_rejected() {
        // A prover folds the honest committee but claims a larger attested stake than the tree holds,
        // hoping to clear quorum on paper. Every opening accumulates the true total, so the bound
        // check rejects the lie even though the root and openings are otherwise honest.
        let leaves = committee(12);
        let full = total(&leaves);
        let sample: Vec<usize> = (0..12).collect();
        let mut forged = build(&leaves, full, &sample);
        forged.attested_stake = full * 2;
        assert!(!verify(&forged, full, 12), "the attested stake must be bound to the fold");
    }

    #[test]
    fn a_wrong_sample_size_is_rejected() {
        let leaves = committee(10);
        let full = total(&leaves);
        let cert = build(&leaves, full, &[0, 2, 4]);
        assert!(verify(&cert, full, 3));
        assert!(!verify(&cert, full, 4), "a certificate must carry the expected sample count");
    }

    #[test]
    fn the_sample_is_deterministic_distinct_and_in_range() {
        let root = sha3_256(b"a committed root");
        let a = sample_indices(&root, 40, 12);
        let b = sample_indices(&root, 40, 12);
        assert_eq!(a, b, "the same root gives the same sample");
        assert_eq!(a.len(), 12);
        // Distinct and sorted and inside the committee.
        for w in a.windows(2) {
            assert!(w[0] < w[1], "sorted and distinct");
        }
        assert!(a.iter().all(|&i| i < 40));

        // A different root gives a different sample, so the sample tracks the commitment.
        let other = sha3_256(b"a different root");
        assert_ne!(sample_indices(&other, 40, 12), a);

        // Asking for more than the committee holds returns the whole committee.
        let all = sample_indices(&root, 6, 20);
        assert_eq!(all, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn a_root_bound_certificate_round_trips() {
        for n in [3usize, 8, 15, 32] {
            let leaves = committee(n);
            let full = total(&leaves);
            let k = 5.min(n);
            let cert = build_sampled(&leaves, full, k);
            assert!(
                verify_sampled(&cert, full, n, k),
                "a fresh root bound certificate of {n} members verifies"
            );
            // The openings are exactly the members the root selects.
            let expected = sample_indices(&cert.root, n, k);
            let got: Vec<usize> = cert.openings.iter().map(|o| o.index).collect();
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn the_certificate_stays_near_constant_size_as_the_committee_grows() {
        // The fold's whole purpose: the certificate core is a fixed root and two stakes, and the
        // openings are a fixed sample, so a committee ten times larger produces a near identical size
        // certificate. Only each opening's path grows, and only logarithmically. This is the bandwidth
        // win that the decision brief rests on.
        let k = 20;
        // Wide seeds so leaves stay distinct well past 256 members.
        let build_committee = |n: usize| -> Vec<([u8; 32], u64)> {
            (0..n)
                .map(|i| (sha3_256(&(i as u32).to_le_bytes()), 1 + (i as u64 % 7)))
                .collect()
        };
        let small = build_committee(500);
        let large = build_committee(5_000);
        let cert_small = build_sampled(&small, total(&small), k);
        let cert_large = build_sampled(&large, total(&large), k);

        assert_eq!(cert_small.openings.len(), k, "the sample is fixed at k");
        assert_eq!(cert_large.openings.len(), k, "the sample is fixed at k");
        assert!(verify_sampled(&cert_small, total(&small), 500, k));
        assert!(verify_sampled(&cert_large, total(&large), 5_000, k));

        // A tenfold larger committee adds only a few path steps per opening, never tenfold, so the
        // certificate size is near constant rather than linear in the committee.
        let steps_small: usize = cert_small.openings.iter().map(|o| o.path.len()).sum();
        let steps_large: usize = cert_large.openings.iter().map(|o| o.path.len()).sum();
        assert!(
            steps_large < steps_small * 2,
            "paths grow logarithmically ({steps_small} then {steps_large}), not with the committee"
        );
    }

    #[test]
    fn a_cherry_picked_sample_is_rejected() {
        // A prover folds the real committee but opens members it chose rather than the ones the root
        // selects, hoping to hide a lie among the unopened members. The root bound check rejects it.
        let leaves = committee(20);
        let full = total(&leaves);
        let k = 5;
        let honest = sample_indices(&fold_root(&leaves).0, 20, k);
        // Pick a sample that is valid in every other way but is not the root's sample.
        let mut picked: Vec<usize> = (0..20).filter(|i| !honest.contains(i)).take(k).collect();
        picked.sort_unstable();
        assert_ne!(picked, honest);
        let forged = build(&leaves, full, &picked);
        // Every opening still folds to the root and quorum holds, so the plain check passes.
        assert!(verify(&forged, full, k));
        // But it is not the sample the root selects, so the root bound check rejects it.
        assert!(!verify_sampled(&forged, full, 20, k));
    }
}
