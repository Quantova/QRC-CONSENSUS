// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_crypto::ml_dsa::{verify as ml_verify, PublicKey, Signature};
use qtv_crypto::sha3::sha3_256;

const NODE_DOMAIN: &[u8] = b"QORUS/fold/node";

pub fn node_hash(left: &[u8; 32], right: &[u8; 32], left_stake: u64, right_stake: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(NODE_DOMAIN.len() + 64 + 16);
    buf.extend_from_slice(NODE_DOMAIN);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    buf.extend_from_slice(&left_stake.to_le_bytes());
    buf.extend_from_slice(&right_stake.to_le_bytes());
    sha3_256(&buf)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Sibling {
        hash: [u8; 32],
        stake: u64,
        on_left: bool,
    },
    Carry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub index: usize,
    pub leaf: [u8; 32],
    pub stake: u64,
    pub path: Vec<Step>,
}

impl Opening {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldCertificate {
    pub root: [u8; 32],
    pub attested_stake: u64,
    pub total_stake: u64,
    pub openings: Vec<Opening>,
}

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

pub fn fold_root(leaves: &[([u8; 32], u64)]) -> ([u8; 32], u64) {
    let levels = build_levels(leaves);
    levels
        .last()
        .and_then(|top| top.first())
        .copied()
        .unwrap_or(([0u8; 32], 0))
}

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

pub fn meets_quorum(cert: &FoldCertificate) -> bool {
    (cert.attested_stake as u128) * 3 > (cert.total_stake as u128) * 2
}

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

const SAMPLE_DOMAIN: &[u8] = b"QORUS/fold/sample";

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

pub fn build_sampled(leaves: &[([u8; 32], u64)], total_stake: u64, k: usize) -> FoldCertificate {
    let (root, _) = fold_root(leaves);
    let sample = sample_indices(&root, leaves.len(), k);
    build(leaves, total_stake, &sample)
}

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

const ATTESTED_LEAF_DOMAIN: &[u8] = b"QORUS/fold/attested-leaf";

/// The fold leaf for an attesting committee member, binding the member's attestation
pub fn attested_leaf(public_key: &PublicKey, stake: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(ATTESTED_LEAF_DOMAIN.len() + public_key.len() + 8);
    buf.extend_from_slice(ATTESTED_LEAF_DOMAIN);
    buf.extend_from_slice(public_key);
    buf.extend_from_slice(&stake.to_le_bytes());
    sha3_256(&buf)
}

#[derive(Clone)]
pub struct AttestedOpening {
    pub index: usize,
    pub public_key: PublicKey,
    pub stake: u64,
    pub signature: Signature,
    pub path: Vec<Step>,
}

impl AttestedOpening {
    pub fn leaf(&self) -> [u8; 32] {
        attested_leaf(&self.public_key, self.stake)
    }

    pub fn fold_to_root(&self) -> ([u8; 32], u64) {
        let mut hash = self.leaf();
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

    pub fn signature_verifies(&self, message: &[u8], context: &[u8]) -> bool {
        ml_verify(&self.public_key, message, &self.signature, context)
    }
}

#[derive(Clone)]
pub struct AttestedFoldCertificate {
    pub root: [u8; 32],
    pub attested_stake: u64,
    pub total_stake: u64,
    pub openings: Vec<AttestedOpening>,
}

/// Build a signature carrying fold certificate over the attesters. Each attester is its
pub fn build_attested(
    attesters: &[(PublicKey, u64, Signature)],
    committee_total: u64,
    k: usize,
) -> AttestedFoldCertificate {
    let leaves: Vec<([u8; 32], u64)> = attesters
        .iter()
        .map(|(pk, stake, _)| (attested_leaf(pk, *stake), *stake))
        .collect();
    let (root, attested_stake) = fold_root(&leaves);
    let sample = sample_indices(&root, leaves.len(), k);
    let levels = build_levels(&leaves);
    let openings = sample
        .iter()
        .filter(|&&i| i < attesters.len())
        .map(|&i| {
            let (pk, stake, sig) = &attesters[i];
            AttestedOpening {
                index: i,
                public_key: *pk,
                stake: *stake,
                signature: *sig,
                path: opening_path(&levels, i),
            }
        })
        .collect();
    AttestedFoldCertificate {
        root,
        attested_stake,
        total_stake: committee_total,
        openings,
    }
}

/// Verify a signature carrying fold certificate. Beyond the stake totals, the quorum,
pub fn verify_attested(
    cert: &AttestedFoldCertificate,
    committee_total: u64,
    attester_count: usize,
    k: usize,
    message: &[u8],
    context: &[u8],
) -> bool {
    if cert.total_stake != committee_total {
        return false;
    }
    if (cert.attested_stake as u128) * 3 <= (cert.total_stake as u128) * 2 {
        return false;
    }
    let expected = sample_indices(&cert.root, attester_count, k);
    if cert.openings.len() != expected.len() {
        return false;
    }
    let mut got: Vec<usize> = cert.openings.iter().map(|o| o.index).collect();
    got.sort_unstable();
    if got != expected {
        return false;
    }
    cert.openings.iter().all(|opening| {
        let (root, stake) = opening.fold_to_root();
        root == cert.root
            && stake == cert.attested_stake
            && opening.signature_verifies(message, context)
    })
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

        let mut tampered = leaves.clone();
        tampered[3].1 += 1;
        assert_ne!(fold_root(&tampered).0, root_a);
    }

    #[test]
    fn every_opening_recomputes_the_root_across_sizes() {
        for n in [1usize, 2, 3, 5, 8, 13, 16, 31] {
            let leaves = committee(n);
            let (root, _) = fold_root(&leaves);
            let sample: Vec<usize> = (0..n).collect();
            let cert = build(&leaves, total(&leaves), &sample);
            assert_eq!(cert.root, root);
            for opening in &cert.openings {
                let (got_root, got_stake) = opening.fold_to_root();
                assert_eq!(got_root, root, "opening {} of {n} must land on the root", opening.index);
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

        let mut bad_leaf = cert.clone();
        bad_leaf.openings[4].leaf[0] ^= 1;
        assert!(!verify(&bad_leaf, total(&leaves), 11));

        let mut bad_stake = cert.clone();
        if let Step::Sibling { stake, .. } = &mut bad_stake.openings[4].path[0] {
            *stake += 1;
        }
        assert!(!verify(&bad_stake, total(&leaves), 11));

        assert!(verify(&cert, total(&leaves), 11));
    }

    #[test]
    fn quorum_and_totals_are_enforced() {
        let leaves = committee(12);
        let full = total(&leaves);
        let sample: Vec<usize> = (0..12).collect();

        let cert = build(&leaves, full, &sample);
        assert!(verify(&cert, full, 12));

        assert!(!verify(&cert, full + 1, 12));

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
        for w in a.windows(2) {
            assert!(w[0] < w[1], "sorted and distinct");
        }
        assert!(a.iter().all(|&i| i < 40));

        let other = sha3_256(b"a different root");
        assert_ne!(sample_indices(&other, 40, 12), a);

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
            let expected = sample_indices(&cert.root, n, k);
            let got: Vec<usize> = cert.openings.iter().map(|o| o.index).collect();
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn the_certificate_stays_near_constant_size_as_the_committee_grows() {
        let k = 20;
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

        let steps_small: usize = cert_small.openings.iter().map(|o| o.path.len()).sum();
        let steps_large: usize = cert_large.openings.iter().map(|o| o.path.len()).sum();
        assert!(
            steps_large < steps_small * 2,
            "paths grow logarithmically ({steps_small} then {steps_large}), not with the committee"
        );
    }

    #[test]
    fn a_cherry_picked_sample_is_rejected() {
        let leaves = committee(20);
        let full = total(&leaves);
        let k = 5;
        let honest = sample_indices(&fold_root(&leaves).0, 20, k);
        let mut picked: Vec<usize> = (0..20).filter(|i| !honest.contains(i)).take(k).collect();
        picked.sort_unstable();
        assert_ne!(picked, honest);
        let forged = build(&leaves, full, &picked);
        assert!(verify(&forged, full, k));
        assert!(!verify_sampled(&forged, full, 20, k));
    }

    use crate::attester::Attester;
    use qtv_bft::block::{Block, Parent};
    use qtv_sampler::beacon::Beacon;

    fn signed_committee(
        n: usize,
        block: Block,
        height: u64,
        slot: u64,
    ) -> (Vec<(PublicKey, u64, Signature)>, Vec<u8>, &'static [u8]) {
        let beacon = Beacon::genesis();
        let subject = crate::attestation::attestation_message(height, slot, 0, &block);
        let members: Vec<(PublicKey, u64, Signature)> = (1..=n as u64)
            .map(|id| {
                let a = Attester::new(id, 100);
                let att = a.attest(height, slot, 0, block, &beacon);
                (*a.attest_public_key(), a.weight(), att.sig)
            })
            .collect();
        (members, subject, crate::params::ATTEST_CONTEXT)
    }

    #[test]
    fn a_signed_fold_certificate_verifies_but_a_forged_signature_is_rejected() {
        let (n, k, height, slot) = (16usize, 5usize, 1u64, 0u64);
        let block = Block::new(height, [9u8; 32], Parent::Genesis);
        let (members, subject, context) = signed_committee(n, block, height, slot);
        let full: u64 = members.iter().map(|(_, s, _)| s).sum();

        let cert = build_attested(&members, full, k);
        assert!(verify_attested(&cert, full, n, k, &subject, context));

        let leaves: Vec<([u8; 32], u64)> = members
            .iter()
            .map(|(pk, s, _)| (attested_leaf(pk, *s), *s))
            .collect();
        assert!(verify_sampled(&build_sampled(&leaves, full, k), full, n, k));

        let mut forged = cert.clone();
        forged.openings[0].signature[0] ^= 1;
        assert!(!verify_attested(&forged, full, n, k, &subject, context));
    }

    #[test]
    fn a_swapped_key_a_swapped_signature_or_a_wrong_subject_is_rejected() {
        let (n, k, height, slot) = (16usize, 5usize, 1u64, 0u64);
        let block = Block::new(height, [9u8; 32], Parent::Genesis);
        let (members, subject, context) = signed_committee(n, block, height, slot);
        let full: u64 = members.iter().map(|(_, s, _)| s).sum();
        let cert = build_attested(&members, full, k);
        assert!(verify_attested(&cert, full, n, k, &subject, context));

        let mut swapped_sig = cert.clone();
        swapped_sig.openings[0].signature = cert.openings[1].signature;
        assert!(!verify_attested(&swapped_sig, full, n, k, &subject, context));

        let mut swapped_key = cert.clone();
        swapped_key.openings[0].public_key = cert.openings[1].public_key;
        assert!(!verify_attested(&swapped_key, full, n, k, &subject, context));

        let other = Block::new(height, [10u8; 32], Parent::Genesis);
        let wrong = crate::attestation::attestation_message(height, slot, 0, &other);
        assert!(!verify_attested(&cert, full, n, k, &wrong, context));
    }
}
