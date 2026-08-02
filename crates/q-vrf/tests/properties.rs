// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Property tests for the Q-VRF primitive: uniqueness and non grindability,
//! pseudorandomness, verifiability and soundness, and the second preimage reduction
//! to SHA3. Each property is one passing test.

use q_vrf::{keygen, output_from_preimage, verify, Output, Proof};
use qtv_sampler::onetime::{leaf_hash, node_hash, MerklePath, PREIMAGE_BYTES};

fn count_ones(bytes: &[u8]) -> u64 {
    bytes.iter().map(|b| b.count_ones() as u64).sum()
}

fn hamming(a: &[u8], b: &[u8]) -> u64 {
    a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones() as u64).sum()
}

// A deterministic pool of alternative preimages an adversary might try to substitute.
fn adversarial_preimages(count: u64) -> Vec<[u8; PREIMAGE_BYTES]> {
    (0..count)
        .map(|i| {
            let mut p = [0u8; PREIMAGE_BYTES];
            p[..8].copy_from_slice(&i.to_le_bytes());
            p[8..16].copy_from_slice(&(i.wrapping_mul(0x9E3779B97F4A7C15)).to_le_bytes());
            p
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Uniqueness and non grindability.
// ---------------------------------------------------------------------------

#[test]
fn exactly_one_output_verifies_per_key_and_position() {
    // The honest output verifies, and every perturbation of it is rejected. Because
    // verify pins the output to the one implied by the committed preimage, no second
    // output can be presented for the same key and position.
    let (sk, pk) = keygen([11u8; 32], 128);
    for position in [0u64, 1, 7, 63, 127] {
        let (y, proof) = sk.eval_and_prove(position);
        assert!(verify(&pk, position, &y, &proof), "honest output must verify");

        // Flip each bit of the output; none may verify with the honest proof.
        for byte in 0..OUTPUT_LEN {
            for bit in 0..8u32 {
                let mut forged = y;
                forged[byte] ^= 1 << bit;
                assert!(
                    !verify(&pk, position, &forged, &proof),
                    "a one bit forged output verified at position {position}"
                );
            }
        }
    }
}

#[test]
fn a_committed_key_cannot_be_reground_to_a_second_output() {
    // Non grindability. The public key commits the tree before any beacon is drawn.
    // We stand in for a grinding signer that, after seeing public randomness, tries
    // to swap in any other preimage at a position to move its output. Every
    // substitute fails membership, so there is no alternative verifying output.
    let (sk, pk) = keygen([22u8; 32], 256);
    let position = 100u64;
    let (honest_y, honest_proof) = sk.eval_and_prove(position);
    assert!(verify(&pk, position, &honest_y, &honest_proof));

    for alt in adversarial_preimages(20_000) {
        if alt == honest_proof.preimage {
            continue;
        }
        let forged_proof = Proof { preimage: alt, path: honest_proof.path.clone() };
        let forged_y = output_from_preimage(position, &alt);
        assert!(
            !verify(&pk, position, &forged_y, &forged_proof),
            "a substituted preimage produced a verifying second output"
        );
    }
}

#[test]
fn a_preimage_from_another_position_or_key_cannot_be_reused() {
    let (sk, pk) = keygen([33u8; 32], 128);
    let (other_sk, _) = keygen([34u8; 32], 128);
    let position = 40u64;
    let honest = sk.prove(position);

    // A preimage authenticated at a different position does not authenticate here.
    let elsewhere = sk.prove(41);
    let mixed = Proof { preimage: elsewhere.preimage, path: honest.path.clone() };
    let y = output_from_preimage(position, &mixed.preimage);
    assert!(!verify(&pk, position, &y, &mixed));

    // A preimage from another key does not authenticate against this key.
    let foreign = other_sk.prove(position);
    let y2 = output_from_preimage(position, &foreign.preimage);
    assert!(!verify(&pk, position, &y2, &foreign));
}

// ---------------------------------------------------------------------------
// Pseudorandomness.
// ---------------------------------------------------------------------------

const OUTPUT_LEN: usize = 32;

#[test]
fn distinct_positions_give_distinct_outputs() {
    let (sk, _) = keygen([44u8; 32], 8192);
    let mut seen = std::collections::HashSet::new();
    for position in 0..8192u64 {
        assert!(seen.insert(sk.eval(position)), "a repeat output appeared at {position}");
    }
}

#[test]
fn output_bits_are_statistically_balanced() {
    // Aggregate over about one million output bits. A pseudorandom function has a
    // bit balance indistinguishable from one half. SHA3 makes this deterministic, so
    // the loose tolerance is comfortable margin, not a flaky bound.
    let (sk, _) = keygen([55u8; 32], 4096);
    let mut ones = 0u64;
    let mut total_bits = 0u64;
    for position in 0..4096u64 {
        let y = sk.eval(position);
        ones += count_ones(&y);
        total_bits += 8 * OUTPUT_LEN as u64;
    }
    let frac = ones as f64 / total_bits as f64;
    assert!((frac - 0.5).abs() < 0.01, "bit balance {frac} strayed from one half");
}

#[test]
fn output_byte_mean_is_near_the_uniform_mean() {
    let (sk, _) = keygen([56u8; 32], 4096);
    let mut sum = 0u64;
    let mut n = 0u64;
    for position in 0..4096u64 {
        for b in sk.eval(position) {
            sum += b as u64;
            n += 1;
        }
    }
    let mean = sum as f64 / n as f64;
    assert!((mean - 127.5).abs() < 2.0, "byte mean {mean} strayed from the uniform mean");
}

#[test]
fn neighbouring_outputs_are_decorrelated() {
    // Successive positions produce outputs whose average Hamming distance is close to
    // half the output width, as independent uniform strings would.
    let (sk, _) = keygen([57u8; 32], 2048);
    let mut total = 0u64;
    let mut pairs = 0u64;
    let mut prev = sk.eval(0);
    for position in 1..2048u64 {
        let cur = sk.eval(position);
        total += hamming(&prev, &cur);
        pairs += 1;
        prev = cur;
    }
    let mean = total as f64 / pairs as f64;
    assert!((mean - 128.0).abs() < 6.0, "mean neighbour Hamming distance {mean} off balance");
}

#[test]
fn the_output_is_domain_separated_and_position_bound() {
    let (sk, pk) = keygen([58u8; 32], 64);
    let position = 9u64;
    let proof = sk.prove(position);
    let y = sk.eval(position);

    // The output is not the revealed preimage and not the committed leaf. Publishing
    // the leaf in the root tells a verifier nothing about the output until the
    // preimage is revealed.
    assert_ne!(y.as_slice(), proof.preimage.as_slice());
    assert_ne!(y, leaf_hash(&proof.preimage));
    let _ = pk;

    // The same preimage at a different position yields a different output.
    let shifted = output_from_preimage(position + 1, &proof.preimage);
    assert_ne!(y, shifted);
}

// ---------------------------------------------------------------------------
// Verifiability and soundness.
// ---------------------------------------------------------------------------

#[test]
fn an_honest_transcript_verifies() {
    let (sk, pk) = keygen([66u8; 32], 512);
    for position in [0u64, 1, 255, 511] {
        let (y, proof) = sk.eval_and_prove(position);
        assert!(verify(&pk, position, &y, &proof));
    }
}

#[test]
fn a_tampered_authentication_path_is_rejected() {
    let (sk, pk) = keygen([67u8; 32], 512);
    let position = 300u64;
    let (y, proof) = sk.eval_and_prove(position);
    assert!(verify(&pk, position, &y, &proof));

    // Flip a bit in each sibling in turn.
    for level in 0..proof.path.siblings.len() {
        let mut siblings = proof.path.siblings.clone();
        siblings[level][0] ^= 1;
        let bad = Proof { preimage: proof.preimage, path: MerklePath { siblings } };
        assert!(!verify(&pk, position, &y, &bad), "a tampered sibling at level {level} verified");
    }

    // A shortened path is rejected.
    let mut short = proof.path.siblings.clone();
    short.pop();
    let bad = Proof { preimage: proof.preimage, path: MerklePath { siblings: short } };
    assert!(!verify(&pk, position, &y, &bad));

    // An extended path is rejected.
    let mut long = proof.path.siblings.clone();
    long.push([0u8; 32]);
    let bad = Proof { preimage: proof.preimage, path: MerklePath { siblings: long } };
    assert!(!verify(&pk, position, &y, &bad));
}

#[test]
fn a_tampered_preimage_is_rejected() {
    let (sk, pk) = keygen([68u8; 32], 512);
    let position = 123u64;
    let (y, proof) = sk.eval_and_prove(position);
    for byte in 0..PREIMAGE_BYTES {
        let mut preimage = proof.preimage;
        preimage[byte] ^= 0x80;
        // Recompute the output honestly for the tampered preimage: it still fails,
        // because the tampered leaf is not the committed one.
        let bad = Proof { preimage, path: proof.path.clone() };
        let y_bad = output_from_preimage(position, &preimage);
        assert!(!verify(&pk, position, &y_bad, &bad));
        // And the tampered preimage under the honest output fails too.
        assert!(!verify(&pk, position, &y, &bad));
    }
}

#[test]
fn a_tampered_output_is_rejected() {
    let (sk, pk) = keygen([69u8; 32], 256);
    let position = 200u64;
    let (y, proof) = sk.eval_and_prove(position);
    for byte in 0..OUTPUT_LEN {
        let mut forged: Output = y;
        forged[byte] ^= 0x01;
        assert!(!verify(&pk, position, &forged, &proof));
    }
}

#[test]
fn a_proof_for_one_position_does_not_validate_another() {
    let (sk, pk) = keygen([70u8; 32], 256);
    let source = 30u64;
    let (y_source, proof) = sk.eval_and_prove(source);
    for target in 0..256u64 {
        if target == source {
            continue;
        }
        // The source output at the wrong position fails.
        assert!(!verify(&pk, target, &y_source, &proof));
        // Re binding the output to the target position with the source preimage also
        // fails, because the path authenticates the source position only.
        let y_target = output_from_preimage(target, &proof.preimage);
        assert!(!verify(&pk, target, &y_target, &proof));
    }
}

#[test]
fn a_position_past_the_slot_count_is_rejected() {
    let (sk, pk) = keygen([71u8; 32], 100);
    let (y, proof) = sk.eval_and_prove(0);
    assert!(verify(&pk, 0, &y, &proof));
    // Present the position zero transcript at an out of range position.
    assert!(!verify(&pk, 100, &y, &proof));
    assert!(!verify(&pk, 1_000_000, &y, &proof));
}

#[test]
fn a_proof_does_not_verify_under_a_foreign_key() {
    let (sk_a, pk_a) = keygen([72u8; 32], 256);
    let (_, pk_b) = keygen([73u8; 32], 256);
    let position = 55u64;
    let (y, proof) = sk_a.eval_and_prove(position);
    assert!(verify(&pk_a, position, &y, &proof));
    assert!(!verify(&pk_b, position, &y, &proof));
}

// ---------------------------------------------------------------------------
// Second preimage reduction to SHA3.
// ---------------------------------------------------------------------------

#[test]
fn forging_reduces_to_a_sha3_second_preimage_or_collision() {
    // The committed value at a position is leaf_hash(honest preimage). Verification
    // passes only when the revealed preimage hashes to that committed leaf and the
    // path folds to the root. So a forger who keeps the honest path must supply a
    // preimage p different from the honest one with leaf_hash(p) equal to the
    // committed leaf, which is a SHA3-256 second preimage. A forger who instead keeps
    // the honest preimage but alters the path must fold a fixed leaf to the fixed
    // root through a changed node, which is a SHA3-256 collision on node_hash.
    //
    // We cannot break SHA3, so we exhibit the structure and confirm that, absent such
    // a break, every substitution fails. This makes the security reduction concrete.
    let (sk, pk) = keygen([88u8; 32], 128);
    let position = 64u64;
    let honest = sk.prove(position);
    let committed_leaf = leaf_hash(&honest.preimage);

    // The path recomputes the committed root from the committed leaf. Confirm the
    // honest leaf is indeed what the path binds by rebuilding the root by hand.
    let mut node = committed_leaf;
    let mut idx = position;
    for sib in &honest.path.siblings {
        node = if idx & 1 == 0 { node_hash(&node, sib) } else { node_hash(sib, &node) };
        idx >>= 1;
    }
    assert_eq!(node, pk.digest(), "the honest path must reconstruct the committed root");

    // Any adversarial preimage that is not a SHA3 second preimage of the committed
    // leaf produces a different leaf and therefore a different reconstructed root.
    for alt in adversarial_preimages(50_000) {
        if alt == honest.preimage {
            continue;
        }
        let alt_leaf = leaf_hash(&alt);
        assert_ne!(alt_leaf, committed_leaf, "found a SHA3-256 second preimage; report immediately");
        // Since the leaf differs, membership with the honest path fails.
        let forged = Proof { preimage: alt, path: honest.path.clone() };
        let y = output_from_preimage(position, &alt);
        assert!(!verify(&pk, position, &y, &forged));
    }
}
