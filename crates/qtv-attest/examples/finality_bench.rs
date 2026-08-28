// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::time::Instant;

use qtv_attest::aggregate::aggregate;
use qtv_attest::{Attestation, Attester, Beacon, Block, CommitteeCommitment, Parent};

const STAKE: u64 = 5_000;
const SIZES: &[usize] = &[64, 128, 256, 500];
const SIG_BYTES: usize = 3_309;

fn measure(committee_size: usize) {
    let budget = committee_size as u64;
    let attesters: Vec<Attester> = (0..committee_size)
        .map(|i| Attester::new(i as u64 + 1, STAKE))
        .collect();
    let refs: Vec<&Attester> = attesters.iter().collect();
    let commitment = CommitteeCommitment::from_attesters_with_budget(0, &refs, budget);
    let beacon = Beacon::genesis();
    let block = Block::new(1, [7u8; 32], Parent::Genesis);
    let weights = vec![STAKE; committee_size];
    let tau = qtv_attest::params::finality_threshold_for_draw(
        qtv_attest::params::expected_committee(&weights, budget),
        commitment.len() as u64,
    );

    let attestations: Vec<Attestation> = attesters
        .iter()
        .map(|a| a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon))
        .collect();

    let t0 = Instant::now();
    let cert = aggregate(1, 1, 0, block, &commitment, &beacon, &attestations, tau)
        .expect("an entitled committee aggregates");
    let aggregate_ms = t0.elapsed().as_secs_f64() * 1e3;

    let t1 = Instant::now();
    let verdict = cert.verify(1, &commitment, &beacon, tau);
    let verify_ms = t1.elapsed().as_secs_f64() * 1e3;
    assert!(verdict.is_verified(), "the certificate must verify before a number is trusted");

    let size_kb = (cert.attestations.len() * SIG_BYTES) as f64 / 1024.0;
    println!(
        "committee {committee_size:>4}: aggregate {aggregate_ms:>8.2} ms   verify {verify_ms:>8.2} ms   \
         size ~{size_kb:>7.1} KB   ({} signatures)",
        cert.attestations.len()
    );
}

fn main() {
    let arg = std::env::args().nth(1).and_then(|a| a.parse::<usize>().ok());
    println!("Finality certificate cost against committee size (committee is bounded at the budget, 500).");
    match arg {
        Some(size) => measure(size),
        None => {
            for &size in SIZES {
                measure(size);
            }
        }
    }
    println!(
        "The committee is a bounded sortition sample, so the size 500 row is the worst case finality \
         cost at any validator count."
    );
}
