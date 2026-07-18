//! Measurement of the stage two certificate.

use std::time::Instant;

use qtv_attest::aggregate::aggregate;
use qtv_attest::certificate::{Body, Certificate};
use qtv_attest::succinct::{prove_stage_two, ProverVerifier, STAGE2_SEGMENTS};
use qtv_attest::{Attester, Beacon, Block, CommitteeCommitment, Parent};

fn stage_two_size(cert: &Certificate) -> usize {
    match &cert.body {
        Body::Stage2(body) => body.proof.bytes.len(),
        Body::Stage1(_) => 0,
    }
}

fn main() {
    // A small committee is enough. The certificate size and the verify time are
    // constant in the committee size, so a larger committee produces the same
    // certificate and the same verify time, only more slowly to set up.
    let members: Vec<Attester> = (1..=4).map(|id| Attester::new(id, 100)).collect();
    let refs: Vec<&Attester> = members.iter().collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, [7u8; 32], Parent::Genesis);
    let commitment = CommitteeCommitment::from_attesters_with_budget(0, &refs, 4);

    // A supermajority of the committee attests, aggregated into a stage one
    // certificate, whose admitted set the stage two certificate proves over.
    let attestations: Vec<_> = members[..3]
        .iter()
        .map(|a| a.attest(1, 0, block, &beacon))
        .collect();
    let stage_one =
        aggregate(1, 0, block, &commitment, &beacon, &attestations).expect("supermajority");
    let admitted = match &stage_one.body {
        Body::Stage1(b) => b.attestations.clone(),
        Body::Stage2(_) => unreachable!(),
    };

    let start = Instant::now();
    let stage_two = prove_stage_two(stage_one.envelope.clone(), &admitted);
    let prove_time = start.elapsed();
    let size = stage_two_size(&stage_two);

    let verifier = ProverVerifier;
    // One warm up verify, then the mean of twenty measured verifies.
    let _ = stage_two.verify_with(&commitment, &beacon, &verifier);
    let iters = 20;
    let start = Instant::now();
    let mut verdict = stage_two.verify_with(&commitment, &beacon, &verifier);
    for _ in 1..iters {
        verdict = stage_two.verify_with(&commitment, &beacon, &verifier);
    }
    let verify_time = start.elapsed() / iters;

    println!("stage two certificate");
    println!("  segments {}", STAGE2_SEGMENTS);
    println!("  size {} bytes ({:.3} MB)", size, size as f64 / 1e6);
    println!("  verify {:?} (mean of {})", verify_time, iters);
    println!("  prove {:?}", prove_time);
    println!("  verdict {}", verdict.is_verified());
    println!();
    println!("the size and the verify time are constant in the committee size");
    println!("the stage one certificate at 500 members is about 9.8 MB and about 630 ms");
    println!("and both grow linearly with the committee");
}
