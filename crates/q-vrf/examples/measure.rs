// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::hint::black_box;
use std::time::Instant;

use q_vrf::{keygen, verify};

fn bench_position(slots: u64) {
    let seed = {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&slots.to_le_bytes());
        s
    };

    let t0 = Instant::now();
    let (sk, pk) = keygen(seed, slots);
    let keygen_ns = t0.elapsed().as_nanos();

    let (y0, proof0) = sk.eval_and_prove(slots / 2);
    assert!(verify(&pk, slots / 2, &y0, &proof0));
    let proof_bytes = proof0.size_bytes();
    let pk_bytes = pk.size_bytes();
    let depth = pk.depth();

    let iters: u64 = 100_000.min(slots.max(1) * 64);

    let t0 = Instant::now();
    for i in 0..iters {
        let pos = i % slots;
        black_box(sk.eval(black_box(pos)));
    }
    let eval_ns = t0.elapsed().as_nanos() as f64 / iters as f64;

    let t0 = Instant::now();
    for i in 0..iters {
        let pos = i % slots;
        black_box(sk.prove(black_box(pos)));
    }
    let prove_ns = t0.elapsed().as_nanos() as f64 / iters as f64;

    let (y, proof) = sk.eval_and_prove(slots / 3);
    let pos = slots / 3;
    let t0 = Instant::now();
    for _ in 0..iters {
        black_box(verify(black_box(&pk), black_box(pos), black_box(&y), black_box(&proof)));
    }
    let verify_ns = t0.elapsed().as_nanos() as f64 / iters as f64;

    println!(
        "slots {:>6}  depth {:>2}  pk {:>3} B  proof {:>5} B  keygen {:>10.1} us  eval {:>7.3} us  prove {:>7.3} us  verify {:>7.3} us",
        slots,
        depth,
        pk_bytes,
        proof_bytes,
        keygen_ns as f64 / 1_000.0,
        eval_ns / 1_000.0,
        prove_ns / 1_000.0,
        verify_ns / 1_000.0,
    );
}

fn main() {
    println!("Q-VRF measurements (single core, times per operation)");
    for slots in [64u64, 256, 1_024, 4_096, 16_384, 65_536] {
        bench_position(slots);
    }

    let slots = 8_192u64;
    let (sk, pk) = keygen([7u8; 32], slots);
    let transcripts: Vec<_> = (0..1_024u64)
        .map(|i| {
            let pos = i % slots;
            let (y, proof) = sk.eval_and_prove(pos);
            (pos, y, proof)
        })
        .collect();
    let t0 = Instant::now();
    let mut ok = 0u64;
    for (pos, y, proof) in &transcripts {
        if verify(&pk, *pos, y, proof) {
            ok += 1;
        }
    }
    let elapsed = t0.elapsed();
    assert_eq!(ok, transcripts.len() as u64);
    println!(
        "verifying a committee of {} credentials at slots {} took {:.3} ms total ({:.3} us each)",
        transcripts.len(),
        slots,
        elapsed.as_secs_f64() * 1_000.0,
        elapsed.as_nanos() as f64 / transcripts.len() as f64 / 1_000.0,
    );
}
