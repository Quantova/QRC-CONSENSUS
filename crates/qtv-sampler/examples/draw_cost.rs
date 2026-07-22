// Per draw and per verify cost of the one time key sortition. Run with:
//     cargo run -p qtv-sampler --example draw_cost --release

use std::hint::black_box;
use std::time::Instant;

use qtv_sampler::beacon::Beacon;
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::sortition::{verify_selection, Credential};
use qtv_sampler::validator::SamplerValidator;

fn ns_per_op<F: FnMut()>(iters: u32, mut f: F) -> f64 {
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed().as_secs_f64() * 1e9 / iters as f64
}

fn draw_cost(slots: u64) -> (usize, f64, f64) {
    let depth = (slots.max(1) as usize).next_power_of_two().trailing_zeros() as usize;
    let v = SamplerValidator::with_slots(1, 100, slots);
    let root = v.root();
    let beacon = Beacon::genesis();
    let slot = slots / 2;
    let cred: Credential = v.reveal(slot);

    let draw = ns_per_op(1_000_000, || {
        black_box(cred.value(black_box(&beacon), DOMAIN_COMMITTEE, slot));
    });
    let verify = ns_per_op(500_000, || {
        black_box(verify_selection(
            &root,
            &beacon,
            DOMAIN_COMMITTEE,
            slot,
            100,
            100,
            100,
            black_box(&cred),
        ));
    });
    (depth, draw, verify)
}

fn main() {
    println!("One time key sortition, per operation cost");
    println!("SHA-3 only. A draw is one permutation, a verify is a Merkle path.\n");

    println!("Keccak-f permutations per operation, exact:");
    println!("   draw   (one SHAKE256 over <=95 bytes)                 1");
    for slots in [64u64, 4096] {
        let depth = (slots as usize).next_power_of_two().trailing_zeros() as usize;
        println!(
            "   verify (leaf + {depth}-deep path + output) at {slots:>4} slots   {}",
            depth + 2
        );
    }

    for slots in [64u64, 4096] {
        let (depth, draw, verify) = draw_cost(slots);
        println!(
            "\nMeasured at {slots} slots (depth {depth}):\n   draw     {draw:>8.1} ns\n   verify   {verify:>8.1} ns"
        );
    }
}
