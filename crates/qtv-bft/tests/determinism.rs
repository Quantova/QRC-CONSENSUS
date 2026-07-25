// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The core is deterministic: the same validator set, committee size, seed, and

use qtv_bft::machine::Machine;
use qtv_bft::validator::{Fault, ValidatorSet};

fn run(seed: [u8; 32], faults: &[(u64, Fault)]) -> Machine {
    let mut set = ValidatorSet::new(4);
    for &(id, fault) in faults {
        set.set_fault(id, fault);
    }
    let mut machine = Machine::new(set, 4, seed, 3, 3);
    machine.run();
    machine
}

#[test]
fn identical_inputs_give_identical_certificates() {
    let first = run([18u8; 32], &[]);
    let second = run([18u8; 32], &[]);
    assert_eq!(first.certificates(), second.certificates());
}

#[test]
fn identical_inputs_give_identical_message_logs() {
    // Signing uses a zero randomizer, so even the attestation bytes match.
    let first = run([171u8; 32], &[]);
    let second = run([171u8; 32], &[]);
    assert_eq!(first.messages(), second.messages());
}

#[test]
fn determinism_holds_with_faults_present() {
    let faults = [(2u64, Fault::Byzantine), (4u64, Fault::Offline)];
    let first = run([192u8; 32], &faults);
    let second = run([192u8; 32], &faults);
    assert_eq!(first.certificates(), second.certificates());
    assert_eq!(first.slashed(), second.slashed());
}

#[test]
fn different_seeds_can_diverge_yet_each_is_stable() {
    let a1 = run([1u8; 32], &[]);
    let a2 = run([1u8; 32], &[]);
    let b = run([2u8; 32], &[]);
    // Each seed reproduces itself exactly.
    assert_eq!(a1.certificates(), a2.certificates());
    // Both seeds still finalize every height.
    assert!(a1.all_finalized());
    assert!(b.all_finalized());
    // The seeds drive different block payloads.
    assert_ne!(
        a1.certificates()[0].block.val,
        b.certificates()[0].block.val
    );
}
