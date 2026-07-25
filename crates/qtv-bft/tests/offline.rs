// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An offline validator is skipped and is never slashed, mirroring the

use qtv_bft::machine::Machine;
use qtv_bft::validator::{Fault, ValidatorSet};

const SEED: [u8; 32] = [192u8; 32];

fn set_with_offline(count: usize, offline: &[u64]) -> ValidatorSet {
    let mut set = ValidatorSet::new(count);
    for &id in offline {
        set.set_fault(id, Fault::Offline);
    }
    set
}

#[test]
fn tolerated_offline_validator_still_finalizes_in_order() {
    // Four validators, one offline. The three online are exactly a quorum.
    let set = set_with_offline(4, &[4]);
    let mut machine = Machine::new(set, 4, SEED, 2, 3);
    let certs = machine.run();
    assert_eq!(certs.len(), 2);
    assert_eq!(certs[0].height, 1);
    assert_eq!(certs[1].height, 2);
}

#[test]
fn offline_validator_is_never_slashed() {
    let set = set_with_offline(4, &[4]);
    let mut machine = Machine::new(set, 4, SEED, 2, 3);
    machine.run();
    assert!(machine.slashed().is_empty());
    assert!(!machine.slashed().contains(&4));
}

#[test]
fn offline_validator_casts_no_attestation() {
    let set = set_with_offline(4, &[4]);
    let mut machine = Machine::new(set, 4, SEED, 2, 3);
    machine.run();
    let attested = machine
        .messages()
        .iter()
        .filter_map(|m| m.as_vote())
        .any(|a| a.from == 4);
    assert!(!attested, "an offline validator never attests");
}

#[test]
fn offline_validator_is_never_a_finalized_proposer() {
    let set = set_with_offline(4, &[4]);
    let mut machine = Machine::new(set, 4, SEED, 2, 3);
    let certs = machine.run();
    for cert in &certs {
        assert!(!cert.attesters.contains(&4));
    }
}

#[test]
fn excess_offline_stalls_but_never_slashes() {
    // Two of four offline leaves only two online, below the quorum of three, so
    // no height finalizes, yet no validator is ever slashed.
    let set = set_with_offline(4, &[3, 4]);
    let mut machine = Machine::new(set, 4, SEED, 2, 3);
    let certs = machine.run();
    assert!(certs.is_empty());
    assert!(machine.slashed().is_empty());
}
