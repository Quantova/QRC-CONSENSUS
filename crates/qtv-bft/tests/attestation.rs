//! Attestations use real module lattice signatures. A genuine attestation

use qtv_bft::attest::Attestation;
use qtv_bft::block::{Block, Parent};
use qtv_bft::certificate::aggregate;
use qtv_bft::machine::Machine;
use qtv_bft::validator::{Validator, ValidatorSet};

const SEED: u64 = 0xC0FFEE;

#[test]
fn genuine_attestation_verifies() {
    let v = Validator::new(1);
    let block = Block::new(1, 42, Parent::Genesis);
    let att = Attestation::create(&v, 1, block);
    assert!(att.verify(v.public_key()));
}

#[test]
fn forged_signature_is_rejected() {
    let v = Validator::new(1);
    let block = Block::new(1, 42, Parent::Genesis);
    let mut att = Attestation::create(&v, 1, block);
    att.sig[100] ^= 0x01;
    assert!(!att.verify(v.public_key()));
}

#[test]
fn attestation_does_not_verify_under_another_validator_key() {
    let signer = Validator::new(1);
    let other = Validator::new(2);
    let block = Block::new(1, 42, Parent::Genesis);
    let att = Attestation::create(&signer, 1, block);
    assert!(!att.verify(other.public_key()));
}

#[test]
fn a_forged_attestation_cannot_complete_a_quorum() {
    let set = ValidatorSet::new(4);
    let committee = vec![1, 2, 3, 4];
    let block = Block::new(1, 42, Parent::Genesis);
    // Two genuine attestations, one short of the quorum of three.
    let mut atts: Vec<Attestation> = [1u64, 2]
        .iter()
        .map(|&id| Attestation::create(set.get(id).unwrap(), 1, block))
        .collect();
    // A forged third attestation must not close the gap.
    let mut forged = Attestation::create(set.get(3).unwrap(), 1, block);
    forged.sig[0] ^= 0xff;
    atts.push(forged);
    assert!(aggregate(1, block, &committee, &atts, &set).is_none());
}

#[test]
fn every_attestation_behind_a_certificate_verifies() {
    let mut machine = Machine::new(ValidatorSet::new(4), 4, SEED, 2, 3);
    let certs = machine.run();
    assert!(!certs.is_empty());
    let set = ValidatorSet::new(4);
    for message in machine.messages() {
        if let Some(att) = message.as_vote() {
            let key = set.public_key(att.from).expect("committee key");
            assert!(att.verify(key), "attestation from {} must verify", att.from);
        }
    }
}
