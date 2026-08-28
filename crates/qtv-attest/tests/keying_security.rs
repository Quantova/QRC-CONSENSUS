// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_attest::aggregate::aggregate;
use qtv_attest::{
    Attester, Beacon, Block, CommitteeCommitment, Parent, Verdict,
};

const STAKE: u64 = 2_000;

const SATURATING_BUDGET: u64 = 100;

#[test]
fn one_secret_drives_the_signing_key_and_the_sortition_root() {
    let secret = [0x5au8; 32];
    let a = Attester::from_secret(1, &secret, STAKE);
    let b = Attester::from_secret(1, &secret, STAKE);
    assert_eq!(a.attest_public_key(), b.attest_public_key());
    assert_eq!(a.root(), b.root());
    let other = Attester::from_secret(1, &[0x5bu8; 32], STAKE);
    assert_ne!(a.attest_public_key(), other.attest_public_key());
    assert_ne!(a.root(), other.root());
}

#[test]
fn a_party_with_only_the_public_key_cannot_forge_an_attestation() {
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);

    let victim = Attester::from_secret(1, &[0xa1u8; 32], STAKE);
    let impostor = Attester::from_secret(1, &[0xb2u8; 32], STAKE);

    let victim_att = victim.attest(1, 1, 0, 0, [0u8; 32], block, &beacon);
    assert!(victim_att.signature_verifies(1, victim.attest_public_key()));

    let forged = impostor.attest(1, 1, 0, 0, [0u8; 32], block, &beacon);
    assert!(
        !forged.signature_verifies(1, victim.attest_public_key()),
        "a party holding only the victim public key forged an attestation under it"
    );

    assert!(!forged.is_entitled(&victim.root(), &beacon, STAKE, STAKE, SATURATING_BUDGET));
    assert!(victim_att.is_entitled(&victim.root(), &beacon, STAKE, STAKE, SATURATING_BUDGET));
}

#[test]
fn an_impostor_certificate_under_the_victim_commitment_is_rejected() {
    let beacon = Beacon::genesis();
    let block = Block::new(1, [7u8; 32], Parent::Genesis);

    let victims: Vec<Attester> = (1..=4)
        .map(|id| Attester::from_secret(id, &[0xc0u8 + id as u8; 32], STAKE))
        .collect();
    let victim_refs: Vec<&Attester> = victims.iter().collect();
    let commitment = CommitteeCommitment::from_attesters_with_budget(0, &victim_refs, SATURATING_BUDGET);

    let impostors: Vec<Attester> = (1..=4)
        .map(|id| Attester::from_secret(id, &[0xf0u8 + id as u8; 32], STAKE))
        .collect();
    let forged: Vec<_> = impostors[..3].iter().map(|a| a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon)).collect();

    assert!(aggregate(1, 1, 0, block, &commitment, &beacon, &forged, 3).is_none());
}

#[test]
fn two_independent_secrets_yield_independent_validators() {
    let beacon = Beacon::genesis();
    let block = Block::new(1, [3u8; 32], Parent::Genesis);

    let a = Attester::from_secret(1, &[0x01u8; 32], STAKE);
    let b = Attester::from_secret(2, &[0x02u8; 32], STAKE);

    assert_ne!(a.attest_public_key(), b.attest_public_key());
    assert_ne!(a.root(), b.root());

    let att_a = a.attest(1, 1, 0, 0, [0u8; 32], block, &beacon);
    assert!(att_a.signature_verifies(1, a.attest_public_key()));
    assert!(!att_a.signature_verifies(1, b.attest_public_key()));
}

#[test]
fn the_draw_and_finality_still_finalize_with_real_keys() {
    let beacon = Beacon::genesis();
    let block = Block::new(1, [5u8; 32], Parent::Genesis);

    let members: Vec<Attester> = (1..=4)
        .map(|id| Attester::from_secret(id, &[0x40u8 + id as u8; 32], STAKE))
        .collect();
    let refs: Vec<&Attester> = members.iter().collect();
    let commitment = CommitteeCommitment::from_attesters_with_budget(0, &refs, SATURATING_BUDGET);

    let atts: Vec<_> = members[..3].iter().map(|a| a.attest(1, 1, 0, 0, commitment.digest(), block, &beacon)).collect();
    let cert = aggregate(1, 1, 0, block, &commitment, &beacon, &atts, 3).expect("an honest quorum finalizes");
    assert_eq!(cert.verify(1, &commitment, &beacon, 3), Verdict::Verified);
    assert_eq!(cert.attesters(), vec![1, 2, 3]);
}
