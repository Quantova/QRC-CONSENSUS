//! End to end acceptance for real validator key material behind the draw and the

use qtv_attest::aggregate::aggregate;
use qtv_attest::{
    Attester, Beacon, Block, CommitteeCommitment, Parent, Verdict,
};

const STAKE: u64 = 2_000;

// A budget that saturates each member's whole stake share, so a genuine draw is
// always entitled and the finality path is exercised without threshold noise.
const SATURATING_BUDGET: u64 = 100;

#[test]
fn one_secret_drives_the_signing_key_and_the_sortition_root() {
    let secret = [0x5au8; 32];
    let a = Attester::from_secret(1, &secret, STAKE);
    let b = Attester::from_secret(1, &secret, STAKE);
    // The one secret reproduces both published commitments exactly.
    assert_eq!(a.attest_public_key(), b.attest_public_key());
    assert_eq!(a.root(), b.root());
    // A different secret moves both commitments; the id did not determine either.
    let other = Attester::from_secret(1, &[0x5bu8; 32], STAKE);
    assert_ne!(a.attest_public_key(), other.attest_public_key());
    assert_ne!(a.root(), other.root());
}

#[test]
fn a_party_with_only_the_public_key_cannot_forge_an_attestation() {
    // The victim publishes its signing public key as a commitment. An impostor, with
    // the same id and stake but its own secret, signs an attestation for the same
    // block. The impostor's signature verifies under the impostor's own key but not
    // under the victim's published key, so it cannot be presented as the victim's.
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);

    let victim = Attester::from_secret(1, &[0xa1u8; 32], STAKE);
    let impostor = Attester::from_secret(1, &[0xb2u8; 32], STAKE);

    let victim_att = victim.attest(1, 0, 0, block, &beacon);
    assert!(victim_att.signature_verifies(victim.attest_public_key()));

    let forged = impostor.attest(1, 0, 0, block, &beacon);
    assert!(
        !forged.signature_verifies(victim.attest_public_key()),
        "a party holding only the victim public key forged an attestation under it"
    );

    // The impostor's membership reveal also does not authenticate to the victim's
    // published root, so the forgery fails on both facts an attestation carries.
    assert!(!forged.is_entitled(&victim.root(), &beacon, STAKE, STAKE, SATURATING_BUDGET));
    assert!(victim_att.is_entitled(&victim.root(), &beacon, STAKE, STAKE, SATURATING_BUDGET));
}

#[test]
fn an_impostor_certificate_under_the_victim_commitment_is_rejected() {
    // The strongest form of the impersonation attempt: the impostor tries to stand in
    // for the whole committee. It builds attestations under its own secrets while the
    // committee commitment pins the victims' public keys and roots. Verification
    // rejects the certificate: neither the signatures nor the memberships match the
    // published commitments.
    let beacon = Beacon::genesis();
    let block = Block::new(1, [7u8; 32], Parent::Genesis);

    let victims: Vec<Attester> = (1..=4)
        .map(|id| Attester::from_secret(id, &[0xc0u8 + id as u8; 32], STAKE))
        .collect();
    let victim_refs: Vec<&Attester> = victims.iter().collect();
    let commitment = CommitteeCommitment::from_attesters_with_budget(0, &victim_refs, SATURATING_BUDGET);

    // The impostor knows the ids and the public commitment but not the secrets.
    let impostors: Vec<Attester> = (1..=4)
        .map(|id| Attester::from_secret(id, &[0xf0u8 + id as u8; 32], STAKE))
        .collect();
    let forged: Vec<_> = impostors[..3].iter().map(|a| a.attest(1, 0, 0, block, &beacon)).collect();

    // No certificate forms: none of the forged attestations is admitted under the
    // victims' commitment, so an entitled supermajority never assembles.
    assert!(aggregate(1, 0, block, &commitment, &beacon, &forged, 3).is_none());
}

#[test]
fn two_independent_secrets_yield_independent_validators() {
    let beacon = Beacon::genesis();
    let block = Block::new(1, [3u8; 32], Parent::Genesis);

    let a = Attester::from_secret(1, &[0x01u8; 32], STAKE);
    let b = Attester::from_secret(2, &[0x02u8; 32], STAKE);

    assert_ne!(a.attest_public_key(), b.attest_public_key());
    assert_ne!(a.root(), b.root());

    // Neither validator's attestation verifies under the other's key.
    let att_a = a.attest(1, 0, 0, block, &beacon);
    assert!(att_a.signature_verifies(a.attest_public_key()));
    assert!(!att_a.signature_verifies(b.attest_public_key()));
}

#[test]
fn the_draw_and_finality_still_finalize_with_real_keys() {
    // An honest committee built from real per secret keys draws, attests, and
    // finalizes. The threshold is unchanged: aggregation only forms a certificate on
    // an entitled supermajority, and the certificate verifies against the published
    // commitments.
    let beacon = Beacon::genesis();
    let block = Block::new(1, [5u8; 32], Parent::Genesis);

    let members: Vec<Attester> = (1..=4)
        .map(|id| Attester::from_secret(id, &[0x40u8 + id as u8; 32], STAKE))
        .collect();
    let refs: Vec<&Attester> = members.iter().collect();
    let commitment = CommitteeCommitment::from_attesters_with_budget(0, &refs, SATURATING_BUDGET);

    // A genuine supermajority of honest attesters, each holding its own secret.
    let atts: Vec<_> = members[..3].iter().map(|a| a.attest(1, 0, 0, block, &beacon)).collect();
    let cert = aggregate(1, 0, block, &commitment, &beacon, &atts, 3).expect("an honest quorum finalizes");
    assert_eq!(cert.verify(&commitment, &beacon, 3), Verdict::Verified);
    assert_eq!(cert.attesters(), vec![1, 2, 3]);
}
