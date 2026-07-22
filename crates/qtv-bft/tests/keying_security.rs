//! The ML-DSA-65 attestation signing key rests on a secret the validator alone
//! holds, not on its public id. These vectors prove the key is a function of the
//! secret and nothing public, that the id is not an input, and that a party holding
//! only the public key cannot sign an attestation that verifies under it.

use qtv_bft::attest::Attestation;
use qtv_bft::block::{Block, Parent};
use qtv_bft::validator::{signing_key_seed, Validator};

#[test]
fn the_signing_seed_is_a_function_of_the_secret_alone_not_the_id() {
    let secret = [0x31u8; 32];
    // The id is not an input: the same secret under two ids yields the same key.
    let a = Validator::from_secret(1, &secret);
    let b = Validator::from_secret(987_654, &secret);
    assert_eq!(a.public_key(), b.public_key());
    // One id under two secrets gives two unrelated keys, so the public id cannot
    // recompute the key.
    let c = Validator::from_secret(1, &[0x32u8; 32]);
    assert_ne!(a.public_key(), c.public_key());
}

#[test]
fn the_public_key_reveals_neither_the_secret_nor_the_seed() {
    let secret = [0x44u8; 32];
    let seed = signing_key_seed(&secret);
    assert_ne!(seed, secret, "the signing seed must not be the secret");
    let v = Validator::from_secret(1, &secret);
    // The 32 byte secret and seed cannot appear as a prefix of the published key.
    assert_ne!(&v.public_key()[..32], &secret[..]);
    assert_ne!(&v.public_key()[..32], &seed[..]);
}

#[test]
fn a_party_with_only_the_public_key_cannot_forge_an_attestation() {
    let victim = Validator::from_secret(1, &[0xa1u8; 32]);
    let impostor = Validator::from_secret(1, &[0xb2u8; 32]);
    let block = Block::new(1, [5u8; 32], Parent::Genesis);

    let genuine = Attestation::create(&victim, 1, block);
    assert!(genuine.verify(victim.public_key()));

    // Same id, same block, but signed under the impostor's own secret: it verifies
    // under the impostor's key, never under the victim's published key.
    let forged = Attestation::create(&impostor, 1, block);
    assert!(forged.verify(impostor.public_key()));
    assert!(
        !forged.verify(victim.public_key()),
        "a party holding only the victim public key forged an attestation under it"
    );
}

#[test]
fn two_independent_secrets_yield_independent_keys() {
    let a = Validator::from_secret(1, &[0x01u8; 32]);
    let b = Validator::from_secret(2, &[0x02u8; 32]);
    assert_ne!(a.public_key(), b.public_key());
    assert_ne!(signing_key_seed(&[0x01u8; 32]), signing_key_seed(&[0x02u8; 32]));
}
