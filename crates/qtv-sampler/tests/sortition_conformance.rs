//! Conformance vector for the ML-DSA derandomized sortition draw.

use qtv_crypto::ml_dsa;
use qtv_crypto::sha3::shake256;
use qtv_crypto::vrf_mldsa;
use qtv_sampler::beacon::Beacon;
use qtv_sampler::params::DOMAIN_COMMITTEE;
use qtv_sampler::sortition::draw;
use qtv_sampler::validator::SamplerValidator;

// The sortition output is the fixed length SHAKE256 digest of the proof, matching
// how the crypto crate derives a VRF output from its proof. This lets the vector
// score a hedged signature the same way a derandomized proof is scored.
fn sortition_output(proof: &[u8; vrf_mldsa::PROOF_BYTES]) -> [u8; vrf_mldsa::OUTPUT_BYTES] {
    let mut out = [0u8; vrf_mldsa::OUTPUT_BYTES];
    shake256(proof, &mut out);
    out
}

#[test]
fn a_draw_is_deterministic_for_a_fixed_key_and_input() {
    let validator = SamplerValidator::new(1, 2_000);
    let beacon = Beacon::genesis();

    let first = draw(&validator, &beacon, DOMAIN_COMMITTEE, 0);
    let second = draw(&validator, &beacon, DOMAIN_COMMITTEE, 0);

    assert_eq!(first.output, second.output);
    assert_eq!(&first.proof[..], &second.proof[..]);
    assert_eq!(first.value(), second.value());
}

#[test]
fn a_different_randomizer_yields_a_different_sortition_output() {
    // A fixed key pair and a fixed sortition input.
    let (sk, pk) = vrf_mldsa::keygen(b"QORUS conformance sortition key");
    let beacon = Beacon::genesis();
    let input = beacon.sortition_input(DOMAIN_COMMITTEE, 0);

    // The derandomized draw is the sortition output the protocol scores, and it is
    // stable across evaluations.
    let (derandomized_output, _proof) = vrf_mldsa::prove(&sk, &input);
    let (again, _) = vrf_mldsa::prove(&sk, &input);
    assert_eq!(derandomized_output, again);

    // The same key and input signed with a non zero randomizer is a hedged
    // signature, and its sortition output differs from the derandomized one. This
    // is why an unrestricted randomizer would let a validator grind for a lower
    // draw, and why the draw signs only with the derandomized function.
    let hedged = ml_dsa::sign_internal(&sk, &input, &[1u8; 32]);
    let hedged_output = sortition_output(&hedged);
    assert_ne!(hedged_output, derandomized_output);

    // The boundary that is not yet closed. The hedged signature still verifies as
    // a valid ML-DSA signature over the input, so a verifier cannot reject it at
    // verification time. Grinding resistance that a light client can check needs
    // the derivation proof and is deferred.
    assert!(ml_dsa::verify_internal(&pk, &input, &hedged));
}
