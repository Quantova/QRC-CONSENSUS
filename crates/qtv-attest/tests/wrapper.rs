//! The staged wrapper carries a stage one body and a placeholder stage two body
//! over one and the same envelope. The stage one body verifies in full. The stage
//! two body is pending without a succinct verifier, and the typed seam decides it
//! once a verifier is supplied, standing in for the prover.

use qtv_attest::aggregate::aggregate;
use qtv_attest::verify::RejectReason;
use qtv_attest::{
    Attester, Beacon, Block, Certificate, CommitteeCommitment, Envelope, Parent, Stage, Stage2Body,
    SuccinctProof, SuccinctVerifier, Verdict,
};

// A stand in for the prover's stage two verifier that accepts every proof.
struct AcceptAll;
impl SuccinctVerifier for AcceptAll {
    fn verify(&self, _e: &Envelope, _b: &Stage2Body, _c: &CommitteeCommitment) -> bool {
        true
    }
}

// A stand in that rejects every proof.
struct RejectAll;
impl SuccinctVerifier for RejectAll {
    fn verify(&self, _e: &Envelope, _b: &Stage2Body, _c: &CommitteeCommitment) -> bool {
        false
    }
}

#[test]
fn the_wrapper_round_trips_both_bodies_through_one_envelope() {
    let members: Vec<Attester> = (1..=4).map(|id| Attester::new(id, 100)).collect();
    let refs: Vec<&Attester> = members.iter().collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, 9, Parent::Genesis);
    let commitment = CommitteeCommitment::from_attesters(0, &refs);

    let atts: Vec<_> = members[..3]
        .iter()
        .map(|a| a.attest(1, 0, block, &beacon))
        .collect();
    let stage_one = aggregate(1, 0, block, &commitment, &beacon, &atts).expect("quorum");

    // The stage two certificate reuses the very same envelope.
    let envelope: Envelope = stage_one.envelope.clone();
    let stage_two = Certificate::stage_two(
        envelope.clone(),
        3,
        SuccinctProof {
            bytes: vec![0u8; 8],
        },
    );
    assert_eq!(stage_one.envelope, stage_two.envelope);
    assert_eq!(stage_one.stage(), Stage::One);
    assert_eq!(stage_two.stage(), Stage::Two);

    // Stage one verifies fully from public inputs.
    assert!(stage_one.verify(&commitment, &beacon).is_verified());

    // Stage two is pending without a verifier, never silently accepted.
    assert_eq!(
        stage_two.verify(&commitment, &beacon),
        Verdict::StageTwoPending
    );

    // The typed seam decides stage two once a verifier is supplied.
    assert!(stage_two
        .verify_with(&commitment, &beacon, &AcceptAll)
        .is_verified());
    assert_eq!(
        stage_two.verify_with(&commitment, &beacon, &RejectAll),
        Verdict::Rejected(RejectReason::SuccinctProof)
    );
}
