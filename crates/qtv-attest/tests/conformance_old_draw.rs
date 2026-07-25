//! Conformance vector: the consensus verification rejects a draw made by the old

use qtv_attest::aggregate::aggregate;
use qtv_attest::verify::RejectReason;
use qtv_attest::{
    Attester, Beacon, Block, Certificate, CommitteeCommitment, Envelope, Parent, Verdict,
};
use qtv_sampler::committee::verify_leader;
use qtv_sampler::onetime::MerklePath;
use qtv_sampler::sortition::Credential;
use qtv_sampler::validator::SamplerValidator;

/// A budget that saturates each member's whole stake share, so a genuine one time
const BUDGET: u64 = 4;

/// The self stake floor. Members are staked at the floor so they are eligible
const STAKE: u64 = 2_000;

fn committee(members: &[Attester]) -> CommitteeCommitment {
    let refs: Vec<&Attester> = members.iter().collect();
    CommitteeCommitment::from_attesters_with_budget(0, &refs, BUDGET)
}

/// A credential shaped like an old mechanism draw: a fabricated preimage and path
fn old_style_draw(slot: u64) -> Credential {
    let depth = SamplerValidator::new(999, STAKE).reveal(slot).path.siblings.len();
    Credential {
        position: slot,
        preimage: [171; 32],
        path: MerklePath {
            siblings: vec![[205; 32]; depth],
        },
    }
}

#[test]
fn the_consensus_verification_rejects_an_old_mechanism_membership_draw() {
    let members: Vec<Attester> = (1..=4).map(|id| Attester::new(id, STAKE)).collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);
    let commitment = committee(&members);

    // Positive control: a quorum carrying genuine one time credentials verifies.
    let mut atts: Vec<_> = members[..3]
        .iter()
        .map(|a| a.attest(1, 0, 0, block, &beacon))
        .collect();
    let good = Certificate::new(Envelope::new(1, 0, block, &commitment), atts.clone());
    assert_eq!(good.verify(&commitment, &beacon, 3), Verdict::Verified);

    // Replace one member's one time credential with an old style draw that has no
    // Merkle path to its registered root. The module lattice signature still
    // verifies, but the membership no longer authenticates, so the consensus
    // rejects the certificate as not entitled instead of finalizing it.
    atts[0].membership = old_style_draw(0);
    let bad = Certificate::new(Envelope::new(1, 0, block, &commitment), atts);
    assert_eq!(
        bad.verify(&commitment, &beacon, 3),
        Verdict::Rejected(RejectReason::NotEntitled)
    );
}

#[test]
fn aggregation_drops_an_old_mechanism_membership_draw() {
    let members: Vec<Attester> = (1..=4).map(|id| Attester::new(id, STAKE)).collect();
    let beacon = Beacon::genesis();
    let block = Block::new(1, [9u8; 32], Parent::Genesis);
    let commitment = committee(&members);

    // Three genuine one time draws are an entitled supermajority and aggregate.
    let genuine: Vec<_> = members[..3]
        .iter()
        .map(|a| a.attest(1, 0, 0, block, &beacon))
        .collect();
    assert!(aggregate(1, 0, block, &commitment, &beacon, &genuine, 3).is_some());

    // With one of the three carrying an old style draw, only two entitled signers
    // remain, below the supermajority of three, so no certificate forms: the old
    // draw is dropped rather than counted toward finality.
    let mut atts = genuine;
    atts[0].membership = old_style_draw(0);
    assert!(aggregate(1, 0, block, &commitment, &beacon, &atts, 3).is_none());
}

#[test]
fn leader_eligibility_rejects_an_old_mechanism_draw() {
    // A proposer proves eligibility with its one time credential against its own
    // registered root. An old style draw with no path to that root is not a valid
    // proposer eligibility proof, so leadership is bound to the one time credential
    // exactly as membership is.
    let leader = SamplerValidator::new(1, STAKE);
    let root = leader.root();
    let genuine = leader.reveal(0);
    assert!(verify_leader(&root, 0, &genuine));
    assert!(!verify_leader(&root, 0, &old_style_draw(0)));
}
