//! Liveness: once the network is stable, an honest online supermajority makes
//! progress and finalizes every pending height, mirroring the Liveness property
//! stable ~> AllFinalized and the MC_Liveness configuration.

use qtv_bft::machine::Machine;
use qtv_bft::params::supermajority;
use qtv_bft::validator::{Fault, ValidatorSet};

const SEED: [u8; 32] = [0xC0u8; 32];

#[test]
fn honest_supermajority_finalizes_every_height() {
    let mut machine = Machine::new(ValidatorSet::new(4), 4, SEED, 3, 3);
    machine.run();
    assert!(machine.all_finalized());
    assert_eq!(machine.certificates().len(), 3);
}

#[test]
fn finalizes_with_a_tolerated_offline_validator() {
    // MC_Liveness: four validators, one offline, quorum of three, two heights.
    let mut set = ValidatorSet::new(4);
    set.set_fault(4, Fault::Offline);
    let mut machine = Machine::new(set, 4, SEED, 2, 3);
    machine.run();
    assert!(machine.all_finalized());
    assert_eq!(machine.certificates().len(), 2);
}

#[test]
fn view_change_makes_progress_past_a_faulty_leader() {
    // The leader of height 1 view 0 is validator 2. Making it offline forces a
    // view change, after which an honest online leader finalizes the height.
    let mut set = ValidatorSet::new(4);
    set.set_fault(2, Fault::Offline);
    let mut machine = Machine::new(set, 4, SEED, 1, 3);
    assert_eq!(machine.leader_of(1, 0), Some(2));
    machine.run();
    assert!(machine.all_finalized());
    assert!(
        machine.view_of(1) >= 1,
        "the view advanced past the faulty leader"
    );
}

#[test]
fn a_stable_honest_leader_is_never_rotated_past() {
    let mut machine = Machine::new(ValidatorSet::new(4), 4, SEED, 1, 3);
    machine.stabilize();
    // Validator 2 leads height 1 view 0 and is honest and online.
    assert_eq!(machine.leader_of(1, 0), Some(2));
    assert!(
        !machine.timeout(1),
        "a stable honest leader is not timed out"
    );
    assert_eq!(machine.view_of(1), 0);
}

#[test]
fn every_certificate_meets_the_two_thirds_quorum() {
    let mut machine = Machine::new(ValidatorSet::new(4), 4, SEED, 3, 3);
    let certs = machine.run();
    let threshold = supermajority(4);
    for cert in &certs {
        assert!(cert.quorum_size() >= threshold);
    }
}

#[test]
fn a_larger_committee_still_finalizes() {
    let mut machine = Machine::new(ValidatorSet::new(7), 7, SEED, 2, 6);
    let certs = machine.run();
    assert!(machine.all_finalized());
    let threshold = supermajority(7);
    for cert in &certs {
        assert!(cert.quorum_size() >= threshold);
    }
}

#[test]
fn a_prover_never_enters_a_quorum() {
    // A prover holds no vote, so adding one does not change finalization.
    let set = ValidatorSet::new(4).with_prover();
    let mut machine = Machine::new(set, 4, SEED, 2, 3);
    let certs = machine.run();
    assert!(machine.all_finalized());
    for cert in &certs {
        assert!(!cert.attesters.contains(&5), "a prover never attests");
    }
}
