// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qtv_bft::block::{Block, Parent};
use qtv_bft::certificate::Certificate;
use qtv_bft::machine::Machine;
use qtv_bft::validator::{Fault, ValidatorSet};

fn agreement_holds(certs: &[Certificate]) -> bool {
    for a in certs {
        for b in certs {
            if a.height == b.height && a.block != b.block {
                return false;
            }
        }
    }
    true
}

fn byzantine_set() -> ValidatorSet {
    let mut set = ValidatorSet::new(4);
    set.set_fault(2, Fault::Byzantine);
    set
}

fn drive_equivocation(seed: [u8; 32], honest_for_a: [bool; 3]) -> Machine {
    let mut machine = Machine::new(byzantine_set(), 4, seed, 1, 1);
    machine.stabilize();

    assert_eq!(machine.leader_of(1, 0), Some(2));

    let block_a = Block::new(1, [100u8; 32], Parent::Genesis);
    let block_b = Block::new(1, [200u8; 32], Parent::Genesis);

    assert!(machine.byz_propose(1, block_a));
    assert!(machine.byz_propose(1, block_b));

    machine.byz_vote(2, 1, block_a);
    machine.byz_vote(2, 1, block_b);

    let honest = [1u64, 3, 4];
    for (i, &id) in honest.iter().enumerate() {
        let block = if honest_for_a[i] { block_a } else { block_b };
        machine.vote(id, 1, block);
    }

    machine.finalize(1, block_a);
    machine.finalize(1, block_b);
    machine
}

#[test]
fn agreement_holds_across_every_honest_split() {
    for seed in [[192u8; 32], [1u8; 32], [2u8; 32], [222u8; 32], [153u8; 32]] {
        for mask in 0..8u8 {
            let split = [mask & 1 != 0, mask & 2 != 0, mask & 4 != 0];
            let machine = drive_equivocation(seed, split);
            let certs = machine.certificates();
            assert!(
                agreement_holds(certs),
                "conflicting finalization at seed {seed:?} split {split:?}"
            );
            let mut blocks: Vec<_> = certs.iter().map(|c| c.block).collect();
            blocks.dedup();
            assert!(blocks.len() <= 1);
        }
    }
}

#[test]
fn a_two_thirds_honest_split_still_finalizes() {
    let machine = drive_equivocation([192u8; 32], [true, true, false]);
    let certs = machine.certificates();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].block.val, [100u8; 32]);
    assert!(agreement_holds(certs));
}

#[test]
fn the_equivocator_is_the_only_slashed_validator() {
    let machine = drive_equivocation([192u8; 32], [true, false, false]);
    let slashed = machine.slashed();
    assert_eq!(slashed, vec![2]);
    assert!(slashed.iter().all(|&id| id == 2));
}

#[test]
fn honest_leader_run_never_conflicts_over_many_seeds() {
    for n in 0..12u8 {
        let seed = [n; 32];
        let mut machine = Machine::new(ValidatorSet::new(4), 4, seed, 3, 3);
        machine.run();
        assert!(agreement_holds(machine.certificates()));
        assert!(machine.slashed().is_empty());
    }
}
