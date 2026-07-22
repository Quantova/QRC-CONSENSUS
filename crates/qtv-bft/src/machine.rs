use std::collections::BTreeMap;

use crate::attest::Attestation;
use crate::block::{Block, Height, Parent, Value};
use crate::certificate::{aggregate, Certificate};
use crate::committee::{leader, sample_committee, View};
use crate::hash::fold;
use crate::message::{Message, Proposal};
use crate::params::MIN_HEIGHT;
use crate::slashing::{slash_from_evidence, EquivocationDetector, Slash, SlashLedger};
use crate::validator::{Fault, ValidatorId, ValidatorSet};

#[derive(Clone, Debug)]
pub struct Machine {
    set: ValidatorSet,
    committee_size: usize,
    genesis_seed: [u8; 32],
    max_height: Height,
    max_view: View,
    msgs: Vec<Message>,
    certs: Vec<Certificate>,
    views: BTreeMap<Height, View>,
    stable: bool,
    detector: EquivocationDetector,
    ledger: SlashLedger,
}

impl Machine {
    pub fn new(
        set: ValidatorSet,
        committee_size: usize,
        genesis_seed: [u8; 32],
        max_height: Height,
        max_view: View,
    ) -> Self {
        let mut views = BTreeMap::new();
        for h in MIN_HEIGHT..=max_height {
            views.insert(h, 0);
        }
        Machine {
            set,
            committee_size,
            genesis_seed,
            max_height,
            max_view,
            msgs: Vec::new(),
            certs: Vec::new(),
            views,
            stable: false,
            detector: EquivocationDetector::new(),
            ledger: SlashLedger::new(),
        }
    }

    pub fn certificates(&self) -> &[Certificate] {
        &self.certs
    }

    pub fn messages(&self) -> &[Message] {
        &self.msgs
    }

    pub fn is_stable(&self) -> bool {
        self.stable
    }

    pub fn view_of(&self, height: Height) -> View {
        *self.views.get(&height).unwrap_or(&0)
    }

    pub fn decided(&self, height: Height) -> bool {
        self.certs.iter().any(|c| c.height == height)
    }

    pub fn final_block_of(&self, height: Height) -> Option<Block> {
        self.certs
            .iter()
            .find(|c| c.height == height)
            .map(|c| c.block)
    }

    fn parent_val(&self, height: Height) -> Parent {
        if height == MIN_HEIGHT {
            Parent::Genesis
        } else {
            match self.final_block_of(height - 1) {
                Some(b) => Parent::Value(b.val),
                None => Parent::Genesis,
            }
        }
    }

    pub fn working(&self, height: Height) -> bool {
        if height < MIN_HEIGHT || height > self.max_height {
            return false;
        }
        if self.decided(height) {
            return false;
        }
        (MIN_HEIGHT..height).all(|g| self.decided(g))
    }

    fn seed_for_height(&self, height: Height) -> [u8; 32] {
        let mut seed = self.genesis_seed;
        let mut h = MIN_HEIGHT;
        while h < height {
            match self.certs.iter().find(|c| c.height == h) {
                Some(cert) => seed = cert.beacon(&seed),
                None => break,
            }
            h += 1;
        }
        seed
    }

    pub fn committee_for(&self, height: Height) -> Vec<ValidatorId> {
        sample_committee(&self.set, &self.seed_for_height(height), self.committee_size)
    }

    pub fn leader_of(&self, height: Height, view: View) -> Option<ValidatorId> {
        leader(&self.committee_for(height), height, view)
    }

    fn is_committee_member(&self, height: Height, id: ValidatorId) -> bool {
        self.committee_for(height).contains(&id)
    }

    fn honest_val(&self, height: Height) -> Value {
        fold(&self.seed_for_height(height), b"HONEST-VAL")
    }

    pub fn honest_block(&self, height: Height) -> Block {
        Block::new(height, self.honest_val(height), self.parent_val(height))
    }

    pub fn valid_block(&self, block: &Block, height: Height) -> bool {
        block.height == height && block.parent == self.parent_val(height) && block.within_budget()
    }

    pub fn voted_for(&self, x: ValidatorId, height: Height, block: &Block) -> bool {
        self.msgs
            .iter()
            .filter_map(|m| m.as_vote())
            .any(|a| a.from == x && a.height == height && &a.block == block)
    }

    fn voted_other(&self, x: ValidatorId, height: Height, block: &Block) -> bool {
        self.msgs
            .iter()
            .filter_map(|m| m.as_vote())
            .any(|a| a.from == x && a.height == height && &a.block != block)
    }

    fn saw_proposal(&self, height: Height, block: &Block) -> bool {
        let view = self.view_of(height);
        self.msgs.iter().filter_map(|m| m.as_proposal()).any(|p| {
            p.height == height
                && &p.block == block
                && p.view <= view
                && self.leader_of(height, p.view) == Some(p.from)
        })
    }

    fn has_message(&self, message: &Message) -> bool {
        self.msgs.contains(message)
    }

    fn votes_for(&self, height: Height, block: &Block) -> Vec<Attestation> {
        self.msgs
            .iter()
            .filter_map(|m| m.as_vote())
            .filter(|a| a.height == height && &a.block == block)
            .cloned()
            .collect()
    }

    pub fn honest_propose(&mut self, height: Height) -> bool {
        if !self.working(height) {
            return false;
        }
        let view = self.view_of(height);
        let l = match self.leader_of(height, view) {
            Some(l) => l,
            None => return false,
        };
        if self.set.fault_of(l) != Fault::Honest {
            return false;
        }
        let block = self.honest_block(height);
        let message = Message::Propose(Proposal {
            from: l,
            height,
            view,
            block,
        });
        if self.has_message(&message) {
            return false;
        }
        self.msgs.push(message);
        true
    }

    pub fn byz_propose(&mut self, height: Height, block: Block) -> bool {
        if !self.working(height) || block.height != height {
            return false;
        }
        let view = self.view_of(height);
        let l = match self.leader_of(height, view) {
            Some(l) => l,
            None => return false,
        };
        if self.set.fault_of(l) != Fault::Byzantine {
            return false;
        }
        let message = Message::Propose(Proposal {
            from: l,
            height,
            view,
            block,
        });
        if self.has_message(&message) {
            return false;
        }
        self.msgs.push(message);
        true
    }

    pub fn vote(&mut self, x: ValidatorId, height: Height, block: Block) -> bool {
        if !self.working(height) {
            return false;
        }
        if self.set.fault_of(x) != Fault::Honest || !self.is_committee_member(height, x) {
            return false;
        }
        if !self.valid_block(&block, height)
            || !self.saw_proposal(height, &block)
            || self.voted_other(x, height, &block)
        {
            return false;
        }
        let validator = match self.set.get(x) {
            Some(v) => v,
            None => return false,
        };
        let attestation = Attestation::create(validator, height, block);
        let message = Message::vote(attestation.clone());
        if self.has_message(&message) {
            return false;
        }
        self.msgs.push(message);
        self.detect_and_slash(&attestation);
        true
    }

    pub fn byz_vote(&mut self, x: ValidatorId, height: Height, block: Block) -> bool {
        if !self.working(height) || block.height != height {
            return false;
        }
        if self.set.fault_of(x) != Fault::Byzantine || !self.is_committee_member(height, x) {
            return false;
        }
        let validator = match self.set.get(x) {
            Some(v) => v,
            None => return false,
        };
        let attestation = Attestation::create(validator, height, block);
        let message = Message::vote(attestation.clone());
        if self.has_message(&message) {
            return false;
        }
        self.msgs.push(message);
        self.detect_and_slash(&attestation);
        true
    }

    /// Feed one attestation to the runtime detector as it is admitted. When it completes
    fn detect_and_slash(&mut self, attestation: &Attestation) {
        if let Some(evidence) = self.detector.observe(attestation) {
            if let Some(slash) = slash_from_evidence(&evidence, &self.set) {
                self.ledger.apply(slash);
            }
        }
    }

    pub fn slashes(&self) -> &[Slash] {
        self.ledger.slashes()
    }

    pub fn is_slashed(&self, id: ValidatorId) -> bool {
        self.ledger.is_banned(id)
    }

    pub fn finalize(&mut self, height: Height, block: Block) -> bool {
        if height < MIN_HEIGHT || height > self.max_height {
            return false;
        }
        if !(MIN_HEIGHT..height).all(|g| self.decided(g)) {
            return false;
        }
        let committee = self.committee_for(height);
        let attestations = self.votes_for(height, &block);
        if let Some(cert) = aggregate(height, block, &committee, &attestations, &self.set) {
            if !self.certs.contains(&cert) {
                self.certs.push(cert);
                return true;
            }
        }
        false
    }

    pub fn timeout(&mut self, height: Height) -> bool {
        if !self.working(height) || self.view_of(height) >= self.max_view {
            return false;
        }
        if self.stable {
            let l = self.leader_of(height, self.view_of(height));
            let rotate = matches!(
                l.map(|id| self.set.fault_of(id)),
                Some(Fault::Offline) | Some(Fault::Byzantine)
            );
            if !rotate {
                return false;
            }
        }
        let v = self.view_of(height);
        self.views.insert(height, v + 1);
        true
    }

    pub fn stabilize(&mut self) -> bool {
        if self.stable {
            return false;
        }
        self.stable = true;
        true
    }

    pub fn slashed(&self) -> Vec<ValidatorId> {
        let attestations: Vec<Attestation> = self
            .msgs
            .iter()
            .filter_map(|m| m.as_vote())
            .cloned()
            .collect();
        crate::equivocation::equivocators(&attestations)
    }

    pub fn all_finalized(&self) -> bool {
        (MIN_HEIGHT..=self.max_height).all(|h| self.decided(h))
    }

    pub fn advance_height(&mut self, height: Height) -> bool {
        loop {
            if self.decided(height) {
                return true;
            }
            let view = self.view_of(height);
            let l = match self.leader_of(height, view) {
                Some(l) => l,
                None => return false,
            };
            if self.set.fault_of(l) == Fault::Honest {
                self.honest_propose(height);
                let block = self.honest_block(height);
                for x in self.committee_for(height) {
                    if self.set.fault_of(x) == Fault::Honest {
                        self.vote(x, height, block);
                    }
                }
                self.finalize(height, block);
                if self.decided(height) {
                    return true;
                }
            }
            if !self.timeout(height) {
                return false;
            }
        }
    }

    pub fn run(&mut self) -> Vec<Certificate> {
        self.stabilize();
        for height in MIN_HEIGHT..=self.max_height {
            if !self.advance_height(height) {
                break;
            }
        }
        let mut certs = self.certs.clone();
        certs.sort_by_key(|c| c.height);
        certs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_matches_the_model() {
        let m = Machine::new(ValidatorSet::new(4), 4, [192u8; 32], 2, 3);
        assert!(m.messages().is_empty());
        assert!(m.certificates().is_empty());
        assert!(!m.is_stable());
        assert_eq!(m.view_of(1), 0);
        assert_eq!(m.view_of(2), 0);
    }

    #[test]
    fn honest_run_finalizes_every_height_in_order() {
        let mut m = Machine::new(ValidatorSet::new(4), 4, [192u8; 32], 3, 3);
        let certs = m.run();
        assert_eq!(certs.len(), 3);
        assert_eq!(certs[0].height, 1);
        assert_eq!(certs[1].height, 2);
        assert_eq!(certs[2].height, 3);
        assert!(m.all_finalized());
        assert!(m.slashed().is_empty());
    }

    #[test]
    fn each_finalized_block_descends_from_the_one_below() {
        let mut m = Machine::new(ValidatorSet::new(4), 4, [18u8; 32], 3, 3);
        let certs = m.run();
        assert_eq!(certs[0].block.parent, Parent::Genesis);
        for pair in certs.windows(2) {
            assert_eq!(pair[1].block.parent, Parent::Value(pair[0].block.val));
        }
    }

    #[test]
    fn timeout_rotates_past_a_byzantine_leader_when_stable() {
        let mut set = ValidatorSet::new(4);
        set.set_fault(2, Fault::Byzantine);
        let mut m = Machine::new(set, 4, [192u8; 32], 1, 3);
        assert_eq!(m.leader_of(1, 0), Some(2));
        let certs = m.run();
        assert_eq!(certs.len(), 1);
        assert!(m.view_of(1) >= 1);
    }

    #[test]
    fn a_runtime_equivocator_is_detected_and_slashed_while_peers_are_not() {
        let mut set = ValidatorSet::new(4);
        set.set_fault(2, Fault::Byzantine);
        let mut m = Machine::new(set, 4, [5u8; 32], 1, 3);
        m.stabilize();
        assert!(m.committee_for(1).contains(&2));

        let first = Block::new(1, [1u8; 32], Parent::Genesis);
        let second = Block::new(1, [2u8; 32], Parent::Genesis);
        assert!(m.byz_vote(2, 1, first));
        assert!(m.slashes().is_empty(), "one vote is not yet a fault");
        assert!(m.byz_vote(2, 1, second));

        assert!(m.is_slashed(2), "the equivocator is slashed live as its second vote lands");
        assert_eq!(m.slashes().len(), 1);
        assert_eq!(m.slashes()[0].validator, 2);
        for peer in [1u64, 3, 4] {
            assert!(!m.is_slashed(peer), "an honest peer must never be slashed");
        }
    }

    #[test]
    fn an_honest_run_slashes_nobody() {
        let mut m = Machine::new(ValidatorSet::new(4), 4, [42u8; 32], 3, 3);
        m.run();
        assert!(m.all_finalized());
        assert!(m.slashes().is_empty());
    }
}
