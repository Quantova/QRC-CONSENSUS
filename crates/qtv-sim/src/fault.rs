use crate::validator::{Fault, ValidatorId, ValidatorSet};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaultConfig {
    faults: Vec<(ValidatorId, Fault)>,
}

impl FaultConfig {
    pub fn new() -> Self {
        FaultConfig::default()
    }

    pub fn with(mut self, id: ValidatorId, fault: Fault) -> Self {
        self.faults.retain(|&(other, _)| other != id);
        self.faults.push((id, fault));
        self
    }

    pub fn offline(self, id: ValidatorId) -> Self {
        self.with(id, Fault::Offline)
    }

    pub fn conflicting(self, id: ValidatorId) -> Self {
        self.with(id, Fault::Conflicting)
    }

    pub fn equivocating(self, id: ValidatorId) -> Self {
        self.with(id, Fault::Equivocating)
    }

    pub fn apply(&self, set: &mut ValidatorSet) {
        for &(id, fault) in &self.faults {
            set.set_fault(id, fault);
        }
    }

    pub fn build(&self, count: usize) -> ValidatorSet {
        let mut set = ValidatorSet::new(count);
        self.apply(&mut set);
        set
    }
}
