pub type ValidatorId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Honest,
    Offline,
    Conflicting,
    Equivocating,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validator {
    pub id: ValidatorId,
    pub fault: Fault,
}

impl Validator {
    pub fn new(id: ValidatorId) -> Self {
        Validator {
            id,
            fault: Fault::Honest,
        }
    }

    pub fn is_offline(&self) -> bool {
        self.fault == Fault::Offline
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
}

impl ValidatorSet {
    pub fn new(count: usize) -> Self {
        let validators = (0..count as u64).map(Validator::new).collect();
        ValidatorSet { validators }
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    pub fn ids(&self) -> Vec<ValidatorId> {
        self.validators.iter().map(|v| v.id).collect()
    }

    pub fn get(&self, id: ValidatorId) -> Option<&Validator> {
        self.validators.iter().find(|v| v.id == id)
    }

    pub fn fault_of(&self, id: ValidatorId) -> Fault {
        self.get(id).map(|v| v.fault).unwrap_or(Fault::Honest)
    }

    pub fn set_fault(&mut self, id: ValidatorId, fault: Fault) {
        if let Some(v) = self.validators.iter_mut().find(|v| v.id == id) {
            v.fault = fault;
        }
    }
}
