//! The authenticated messages of the protocol: proposals from a leader and
//! attestations from committee members. Together they form the growing message
//! set, mirroring the msgs variable of the formal model, which holds propose
//! and vote records.

use crate::attest::Attestation;
use crate::block::{Block, Height};
use crate::committee::View;
use crate::validator::ValidatorId;

/// A block proposed by the leader of a height and view. Mirrors a propose
/// record [kind, from, height, view, block].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub from: ValidatorId,
    pub height: Height,
    pub view: View,
    pub block: Block,
}

/// An authenticated protocol message. A vote carries a real attestation, boxed
/// because an ML-DSA signature is large next to a proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Propose(Proposal),
    Vote(Box<Attestation>),
}

impl Message {
    /// Build a vote message from an attestation.
    pub fn vote(attestation: Attestation) -> Self {
        Message::Vote(Box::new(attestation))
    }
}

impl Message {
    pub fn from(&self) -> ValidatorId {
        match self {
            Message::Propose(p) => p.from,
            Message::Vote(a) => a.from,
        }
    }

    pub fn height(&self) -> Height {
        match self {
            Message::Propose(p) => p.height,
            Message::Vote(a) => a.height,
        }
    }

    pub fn is_propose(&self) -> bool {
        matches!(self, Message::Propose(_))
    }

    pub fn is_vote(&self) -> bool {
        matches!(self, Message::Vote(_))
    }

    pub fn as_vote(&self) -> Option<&Attestation> {
        match self {
            Message::Vote(a) => Some(a.as_ref()),
            _ => None,
        }
    }

    pub fn as_proposal(&self) -> Option<&Proposal> {
        match self {
            Message::Propose(p) => Some(p),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::Attestation;
    use crate::block::Parent;
    use crate::validator::Validator;

    #[test]
    fn proposal_message_reports_origin_and_height() {
        let block = Block::new(1, 3, Parent::Genesis);
        let m = Message::Propose(Proposal {
            from: 2,
            height: 1,
            view: 0,
            block,
        });
        assert_eq!(m.from(), 2);
        assert_eq!(m.height(), 1);
        assert!(m.is_propose());
        assert!(m.as_vote().is_none());
    }

    #[test]
    fn vote_message_wraps_an_attestation() {
        let v = Validator::new(1);
        let block = Block::new(1, 3, Parent::Genesis);
        let att = Attestation::create(&v, 1, block);
        let m = Message::vote(att);
        assert_eq!(m.from(), 1);
        assert!(m.is_vote());
        assert!(m.as_proposal().is_none());
    }
}
