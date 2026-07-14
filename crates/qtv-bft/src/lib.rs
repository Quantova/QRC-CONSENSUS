//! qtv-bft is the QORUS stage one byzantine fault tolerant core, implemented as
//! a deterministic state machine that mirrors the verified formal model in
//! formal/QorusBFT.tla and follows SPEC-consensus-qorus.md.
//!
//! A committee decides one block per height. A deterministic leader proposes,
//! committee members attest with a real module lattice signature, and a
//! supermajority of two thirds plus one aggregates into a single finality
//! certificate. Timeouts drive view changes under partial synchrony. Offline
//! validators are skipped and never slashed. Provers hold no vote. Attestations
//! and the certificate use ML-DSA only, per the frozen consensus decision.
//!
//! Each state machine action in `machine` corresponds to an action of the
//! `Next` relation in the formal model, so a reviewer can line the two up.
