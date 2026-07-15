//! qtv-sampler selects the per slot committee and the leader by verifiable
//! random sortition, following SPEC-consensus-qorus.md and SPEC-vrf.md.
//!
//! A validator draws a verifiable random output over the epoch beacon and its
//! own key with the crypto crate. The construction is the ML-DSA verifiable
//! random function, qtv_crypto::vrf_mldsa, and the draw signs only with the
//! derandomized function of FIPS 204, so the output is a fixed function of the
//! key and the input. That output, weighted by native stake, decides committee
//! membership and proposer eligibility. Because the verifiable random function
//! is deterministic and unforgeable, another node checks the same output and its
//! proof without the private key, so every selection is verifiable.
//!
//! Only native stake counts. An origin tagged bridged asset is never stake. A
//! prover holds zero votes and is never selected. An offline validator that is
//! selected is simply skipped and is never slashed. The committee size is bounded
//! by the resource budget, a consensus parameter.

pub mod beacon;
pub mod committee;
pub mod params;
pub mod sortition;
pub mod stake;
pub mod validator;
