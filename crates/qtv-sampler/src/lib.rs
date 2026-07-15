//! qtv-sampler selects the per slot committee and the leader by grinding
//! resistant sortition, following SPEC-sortition-onetime.md and SPEC-vrf.md.
//!
//! Each staking account commits, at registration and bonded to its stake, the
//! Merkle root of a tree of one time preimages, one leaf per slot. For a slot the
//! account's sortition output is the deterministic hash, over SHA3 and SHAKE from
//! the crypto crate, of its preimage at that position and the beacon of the slot.
//! The credential is that preimage with its Merkle path to the registered root.
//! The account is a committee member when the output falls below a stake weighted
//! threshold, exactly as before. There is no randomizer, so there is nothing to re
//! roll: the grinding budget is one draw per bonded account per slot, enforced by
//! position and by the tree being committed before any beacon is known.
//!
//! Committee membership is stake neutral under splitting because the threshold
//! scales with stake. Leadership is made stake neutral by a sub weight exponential
//! race, so splitting a stake across accounts does not raise the chance of
//! leading. The two attributable faults, a preimage out of position and two draws
//! for one slot, leave evidence any node checks from the registered root.
//!
//! Only native stake counts. An origin tagged bridged asset is never stake. A
//! prover holds zero votes and is never selected. An offline account that is
//! selected is simply skipped and is never slashed. The committee size is bounded
//! by the resource budget, a consensus parameter.

pub mod beacon;
pub mod committee;
pub mod evidence;
pub mod onetime;
pub mod params;
pub mod sortition;
pub mod stake;
pub mod validator;
