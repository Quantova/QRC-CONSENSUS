// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::map_clone)]
#![allow(clippy::unnecessary_map_or)]

#[cfg(all(feature = "test-fixtures", not(any(test, debug_assertions))))]
compile_error!("the test-fixtures feature exposes deterministic validator secrets and must never be enabled in a release build");

pub mod beacon;
pub mod committee;
pub mod epoch;
pub use q_vrf::onetime;
pub mod params;
pub mod sortition;
pub mod stake;
pub mod validator;

pub(crate) fn wipe(buf: &mut [u8]) {
    for slot in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(slot, 0u8);
        }
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
