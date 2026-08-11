// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub use qtv_sampler::params::{
    finality_threshold, finality_threshold_for_draw, COMMITTEE_BUDGET, DOMAIN_COMMITTEE,
};
pub use qtv_sampler::sortition::expected_committee;

pub const ATTEST_CONTEXT: &[u8] = b"QORUS-ATTEST-CERT";
