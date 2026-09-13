use qtv_sampler::beacon::Beacon;
use qtv_sampler::committee::CommitteeView;
use qtv_sampler::onetime::{MerklePath, Root};
use qtv_sampler::params::MIN_SELF_STAKE;
use qtv_sampler::sortition::Credential;
use qtv_sampler::validator::{Registration, ValidatorId};
use std::time::Instant;

fn roster(n: u64) -> CommitteeView {
    CommitteeView::new(
        (1..=n)
            .map(|i| Registration {
                id: i as ValidatorId,
                weight: MIN_SELF_STAKE + i,
                root: Root {
                    digest: [0u8; 32],
                    slots: 1,
                },
            })
            .collect(),
    )
}

fn main() {
    let cred = Credential {
        position: 0,
        preimage: [0u8; 32],
        path: MerklePath {
            siblings: Vec::new(),
        },
    };
    let beacon = Beacon::genesis();
    for n in [100u64, 1_000, 5_000, 10_000] {
        let v = roster(n);
        let reps = 2_000;
        let t = Instant::now();
        for _ in 0..reps {
            std::hint::black_box(v.admits(&beacon, 1, u32::MAX as ValidatorId, &cred));
        }
        let us = t.elapsed().as_secs_f64() * 1e6 / reps as f64;
        println!("roster {:>6}  garbage-id admit {:>9.2} us", n, us);
    }
}
