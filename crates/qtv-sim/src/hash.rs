//! Deterministic mixing used by committee sampling and beacon rotation.
//! Standard library only, stable across runs and platforms.

pub fn mix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

pub fn combine(a: u64, b: u64) -> u64 {
    mix64(a ^ mix64(b))
}
