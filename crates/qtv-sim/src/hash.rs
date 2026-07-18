//! Deterministic mixing used by committee sampling and beacon rotation.
//! Standard library only, stable across runs and platforms.

pub fn mix64(mut x: u64) -> u64 {
    x = x.wrapping_add(11400714819323198485);
    x = (x ^ (x >> 30)).wrapping_mul(13787848793156543929);
    x = (x ^ (x >> 27)).wrapping_mul(10723151780598845931);
    x ^ (x >> 31)
}

pub fn combine(a: u64, b: u64) -> u64 {
    mix64(a ^ mix64(b))
}
