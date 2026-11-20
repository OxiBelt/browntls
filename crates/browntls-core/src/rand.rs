//! Helpers over the provider's random source.

use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::SecureRandom;

/// The random source failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetRandomFailed;

impl core::fmt::Display for GetRandomFailed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("failed to get random bytes")
    }
}

impl core::error::Error for GetRandomFailed {}

pub(crate) fn random_vec(rng: &dyn SecureRandom, len: usize) -> Result<Vec<u8>, GetRandomFailed> {
    let mut v = vec![0u8; len];
    rng.fill(&mut v)?;
    Ok(v)
}

pub(crate) fn random_u32(rng: &dyn SecureRandom) -> Result<u32, GetRandomFailed> {
    let mut buf = [0u8; 4];
    rng.fill(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}
