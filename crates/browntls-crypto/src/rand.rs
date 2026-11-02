//! Randomness sources.

use crate::Error;

/// A cryptographically secure random byte source.
pub trait SecureRandom {
    /// Fills `dest` with random bytes.
    fn fill(&self, dest: &mut [u8]) -> Result<(), Error>;
}

/// Operating-system entropy.
///
/// * Linux on x86-64, aarch64 and riscv64: the `getrandom(2)` system call,
///   issued directly (no libc).
/// * Other targets: the `getrandom` crate when the `getrandom` feature is
///   enabled.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRng;

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )
))]
impl SecureRandom for OsRng {
    fn fill(&self, dest: &mut [u8]) -> Result<(), Error> {
        crate::sys::getrandom(dest).map_err(|_| Error::RandomFailure)
    }
}

#[cfg(all(
    feature = "getrandom",
    not(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ))
))]
impl SecureRandom for OsRng {
    fn fill(&self, dest: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(dest).map_err(|_| Error::RandomFailure)
    }
}

impl<R: SecureRandom + ?Sized> SecureRandom for &R {
    fn fill(&self, dest: &mut [u8]) -> Result<(), Error> {
        (**self).fill(dest)
    }
}

/// Returns `N` random bytes from `rng`.
pub fn array<const N: usize>(rng: &dyn SecureRandom) -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    rng.fill(&mut out)?;
    Ok(out)
}

/// A deterministic byte source for tests and known-answer vectors.
///
/// **Not secure**: it replays the bytes it was constructed with and fails once
/// they are exhausted.
#[derive(Debug)]
pub struct FixedRng<'a> {
    bytes: core::cell::Cell<&'a [u8]>,
}

impl<'a> FixedRng<'a> {
    /// Creates a source that yields exactly `bytes`.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes: core::cell::Cell::new(bytes),
        }
    }
}

impl SecureRandom for FixedRng<'_> {
    fn fill(&self, dest: &mut [u8]) -> Result<(), Error> {
        let src = self.bytes.get();
        if src.len() < dest.len() {
            return Err(Error::RandomFailure);
        }
        let (head, tail) = src.split_at(dest.len());
        dest.copy_from_slice(head);
        self.bytes.set(tail);
        Ok(())
    }
}
