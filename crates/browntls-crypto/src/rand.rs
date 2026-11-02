//! Operating-system randomness.
//!
//! browntls draws all randomness directly from the operating system CSPRNG and
//! keeps no user-space generator state that could be duplicated by `fork`.

/// The operating system failed to provide randomness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandError;

impl core::fmt::Display for RandError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("operating system randomness unavailable")
    }
}

/// Fills `dest` with cryptographically secure random bytes.
///
/// # Errors
///
/// Returns [`RandError`] when the operating system source fails or when the
/// crate was built without the `std` feature.
pub fn fill(dest: &mut [u8]) -> Result<(), RandError> {
    fill_impl(dest)
}

#[cfg(feature = "std")]
fn fill_impl(dest: &mut [u8]) -> Result<(), RandError> {
    getrandom::fill(dest).map_err(|_| RandError)
}

#[cfg(not(feature = "std"))]
fn fill_impl(_dest: &mut [u8]) -> Result<(), RandError> {
    Err(RandError)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    #[test]
    fn fills() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        super::fill(&mut a).unwrap();
        super::fill(&mut b).unwrap();
        assert_ne!(a, b);
    }
}
