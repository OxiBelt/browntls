//! The clock used for certificate validity and ticket ages.

use core::fmt::Debug;

use browntls_pki::UnixTime;

/// A source of the current time.
pub trait TimeProvider: Debug + Send + Sync {
    /// The current time, or `None` if unavailable.
    fn current_time(&self) -> Option<UnixTime>;
}

/// The system clock.
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct DefaultTimeProvider;

#[cfg(feature = "std")]
impl TimeProvider for DefaultTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::now())
    }
}
