//! Time used for certificate validity checks.

use core::time::Duration;

/// Seconds since the Unix epoch (1970-01-01T00:00:00Z), ignoring leap seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(u64);

impl UnixTime {
    /// The current system time.
    ///
    /// # Panics
    ///
    /// Never: a system clock before 1970 yields the epoch.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn now() -> Self {
        Self::since_unix_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO),
        )
    }

    /// Constructs a time from a duration since the epoch (whole seconds).
    #[must_use]
    pub const fn since_unix_epoch(d: Duration) -> Self {
        Self(d.as_secs())
    }

    /// Seconds since the epoch.
    #[must_use]
    pub const fn as_secs(&self) -> u64 {
        self.0
    }
}
