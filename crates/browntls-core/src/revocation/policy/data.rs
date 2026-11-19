//! Installed revocation data: a CRLite snapshot and the CT logs that decide
//! which certificates it covers.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::UnixTime;
use browntls_pki::crlite::CrliteSnapshot;
use browntls_pki::sct::{CtLog, SctError};

use super::RevocationDigests;
use crate::sync::Arc;

/// Largest number of CT logs in one [`RevocationData`].
const MAX_CT_LOGS: usize = 1024;

/// The public key of a CT log the application trusts, and the SCT timestamps
/// it is trusted for.
#[derive(Clone, PartialEq, Eq)]
pub struct CtLogKey {
    spki: Vec<u8>,
    expected_id: Option<[u8; 32]>,
    from_ms: u64,
    until_ms: u64,
}

impl CtLogKey {
    /// A log with the DER `SubjectPublicKeyInfo` `spki`, trusted for every
    /// timestamp. The key is checked when the log joins a
    /// [`RevocationData`].
    pub fn new(spki: Vec<u8>) -> Self {
        Self {
            spki,
            expected_id: None,
            from_ms: 0,
            until_ms: u64::MAX,
        }
    }

    /// Requires the key to hash to `id`, the log ID a log list gives.
    pub fn with_expected_id(mut self, id: [u8; 32]) -> Self {
        self.expected_id = Some(id);
        self
    }

    /// Trusts only SCTs whose timestamp, in milliseconds since the Unix
    /// epoch, is at least `from_ms` and less than `until_ms`.
    pub fn with_timestamp_window(mut self, from_ms: u64, until_ms: u64) -> Self {
        self.from_ms = from_ms;
        self.until_ms = until_ms;
        self
    }

    /// The log as the SCT verifier takes it.
    pub(super) fn to_ct_log(&self, digests: &RevocationDigests) -> Result<CtLog<'_>, SctError> {
        let log = CtLog::new(&self.spki, digests.sha256)?;
        let log = match &self.expected_id {
            Some(id) => log.with_expected_id(id)?,
            None => log,
        };
        Ok(log.with_timestamp_window(self.from_ms, self.until_ms))
    }
}

impl fmt::Debug for CtLogKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtLogKey")
            .field("from_ms", &self.from_ms)
            .field("until_ms", &self.until_ms)
            .finish_non_exhaustive()
    }
}

/// Why revocation data was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevocationDataError {
    /// A CT log key is malformed or does not hash to its expected log ID.
    InvalidCtLog(SctError),
    /// More CT logs were given than one snapshot may carry (1024).
    TooManyCtLogs,
    /// The offered generation does not exceed the newest generation that was
    /// ever installed.
    NotNewer {
        /// The newest generation installed so far.
        installed: u64,
        /// The generation that was offered.
        offered: u64,
    },
}

impl fmt::Display for RevocationDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCtLog(error) => write!(f, "invalid CT log key: {error}"),
            Self::TooManyCtLogs => f.write_str("too many CT logs"),
            Self::NotNewer { installed, offered } => write!(
                f,
                "revocation data generation {offered} does not exceed installed generation {installed}"
            ),
        }
    }
}

impl core::error::Error for RevocationDataError {}

struct DataInner {
    crlite: CrliteSnapshot,
    ct_logs: Vec<CtLogKey>,
}

/// One immutable generation of revocation data: a CRLite snapshot together
/// with the CT logs whose timestamps decide its coverage.
///
/// The snapshot's generation, effective times and expiry, the filter bytes
/// and the log keys must all come from one channel the application has
/// authenticated. This type validates their form only. Cloning is cheap and
/// shares the data.
#[derive(Clone)]
pub struct RevocationData(Arc<DataInner>);

impl RevocationData {
    /// Pairs `crlite` with the CT logs it was built against.
    ///
    /// # Errors
    ///
    /// [`RevocationDataError::InvalidCtLog`] or
    /// [`RevocationDataError::TooManyCtLogs`].
    pub fn new(
        crlite: CrliteSnapshot,
        ct_logs: Vec<CtLogKey>,
        digests: &RevocationDigests,
    ) -> Result<Self, RevocationDataError> {
        if ct_logs.len() > MAX_CT_LOGS {
            return Err(RevocationDataError::TooManyCtLogs);
        }
        for log in &ct_logs {
            log.to_ct_log(digests)
                .map_err(RevocationDataError::InvalidCtLog)?;
        }
        Ok(Self(Arc::new(DataInner { crlite, ct_logs })))
    }

    /// The generation of the CRLite snapshot.
    pub fn generation(&self) -> u64 {
        self.0.crlite.generation()
    }

    /// The time from which the snapshot no longer vouches for a certificate.
    pub fn expiry(&self) -> UnixTime {
        self.0.crlite.expiry()
    }

    pub(super) fn crlite(&self) -> &CrliteSnapshot {
        &self.0.crlite
    }

    pub(super) fn ct_logs(&self) -> &[CtLogKey] {
        &self.0.ct_logs
    }
}

impl fmt::Debug for RevocationData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationData")
            .field("generation", &self.generation())
            .field("expiry", &self.expiry())
            .field("ct_logs", &self.0.ct_logs.len())
            .finish_non_exhaustive()
    }
}

/// Where a [`RevocationPolicy`](super::RevocationPolicy) reads the current
/// revocation data.
///
/// An implementation must replace its data as a whole and must never return
/// a generation older than one it returned before.
/// [`SharedRevocationData`] does both. Without the `std` feature an
/// application supplies its own implementation, or uses a fixed
/// [`RevocationData`].
pub trait RevocationDataSource: fmt::Debug + Send + Sync {
    /// The data to verify against, if any is installed.
    fn current(&self) -> Option<RevocationData>;
}

/// Data that is never replaced.
impl RevocationDataSource for RevocationData {
    fn current(&self) -> Option<RevocationData> {
        Some(self.clone())
    }
}

#[cfg(feature = "std")]
#[derive(Debug, Default)]
struct SharedState {
    data: Option<RevocationData>,
    /// The newest generation ever installed.
    newest_generation: Option<u64>,
}

/// Revocation data that an application replaces while verifiers use it.
///
/// A verification reads the data once and uses that generation throughout,
/// so a replacement never mixes a snapshot with the logs of another.
#[cfg(feature = "std")]
#[derive(Debug, Default)]
pub struct SharedRevocationData {
    state: std::sync::RwLock<SharedState>,
}

#[cfg(feature = "std")]
impl SharedRevocationData {
    /// A holder with no data installed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs `data` in place of the current generation.
    ///
    /// # Errors
    ///
    /// [`RevocationDataError::NotNewer`] unless the generation of `data`
    /// exceeds every generation installed before. The installed data stays
    /// in use.
    pub fn replace(&self, data: RevocationData) -> Result<(), RevocationDataError> {
        // A panic cannot leave the state half written: both fields are
        // assigned after the only fallible step.
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let offered = data.generation();
        if let Some(installed) = state.newest_generation
            && offered <= installed
        {
            return Err(RevocationDataError::NotNewer { installed, offered });
        }
        state.newest_generation = Some(offered);
        state.data = Some(data);
        Ok(())
    }
}

#[cfg(feature = "std")]
impl RevocationDataSource for SharedRevocationData {
    fn current(&self) -> Option<RevocationData> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .data
            .clone()
    }
}
