//! The error types of the unbuffered API.

use core::fmt;

#[cfg(doc)]
use super::{EncodeTlsData, MayEncryptEarlyData};

/// The caller's buffer is too small.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsufficientSizeError {
    /// The buffer size needed to make progress.
    pub required_size: usize,
}

impl fmt::Display for InsufficientSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "buffer too small: {} bytes required", self.required_size)
    }
}

impl core::error::Error for InsufficientSizeError {}

/// Why [`EncodeTlsData::encode`] failed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The output buffer cannot hold the next record.
    InsufficientSize(InsufficientSizeError),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSize(e) => e.fmt(f),
        }
    }
}

impl core::error::Error for EncodeError {}

/// Why encrypting into the caller's buffer failed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptError {
    /// The output buffer is too small; nothing was written.
    InsufficientSize(InsufficientSizeError),
    /// The write key has reached its confidentiality or sequence-number
    /// limit and cannot be refreshed (TLS 1.2, 0-RTT data, or the RFC 9846
    /// §4.7.3 key epoch limit): the connection must be closed.
    EncryptExhausted,
    /// The write key has reached its confidentiality limit, and the
    /// KeyUpdate that refreshes it can only be sent once the handshake has
    /// completed (a server's half-RTT data). Temporary: retry once
    /// `is_handshaking()` is false.
    KeyUpdateAwaitsHandshake,
    /// Our `close_notify` (or a fatal alert) was already sent, or the
    /// connection has failed.
    AlreadyClosed,
    /// Record protection failed; the connection is unusable, and what the
    /// call wrote to the output buffer must not be sent.
    Failed,
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSize(e) => e.fmt(f),
            Self::EncryptExhausted => f.write_str("encryption key exhausted"),
            Self::KeyUpdateAwaitsHandshake => {
                f.write_str("encryption key spent until the handshake completes")
            }
            Self::AlreadyClosed => f.write_str("connection already closed for writing"),
            Self::Failed => f.write_str("record encryption failed"),
        }
    }
}

impl core::error::Error for EncryptError {}

/// Why [`MayEncryptEarlyData::encrypt`] failed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EarlyDataError {
    /// The data exceeds what the server's ticket allows.
    ExceededAllowedEarlyData,
    /// Encryption failed.
    Encrypt(EncryptError),
}

impl fmt::Display for EarlyDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceededAllowedEarlyData => f.write_str("too much early data"),
            Self::Encrypt(e) => e.fmt(f),
        }
    }
}

impl core::error::Error for EarlyDataError {}
