//! Client early-data policy and plaintext accounting shared by both adapters.

use std::fmt;
use std::io;
use std::num::NonZeroUsize;

use browntls_crypto::zeroize::zeroize_bytes;

use crate::common::HandshakeFailure;

/// What a Tokio client may do with bytes the peer declined as early data.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum RejectedEarlyDataPolicy {
    /// Report the rejection and let the application decide what to send.
    #[default]
    ReportOnly,
    /// Resend after the handshake if the same concrete ALPN was negotiated.
    ResendIfSameAlpn {
        /// Upper bound on the plaintext retained for automatic resend.
        ///
        /// This also caps the amount the stream writes as early data.
        max_bytes: NonZeroUsize,
    },
}

/// The local outcome of an early-data phase. Counts are plaintext bytes.
///
/// Even a successful decision or flush says nothing about whether the
/// peer's application processed the data.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum EarlyDataOutcome {
    /// No early bytes were written.
    #[default]
    NoEarlyBytes,
    /// The early phase has yet to finish.
    Pending,
    /// The TLS peer accepted the early data.
    Accepted {
        /// Bytes the caller wrote as early data.
        early_bytes: usize,
    },
    /// The TLS peer rejected the early data and the connection is usable.
    Rejected {
        /// Bytes the caller wrote as early data.
        early_bytes: usize,
        /// Bytes automatically resent and flushed after the handshake.
        resent_bytes: usize,
        /// Bytes left for the application to handle.
        unresent_bytes: usize,
    },
    /// The handshake or transport failed during the early phase.
    Failed {
        /// Bytes the caller wrote as early data.
        early_bytes: usize,
        /// Bytes queued under ordinary traffic keys before the failure.
        /// Their delivery is uncertain.
        queued_resend_bytes: usize,
    },
}

/// The server declined 0-RTT bytes that were left for the application to
/// handle. A write, flush, shutdown or buffered handoff reports this until
/// the application acknowledges it. The stream itself remains usable.
#[derive(Debug)]
pub struct EarlyDataNotResent {
    /// How many bytes of early data were declined and left unresent.
    pub len: usize,
}

impl fmt::Display for EarlyDataNotResent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the server declined {} bytes of 0-RTT data that were left unresent",
            self.len
        )
    }
}

impl std::error::Error for EarlyDataNotResent {}

#[derive(Debug, Default)]
pub(crate) struct EarlyResult {
    pub(crate) outcome: EarlyDataOutcome,
    unacknowledged: Option<usize>,
    failure: Option<HandshakeFailure>,
}

impl EarlyResult {
    pub(crate) fn pending() -> Self {
        Self {
            outcome: EarlyDataOutcome::Pending,
            ..Self::default()
        }
    }

    pub(crate) fn complete(&mut self, write: &EarlyWrite, accepted: bool) {
        self.outcome = if write.written == 0 {
            EarlyDataOutcome::NoEarlyBytes
        } else if accepted {
            EarlyDataOutcome::Accepted {
                early_bytes: write.written,
            }
        } else {
            let unresent = write.written - write.resent;
            self.unacknowledged = (unresent != 0).then_some(unresent);
            EarlyDataOutcome::Rejected {
                early_bytes: write.written,
                resent_bytes: write.resent,
                unresent_bytes: unresent,
            }
        };
    }

    pub(crate) fn fail(&mut self, write: &EarlyWrite, error: &io::Error) {
        self.outcome = EarlyDataOutcome::Failed {
            early_bytes: write.written,
            queued_resend_bytes: write.resent,
        };
        self.failure = Some(HandshakeFailure::new(error));
    }

    pub(crate) fn failure(&self) -> io::Result<()> {
        self.failure.as_ref().map_or(Ok(()), |err| Err(err.error()))
    }

    pub(crate) fn check_write(&self) -> io::Result<()> {
        match self.unacknowledged {
            Some(len) => Err(io::Error::other(EarlyDataNotResent { len })),
            None => self.failure(),
        }
    }

    pub(crate) fn acknowledge(&mut self) -> Option<usize> {
        self.unacknowledged.take()
    }
}

pub(crate) struct EarlyWrite {
    policy: RejectedEarlyDataPolicy,
    written: usize,
    sent: Vec<u8>,
    resent: usize,
}

impl EarlyWrite {
    pub(crate) fn new(policy: RejectedEarlyDataPolicy) -> Self {
        Self {
            policy,
            written: 0,
            sent: Vec::new(),
            resent: 0,
        }
    }

    pub(crate) fn limit(&self, len: usize) -> usize {
        match self.policy {
            RejectedEarlyDataPolicy::ReportOnly => len,
            RejectedEarlyDataPolicy::ResendIfSameAlpn { max_bytes } => {
                len.min(max_bytes.get() - self.written)
            }
        }
    }

    pub(crate) fn record(&mut self, data: &[u8]) {
        self.written += data.len();
        if let RejectedEarlyDataPolicy::ResendIfSameAlpn { max_bytes } = self.policy {
            if self.written > self.sent.capacity() {
                let capacity = self
                    .sent
                    .capacity()
                    .saturating_mul(2)
                    .min(max_bytes.get())
                    .max(self.written);
                // Replace the allocation explicitly so the previous
                // plaintext can be wiped before releasing its storage.
                let mut replacement = Vec::with_capacity(capacity);
                replacement.extend_from_slice(&self.sent);
                zeroize_bytes(&mut self.sent);
                self.sent = replacement;
            }
            self.sent.extend_from_slice(data);
        }
    }

    pub(crate) fn may_resend(&self, early: Option<&[u8]>, negotiated: Option<&[u8]>) -> bool {
        !self.sent.is_empty() && early.is_some() && early == negotiated
    }

    pub(crate) fn remaining(&self) -> &[u8] {
        &self.sent[self.resent..]
    }

    pub(crate) fn queued_resend(&mut self, len: usize) {
        self.resent += len;
    }
}

impl Drop for EarlyWrite {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.sent);
    }
}

impl fmt::Debug for EarlyWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EarlyWrite")
            .field("policy", &self.policy)
            .field("written", &self.written)
            .field("resent", &self.resent)
            .finish()
    }
}
