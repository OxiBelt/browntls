//! Server early-data delivery state shared by the connection APIs.

use core::fmt;

use crate::vecbuf::ChunkVecBuffer;

/// Where 0-RTT stands on a server connection.
#[derive(Default)]
enum EarlyDataKind {
    /// No decision yet.
    #[default]
    New,
    /// Accepted: `received` holds the data (buffered API only), `left` what
    /// may still arrive.
    Accepted {
        received: ChunkVecBuffer,
        left: usize,
    },
    /// Declined (by configuration, policy, or the application).
    Rejected,
}

/// The server's 0-RTT bookkeeping.
#[derive(Default)]
pub(in crate::server) struct EarlyDataState {
    kind: EarlyDataKind,
    /// Unbuffered API: accepted early data stays in the caller's buffer.
    in_place: bool,
    /// Unbuffered API: the record just processed was accepted early data.
    in_place_pending: bool,
}

impl EarlyDataState {
    pub(in crate::server) fn reject(&mut self) {
        self.kind = EarlyDataKind::Rejected;
    }

    pub(in crate::server) fn accept(&mut self, max_size: usize) {
        self.kind = EarlyDataKind::Accepted {
            received: ChunkVecBuffer::new(Some(max_size)),
            left: max_size,
        };
    }

    pub(in crate::server) fn was_accepted(&self) -> bool {
        matches!(self.kind, EarlyDataKind::Accepted { .. })
    }

    pub(in crate::server) fn was_rejected(&self) -> bool {
        matches!(self.kind, EarlyDataKind::Rejected)
    }

    /// Stores early data; `false` if it exceeds what was announced.
    ///
    /// With the unbuffered API nothing is copied: the record stays where it
    /// was decrypted and only the budget is charged.
    pub(in crate::server) fn take_received_plaintext(&mut self, bytes: &[u8]) -> bool {
        let EarlyDataKind::Accepted { received, left } = &mut self.kind else {
            return false;
        };
        let available = bytes.len();
        if self.in_place {
            if available > *left {
                return false;
            }
            *left -= available;
            self.in_place_pending = true;
            return true;
        }
        if received.apply_limit(available) != available || available > *left {
            return false;
        }
        received.append(bytes.to_vec());
        *left -= available;
        true
    }

    /// Unbuffered API: leave accepted early data in the caller's buffer.
    pub(super) fn set_in_place(&mut self) {
        self.in_place = true;
    }

    pub(super) fn take_in_place_pending(&mut self) -> bool {
        core::mem::take(&mut self.in_place_pending)
    }

    pub(super) fn has_buffered_plaintext(&self) -> bool {
        matches!(&self.kind, EarlyDataKind::Accepted { received, .. } if !received.is_empty())
    }

    #[cfg(feature = "std")]
    pub(super) fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.kind {
            EarlyDataKind::Accepted { received, .. } => Ok(received.read(buf)),
            _ => Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
        }
    }
}

impl fmt::Debug for EarlyDataState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            EarlyDataKind::New => f.write_str("EarlyDataState::New"),
            EarlyDataKind::Accepted { received, left } => f
                .debug_struct("EarlyDataState::Accepted")
                .field("received", &received.len())
                .field("left", left)
                .finish(),
            EarlyDataKind::Rejected => f.write_str("EarlyDataState::Rejected"),
        }
    }
}
