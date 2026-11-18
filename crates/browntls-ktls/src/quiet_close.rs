//! Closing a socket that sent files without a `SIGPIPE`.
//!
//! The kernel sends the records it still holds when the socket is closed,
//! each as the call that made it asked. A write asks for no `SIGPIPE`;
//! `sendfile(2)` cannot. So when the connection has failed by then, the
//! close of a socket whose stream sent files raises `SIGPIPE` for the
//! closing thread, outside any call the stream could answer for.
//!
//! A stream therefore keeps a [`QuietClose`] in a field declared behind its
//! socket. Its `Drop` calls [`QuietClose::closing`], which holds the signal
//! back; the fields are then dropped in their order, the socket (closed if
//! the stream owned it) before the `QuietClose`, whose held signal mask
//! takes a `SIGPIPE` that the close raised and restores the thread's mask.

use crate::sys::HeldSigpipe;

/// See the [module](self).
#[derive(Default)]
pub(crate) struct QuietClose {
    /// The stream called `sendfile`: the kernel may hold records that
    /// raise `SIGPIPE`.
    sent_file: bool,
    /// The signal, held back from [`Self::closing`] until this is dropped.
    held: Option<HeldSigpipe>,
}

impl QuietClose {
    /// Notes a `sendfile` on the socket.
    pub(crate) fn sent_file(&mut self) {
        self.sent_file = true;
    }

    /// The stream is being dropped, and its socket with it.
    pub(crate) fn closing(&mut self) {
        if self.sent_file {
            // Without the hold the close is as loud as the kernel makes it.
            self.held = HeldSigpipe::hold().ok();
        }
    }
}
