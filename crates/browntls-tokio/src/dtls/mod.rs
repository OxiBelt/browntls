//! DTLS 1.3 over caller-created Tokio UDP sockets.
//!
//! [`UdpClient`] drives a single connected socket. [`UdpServer`] drives
//! multiple peers through an unconnected socket and reports peer events.
//! Both use explicit calls and the runtime's I/O and time drivers.
//!
//! Transport state-machine invariants:
//!
//! - A ciphertext datagram removed from core stays owned by the adapter
//!   until the socket accepts its entire contents. Pending, cancellation
//!   and I/O errors must never cause it to be resealed or overwritten.
//! - A receive uses a buffer large enough for a whole ordinary UDP payload.
//!   All plaintext ranges from that datagram are consumed before another
//!   socket read can overwrite the buffer, including empty records.
//! - Core's clock is elapsed Tokio time from one fixed origin. Operation
//!   deadlines cover elapsed time, rather than restarting after each input.
//! - Each poll has a finite work budget, even for continuously ready I/O.
//!   Timers and protocol replies run only while an operation is polled.

use std::io;
use std::task::Poll;

pub mod client;
mod server;
mod session;

pub use client::UdpClient;
pub use server::{ServerEvent, UdpServer};
pub use session::{SessionDriver, SessionLimits, UdpListener, UdpSession};

/// The result of receiving one application record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recv {
    /// One complete application datagram, possibly empty.
    Data(usize),
    /// The peer sent an authenticated `close_notify`.
    Closed,
}

// Covers ordinary IPv4 and IPv6 UDP payloads without truncation. IPv6
// jumbograms are outside this adapter's contract.
const MAX_DATAGRAM: usize = 65_535;
const IO_BURST: usize = 32;

fn io_error(error: browntls_core::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Only a complete successful send releases the pending datagram. In
/// particular, a short send is an error, never a request to send a suffix.
fn poll_send_datagram(
    out: &mut Vec<u8>,
    send: impl FnOnce(&[u8]) -> Poll<io::Result<usize>>,
) -> Poll<io::Result<()>> {
    match send(out) {
        Poll::Ready(Ok(len)) if len == out.len() => {
            out.clear();
            Poll::Ready(Ok(()))
        }
        Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "UDP socket did not send the whole DTLS datagram",
        ))),
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Pending => Poll::Pending,
    }
}
