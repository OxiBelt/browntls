//! The kernel handoff of a `browntls-tokio` stream (`into_kernel_handoff`),
//! as one operation of the `tls_tokio` harness.
//!
//! Checked properties:
//! * the plaintext the handoff sets aside continues what that side read
//!   before (the harness's prefix check), on success, on failure and when
//!   the future is given up;
//! * the 0-RTT data counted lies within the plaintext set aside;
//! * a stream reported ready has no handoff blocker, and its connection's
//!   `dangerous_into_kernel_connection` succeeds;
//! * whatever comes back (a ready stream turned back, a refused one, an
//!   abandoned one) goes on working under the harness's other checks.

use std::future::Future as _;
use std::pin::Pin;
use std::task::Poll;

use browntls_tokio::TlsStream;

use super::{CLIENT, Client, Op, SERVER, Server, World, cx};
use crate::input::put_short_field;

/// `flags` bit 0: a ready stream goes on in userspace instead of being
/// taken apart.
const BACK_TO_USERSPACE: u8 = 1;
/// `flags` bit 1: a refused stream is dropped (`into_io_error`).
const DROP_REFUSED: u8 = 2;

impl World {
    /// Hands `side`'s stream to `into_kernel_handoff`, polling the future
    /// `flags >> 4` times before giving it up.
    pub(super) fn handoff(&mut self, side: usize, flags: u8) {
        // 0-RTT data is tracked apart from the server's ordinary data.
        if side == SERVER {
            self.early_read();
        }
        let stream = match side {
            CLIENT => match std::mem::replace(&mut self.client, Client::Gone) {
                Client::Ready(stream) => stream,
                other => {
                    self.client = other;
                    return;
                }
            },
            _ => match std::mem::replace(&mut self.server, Server::Gone) {
                Server::Ready(stream) => stream,
                other => {
                    self.server = other;
                    return;
                }
            },
        };

        /// Evaluates to the stream to go on with, if any, and the plaintext
        /// taken out of it.
        macro_rules! drive {
            ($stream:expr) => {{
                let mut future = $stream.into_kernel_handoff();
                let mut outcome = None;
                for _ in 0..flags >> 4 {
                    if let Poll::Ready(result) = Pin::new(&mut future).poll(&mut cx()) {
                        outcome = Some(result);
                        break;
                    }
                }
                match outcome {
                    None => {
                        let _ = format!("{future:?}");
                        let early = future.early_data_len();
                        let (stream, received) =
                            future.into_stream().expect("the future did not return");
                        assert!(early <= received.len(), "0-RTT data beyond the data taken");
                        (Some(stream), received)
                    }
                    Some(Ok(handoff)) => {
                        let _ = format!("{handoff:?}");
                        assert_eq!(
                            handoff.get_ref().1.kernel_handoff_blocker(),
                            None,
                            "a ready stream has a handoff blocker"
                        );
                        let received = handoff.received().to_vec();
                        assert!(
                            handoff.early_data_len() <= received.len(),
                            "0-RTT data beyond the data taken"
                        );
                        if flags & BACK_TO_USERSPACE != 0 {
                            let (stream, taken) = handoff.into_stream();
                            assert_eq!(taken, received);
                            (Some(stream), received)
                        } else {
                            let (_io, conn, taken) = handoff.into_parts();
                            assert_eq!(taken, received);
                            assert!(
                                conn.dangerous_into_kernel_connection().is_ok(),
                                "the kernel handover of a ready connection failed"
                            );
                            (None, received)
                        }
                    }
                    Some(Err(err)) => {
                        let _ = format!("{err} {err:?}");
                        assert!(
                            err.early_data_len <= err.received.len(),
                            "0-RTT data beyond the data taken"
                        );
                        if flags & DROP_REFUSED != 0 {
                            let received = err.received.clone();
                            let _ = err.into_io_error();
                            (None, received)
                        } else {
                            (Some(err.stream), err.received)
                        }
                    }
                }
            }};
        }
        let (stream, received) = match stream {
            TlsStream::Client(stream) => {
                let (stream, received) = drive!(stream);
                (stream.map(TlsStream::Client), received)
            }
            TlsStream::Server(stream) => {
                let (stream, received) = drive!(stream);
                (stream.map(TlsStream::Server), received)
            }
        };
        self.received[side].extend_from_slice(&received);
        if let Some(stream) = stream {
            match side {
                CLIENT => self.client = Client::Ready(stream),
                _ => self.server = Server::Ready(stream),
            }
        }
        self.check();
    }
}

/// One handoff seed: the protocol versions byte, whether secret extraction
/// is on, the side handed over, and the operation's flags.
pub(super) type Case = (u8, bool, usize, u8);

/// What the peer writes before the handoff; seven bytes of it are read.
pub(super) const BEFORE: &[u8] = b"read before the handoff, and after";
/// What the side handed over writes afterwards, if it still can.
pub(super) const AFTER: &[u8] = b"written after the handoff";

/// Each side handed over with data unread and taken apart, turned back to
/// userspace and used again, refused without secret extraction (kept, and
/// dropped), and a future given up before its first poll.
pub(super) fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for versions in [1u8, 2] {
        for extraction in [true, false] {
            for side in [CLIENT, SERVER] {
                for flags in [0xf0u8, 0xf0 | BACK_TO_USERSPACE, 0xf0 | DROP_REFUSED, 0x01] {
                    cases.push((versions, extraction, side, flags));
                }
            }
        }
    }
    cases
}

pub(super) fn seed((versions, extraction, side, flags): Case) -> Vec<u8> {
    let op = |out: &mut Vec<u8>, op: Op, side: usize| {
        out.push(op as u8);
        out.push(side as u8);
    };
    let write = |out: &mut Vec<u8>, side: usize, data: &[u8]| {
        op(out, Op::Write, side);
        out.push(0);
        put_short_field(out, data);
    };
    let auth = if extraction { 4 } else { 0 };
    let mut s = vec![versions, auth, 0, 0, 0, 0, 255, 0, 255, 0];
    op(&mut s, Op::Pump, 0);
    write(&mut s, 1 - side, BEFORE);
    op(&mut s, Op::Flush, 1 - side);
    // Seven bytes are read; the rest stays in the connection.
    op(&mut s, Op::Read, side);
    s.extend([0, 7]);
    op(&mut s, Op::Handoff, side);
    s.push(flags);
    write(&mut s, side, AFTER);
    write(&mut s, 1 - side, b"more");
    op(&mut s, Op::Pump, 0);
    s
}

pub(super) fn seeds() -> Vec<Vec<u8>> {
    cases().into_iter().map(seed).collect()
}

/// Whether a stream handed over with `flags` is gone afterwards.
#[cfg(test)]
pub(super) fn ends_the_stream(extraction: bool, flags: u8) -> bool {
    flags >> 4 != 0
        && if extraction {
            flags & BACK_TO_USERSPACE == 0
        } else {
            flags & DROP_REFUSED != 0
        }
}
