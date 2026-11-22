//! The kernel handoff of a `browntls-tokio` stream (`into_kernel_handoff`),
//! as one operation of the `tls_tokio` harness.
//!
//! Checked properties:
//! * the plaintext the handoff sets aside continues what that side read
//!   before (the harness's prefix check), on success, on failure and when
//!   the future is given up;
//! * the 0-RTT data counted lies within the plaintext set aside, a client
//!   has none, and what a server's handoff counts as 0-RTT data is held
//!   against what the client sent first (the server leaves it unread when
//!   `flags` says so; the seed test checks the exact split);
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
/// `flags` bit 2: a server leaves the 0-RTT data it accepted unread, for
/// the handoff to set aside.
const KEEP_EARLY: u8 = 4;

impl World {
    /// Hands `side`'s stream to `into_kernel_handoff`, polling the future
    /// `flags >> 4` times before giving it up.
    pub(super) fn handoff(&mut self, side: usize, flags: u8) {
        // 0-RTT data is tracked apart from the server's ordinary data:
        // read first, or left to the handoff, which counts it.
        if side == SERVER && flags & KEEP_EARLY == 0 {
            self.early_read(false);
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

        /// Evaluates to the stream to go on with, if any, the plaintext
        /// taken out of it, and how much of that is 0-RTT data.
        macro_rules! drive {
            ($stream:expr, $inspect:expr) => {{
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
                        (Some(stream), received, early)
                    }
                    Some(Ok(handoff)) => {
                        ($inspect)(&handoff);
                        let _ = format!("{handoff:?}");
                        assert_eq!(
                            handoff.get_ref().1.kernel_handoff_blocker(),
                            None,
                            "a ready stream has a handoff blocker"
                        );
                        let received = handoff.received().to_vec();
                        let early = handoff.early_data_len();
                        assert!(early <= received.len(), "0-RTT data beyond the data taken");
                        if flags & BACK_TO_USERSPACE != 0 {
                            let (stream, taken) = handoff.into_stream();
                            assert_eq!(taken, received);
                            (Some(stream), received, early)
                        } else {
                            let (_io, conn, taken) = handoff.into_parts();
                            assert_eq!(taken, received);
                            assert!(
                                conn.dangerous_into_kernel_connection().is_ok(),
                                "the kernel handover of a ready connection failed"
                            );
                            (None, received, early)
                        }
                    }
                    Some(Err(err)) => {
                        let _ = format!("{err} {err:?}");
                        let early = err.early_data_len;
                        assert!(
                            early <= err.received.len(),
                            "0-RTT data beyond the data taken"
                        );
                        if flags & DROP_REFUSED != 0 {
                            let received = err.received.clone();
                            let _ = err.into_io_error();
                            (None, received, early)
                        } else {
                            (Some(err.stream), err.received, early)
                        }
                    }
                }
            }};
        }
        let (stream, received, early) = match stream {
            TlsStream::Client(stream) => {
                let (stream, received, early) =
                    drive!(stream, |handoff: &browntls_tokio::kernel::KernelHandoff<
                        browntls_tokio::client::TlsStream<_>,
                    >| {
                        assert_ne!(
                            handoff.early_data_outcome(),
                            browntls_tokio::EarlyDataOutcome::Pending
                        );
                    });
                assert_eq!(early, 0, "0-RTT data received by a client");
                (stream.map(TlsStream::Client), received, early)
            }
            TlsStream::Server(stream) => {
                let (stream, received, early) = drive!(stream, |_| {});
                (stream.map(TlsStream::Server), received, early)
            }
        };
        // `check` holds the 0-RTT part against what the client sent first.
        let (early, rest) = received.split_at(early);
        self.early.extend_from_slice(early);
        self.received[side].extend_from_slice(rest);
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

/// A server handed over with accepted 0-RTT data unread: a first
/// connection leaves a ticket, the second writes early, and the handoff
/// sets the 0-RTT data aside in front of what followed it. The stream
/// goes on in userspace.
pub(super) fn early_seed() -> Vec<u8> {
    let op = |out: &mut Vec<u8>, op: Op, side: usize| {
        out.push(op as u8);
        out.push(side as u8);
    };
    let write = |out: &mut Vec<u8>, side: usize, data: &[u8]| {
        op(out, Op::Write, side);
        out.push(0);
        put_short_field(out, data);
    };
    let mut s = vec![0x41, 4, 0, 0, 0, 0x40, 255, 0, 255, 0];
    op(&mut s, Op::Pump, 0);
    write(&mut s, SERVER, b"ticket");
    op(&mut s, Op::Pump, 0);
    op(&mut s, Op::Reconnect, 0);
    // The connect future returns at once, before the handshake.
    op(&mut s, Op::Poll, CLIENT);
    write(&mut s, CLIENT, EARLY);
    op(&mut s, Op::Pump, 0);
    write(&mut s, CLIENT, AFTER_EARLY);
    op(&mut s, Op::Flush, CLIENT);
    // One byte of it is read; the handoff takes the 0-RTT data and the
    // rest together.
    op(&mut s, Op::Read, SERVER);
    s.extend([0, 1]);
    op(&mut s, Op::Handoff, SERVER);
    s.push(0xf0 | KEEP_EARLY | BACK_TO_USERSPACE);
    write(&mut s, CLIENT, b"more");
    op(&mut s, Op::Pump, 0);
    op(&mut s, Op::Read, SERVER);
    s.extend([0, 16]);
    s
}

/// One seed of a server handed over in the middle of its handshake:
/// whether the client's Finished is on its way, the configuration byte
/// (bit 7: 0.5-RTT data) and the mode byte (bit 7: the accept future
/// returns early; the acceptor or the lazy acceptor).
pub(super) type EarlyCase = (bool, u8, u8);

/// The acceptor and the lazy acceptor, with and without 0.5-RTT data, and
/// a handoff given up while it waits.
pub(super) const EARLY_CASES: [EarlyCase; 5] = [
    (true, 0x41, 0xc0),
    (false, 0x41, 0xc0),
    (true, 0xc1, 0xc0),
    (true, 0x41, 0xd0),
    (true, 0xc1, 0xd8),
];

/// What a server with 0.5-RTT data writes before it is handed over.
pub(super) const HALF_RTT: &[u8] = b"reply";

/// A server handed over in the middle of its handshake: its accept future
/// returned early for the 0-RTT data (mode bit 7), which nobody read. With
/// `finished`, the client's Finished and more data are on their way and
/// the handoff completes the handshake; without, the handoff is given up
/// while it waits and the stream finishes its handshake afterwards. The
/// stream goes on in userspace either way.
pub(super) fn returned_early_seed((finished, config, mode): EarlyCase) -> Vec<u8> {
    let op = |out: &mut Vec<u8>, op: Op, side: usize| {
        out.push(op as u8);
        out.push(side as u8);
    };
    let write = |out: &mut Vec<u8>, side: usize, data: &[u8]| {
        op(out, Op::Write, side);
        out.push(0);
        put_short_field(out, data);
    };
    let mut s = vec![config, 4, 0, 0, 0, mode, 255, 0, 255, 0];
    op(&mut s, Op::Pump, 0);
    write(&mut s, SERVER, b"ticket");
    op(&mut s, Op::Pump, 0);
    op(&mut s, Op::Reconnect, 0);
    op(&mut s, Op::Poll, CLIENT);
    write(&mut s, CLIENT, EARLY);
    // The ClientHello and the early data go out, and the accept future
    // returns with the server's flight written (the lazy acceptor takes
    // one poll more than the acceptor).
    op(&mut s, Op::Flush, CLIENT);
    op(&mut s, Op::Poll, SERVER);
    op(&mut s, Op::Poll, SERVER);
    if config & 0x80 != 0 {
        // Sent at once, ahead of the client's Finished.
        write(&mut s, SERVER, HALF_RTT);
    }
    if finished {
        // The client alone moves on: its Finished, then more data.
        op(&mut s, Op::Flush, CLIENT);
        write(&mut s, CLIENT, AFTER_EARLY);
        op(&mut s, Op::Flush, CLIENT);
    }
    op(&mut s, Op::Handoff, SERVER);
    s.push(0xf0 | KEEP_EARLY | BACK_TO_USERSPACE);
    if !finished {
        op(&mut s, Op::Flush, CLIENT);
        write(&mut s, CLIENT, AFTER_EARLY);
    }
    write(&mut s, CLIENT, b"more");
    op(&mut s, Op::Pump, 0);
    op(&mut s, Op::EarlyRead, SERVER);
    op(&mut s, Op::Read, SERVER);
    s.extend([0, 32]);
    op(&mut s, Op::Read, CLIENT);
    s.extend([0, 32]);
    s
}

/// What the client of [`early_seed`] sends as 0-RTT data, and after it.
pub(super) const EARLY: &[u8] = b"early request";
pub(super) const AFTER_EARLY: &[u8] = b", then the rest";

pub(super) fn seeds() -> Vec<Vec<u8>> {
    let mut seeds: Vec<_> = cases().into_iter().map(seed).collect();
    seeds.push(early_seed());
    seeds.extend(EARLY_CASES.map(returned_early_seed));
    seeds
}

/// Whether a stream handed over with `flags` is gone afterwards.
#[cfg(test)]
fn ends_the_stream(extraction: bool, flags: u8) -> bool {
    flags >> 4 != 0
        && if extraction {
            flags & BACK_TO_USERSPACE == 0
        } else {
            flags & DROP_REFUSED != 0
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_tokio::play;

    /// The handoff seeds do what they are meant to: with secret extraction
    /// a polled stream becomes ready with the unread plaintext set aside,
    /// without it the stream is refused untouched, and every stream that
    /// comes back carries on.
    #[test]
    fn handoff_seeds_hand_streams_over() {
        for case in cases() {
            let (_, extraction, side, flags) = case;
            let world = play(&seed(case)).expect("configurations");
            let gone = match side {
                CLIENT => matches!(world.client, Client::Gone),
                _ => matches!(world.server, Server::Gone),
            };
            let got = &world.received[side];
            if ends_the_stream(extraction, flags) {
                assert!(gone, "{case:?}");
                // A refusal up front takes nothing out of the stream.
                let expected = if extraction { BEFORE } else { &BEFORE[..7] };
                assert_eq!(got, expected, "{case:?}");
            } else {
                assert!(!gone, "{case:?}");
                assert_eq!(*got, [BEFORE, b"more"].concat(), "{case:?}");
                assert_eq!(world.received[1 - side], AFTER, "{case:?}");
            }
        }

        // 0-RTT data left unread is set aside by the handoff and counted.
        let world = play(&early_seed()).expect("configurations");
        assert!(world.early_attempted);
        assert_eq!(world.early, EARLY);
        assert_eq!(world.received[SERVER], [AFTER_EARLY, b"more"].concat());
    }

    /// A server's stream returned before its handshake completed is handed
    /// over in that state. The handoff completes the handshake and counts
    /// the 0-RTT data nobody read; one given up while it waits takes
    /// nothing, and the stream completes its handshake afterwards.
    #[test]
    fn handoff_seeds_hand_over_a_stream_returned_early() {
        for case in EARLY_CASES {
            let (finished, config, _) = case;
            let seed = returned_early_seed(case);
            let at = seed
                .windows(2)
                .position(|w| w == [Op::Handoff as u8, SERVER as u8])
                .expect("the handoff");

            let world = play(&seed[..at]).expect("configurations");
            assert_eq!(world.server_returned_early, 1);
            let Server::Ready(server) = &world.server else {
                panic!("no server stream");
            };
            assert!(server.get_ref().1.is_handshaking());
            assert!(world.early.is_empty() && world.received[SERVER].is_empty());

            let world = play(&seed[..at + 3]).expect("configurations");
            let Server::Ready(server) = &world.server else {
                panic!("no server stream");
            };
            assert_eq!(server.get_ref().1.is_handshaking(), !finished);
            if finished {
                assert_eq!(world.early, EARLY);
                assert!(AFTER_EARLY.starts_with(&world.received[SERVER]));
            } else {
                assert!(world.early.is_empty() && world.received[SERVER].is_empty());
            }

            let world = play(&seed).expect("configurations");
            assert_eq!(world.early, EARLY, "{case:?}");
            assert_eq!(
                world.received[SERVER],
                [AFTER_EARLY, b"more"].concat(),
                "{case:?}"
            );
            // The 0.5-RTT answer written before the handoff arrived.
            let answer = if config & 0x80 != 0 { HALF_RTT } else { b"" };
            assert_eq!(world.received[CLIENT], answer, "{case:?}");
        }
    }
}
