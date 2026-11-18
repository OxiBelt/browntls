//! `browntls-tokio`: the asynchronous connector, acceptor, lazy acceptor and
//! streams between a genuine client and server in the same process, over an
//! in-memory transport whose behaviour the input controls.
//!
//! Input: the 5-byte configuration header of `tls_conn`
//! (`tls_conn::setup::Knobs`), a mode byte (how each side is created: the
//! `TlsConnector` entry point, `TlsAcceptor` or `LazyConfigAcceptor` with
//! `into_stream`, `into_stream_with` or `from_parts`, the fallible futures,
//! early data), two bytes per direction for the transport (largest chunk
//! per call, and a mask of calls that return `Pending`), then up to 96
//! operations: polls of the handshake futures, writes (plain or vectored),
//! reads (`poll_read` or `poll_fill_buf` and `consume`), flushes,
//! shutdowns, damaged, inserted or ended transport bytes, key updates,
//! accessors, early data reads, the lazy acceptor's `take_io`, pumping
//! until idle, reconnection (resumption and 0-RTT), a stream split into its
//! read and write halves, used through them and put back together, and the
//! kernel handoff of a stream (`handoff`).
//!
//! The futures and streams are polled with a no-op waker, one poll per
//! operation: the harness drives them itself rather than waiting for
//! wake-ups, so it checks what polls return, not when tasks are woken.
//!
//! Checked properties:
//! * plaintext a side reads (and accepted 0-RTT data the server reads) is a
//!   prefix of what the peer wrote, whatever happened to the bytes;
//! * a write never reports more bytes than it was given, and never `Ok(0)`
//!   for a non-empty buffer;
//! * the halves of a stream are a pair and reunite into it, and halves of
//!   two streams do neither and come back unharmed;
//! * nothing panics, and no poll loops forever.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, IoSlice, Read as _};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use browntls::server::Acceptor;
use browntls::{ClientConfig, ServerConfig};
use browntls_tokio::{
    Accept, Connect, FallibleAccept, FallibleConnect, LazyConfigAcceptor, ReadHalf, ReuniteError,
    StartHandshake, TlsAcceptor, TlsConnector, TlsStream, WriteHalf,
};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::input::{Input, put_short_field};
use crate::tls_conn::setup::{Knobs, assert_prefix, server_name};

mod handoff;

const MAX_OPS: usize = 96;
const MAX_CONNECTIONS: usize = 3;
/// What the split seeds write through a write half, and in how many rounds.
const SPLIT_DATA: &[u8] = b"through a half";
const SPLIT_ROUNDS: u8 = 8;
const CLIENT: usize = 0;
const SERVER: usize = 1;
/// The most bytes one direction of the transport holds.
const LANE_CAPACITY: usize = 64 * 1024;

/// One direction of the transport: bytes written by one side for the other.
#[derive(Default)]
struct Lane {
    bytes: VecDeque<u8>,
    /// The writer shut its side down, or the input ended the lane.
    closed: bool,
    /// Largest number of bytes per read or write call (at least 1).
    chunk: usize,
    /// Bit `i % 8` set: the `i`th read, and the `i`th write, on this lane
    /// return `Pending`.
    pending_mask: u8,
    /// Calls so far: reads, writes.
    calls: [u32; 2],
}

impl Lane {
    fn pending(&mut self, write: bool) -> bool {
        let calls = &mut self.calls[usize::from(write)];
        let bit = *calls % 8;
        *calls = calls.wrapping_add(1);
        self.pending_mask & (1 << bit) != 0
    }
}

/// One end of the in-memory transport; lane `side` carries its writes.
struct End {
    lanes: Rc<RefCell<[Lane; 2]>>,
    side: usize,
}

impl AsyncRead for End {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut lanes = self.lanes.borrow_mut();
        let lane = &mut lanes[1 - self.side];
        if lane.pending(false) {
            return Poll::Pending;
        }
        if lane.bytes.is_empty() {
            return if lane.closed {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            };
        }
        let n = buf.remaining().min(lane.chunk).min(lane.bytes.len());
        for byte in lane.bytes.drain(..n) {
            buf.put_slice(&[byte]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for End {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut lanes = self.lanes.borrow_mut();
        let lane = &mut lanes[self.side];
        if lane.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if lane.pending(true) || lane.bytes.len() >= LANE_CAPACITY {
            return Poll::Pending;
        }
        let n = buf
            .len()
            .min(lane.chunk)
            .min(LANE_CAPACITY - lane.bytes.len());
        lane.bytes.extend(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.lanes.borrow_mut()[self.side].closed = true;
        Poll::Ready(Ok(()))
    }
}

enum Client {
    Connecting(Connect<End>),
    Fallible(FallibleConnect<End>),
    Ready(TlsStream<End>),
    Gone,
}

enum Server {
    Lazy(LazyConfigAcceptor<End>),
    Accepting(Accept<End>),
    Fallible(FallibleAccept<End>),
    Ready(TlsStream<End>),
    Gone,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum Op {
    /// `side`: polls that side's handshake future once.
    Poll,
    /// `side, vectored, data (short field)`: one write.
    Write,
    /// `side, buffered, size`: one read.
    Read,
    /// `side`: one flush.
    Flush,
    /// `side`: one shutdown.
    Shutdown,
    /// `lane, position (u16), xor`: flips bits of a byte in flight.
    Damage,
    /// `lane, bytes (short field)`: appends raw bytes to a lane.
    Inject,
    /// `lane`: ends a lane (end of file for its reader).
    Close,
    /// `side`: `refresh_traffic_keys`.
    KeyUpdate,
    /// `side`: every accessor of that side's future or stream.
    Accessors,
    /// The server reads accepted 0-RTT data.
    EarlyRead,
    /// The lazy acceptor gives its transport back.
    TakeIo,
    /// Polls everything until nothing moves.
    Pump,
    /// Starts a new connection with the same configurations.
    Reconnect,
    /// `side, how, data (short field), size`: splits that side's stream,
    /// writes, flushes and reads once through the halves and reunites them.
    Split,
    /// `side, flags`: `into_kernel_handoff` (see `handoff`).
    Handoff,
}

const OPS: [Op; 16] = [
    Op::Poll,
    Op::Write,
    Op::Read,
    Op::Flush,
    Op::Shutdown,
    Op::Damage,
    Op::Inject,
    Op::Close,
    Op::KeyUpdate,
    Op::Accessors,
    Op::EarlyRead,
    Op::TakeIo,
    Op::Pump,
    Op::Reconnect,
    Op::Split,
    Op::Handoff,
];

struct World {
    connector: TlsConnector,
    server_config: Arc<ServerConfig>,
    mode: u8,
    transport: [u8; 4],
    lanes: Rc<RefCell<[Lane; 2]>>,
    client: Client,
    server: Server,
    /// Plaintext each side wrote.
    sent: [Vec<u8>; 2],
    /// Plaintext each side read, as ordinary data.
    received: [Vec<u8>; 2],
    /// 0-RTT data the server read.
    early: Vec<u8>,
    /// The client's connect returned before its handshake (0-RTT): the
    /// server's ordinary data then starts after the accepted early data.
    early_attempted: bool,
}

fn cx() -> Context<'static> {
    Context::from_waker(Waker::noop())
}

/// The stream of its two halves, asked of either half.
fn rejoin<S>(read: ReadHalf<S>, write: WriteHalf<S>, write_first: bool) -> S {
    assert!(read.is_pair_of(&write) && write.is_pair_of(&read));
    let stream = if write_first {
        write.reunite(read)
    } else {
        read.reunite(write)
    };
    match stream {
        Ok(stream) => stream,
        Err(_) => panic!("the halves of one stream did not reunite"),
    }
}

/// What a handshake future's accessors returned: `(get_ref, get_mut)` and
/// `(connection, connection_mut)`, each as "is some".
fn check_future_accessors(io: (bool, bool), conn: (bool, bool)) {
    assert_eq!(io.0, io.1, "get_ref and get_mut disagree");
    assert_eq!(conn.0, conn.1, "connection and connection_mut disagree");
    assert!(io.0 || !conn.0, "a connection without a transport");
}

impl World {
    fn new(client_config: ClientConfig, server_config: ServerConfig, mode: u8, t: [u8; 4]) -> Self {
        let connector = TlsConnector::from(Arc::new(client_config)).early_data(mode & 0x40 != 0);
        let mut world = Self {
            connector,
            server_config: Arc::new(server_config),
            mode,
            transport: t,
            lanes: Rc::new(RefCell::new([Lane::default(), Lane::default()])),
            client: Client::Gone,
            server: Server::Gone,
            sent: [Vec::new(), Vec::new()],
            received: [Vec::new(), Vec::new()],
            early: Vec::new(),
            early_attempted: false,
        };
        world.connect();
        world
    }

    /// A fresh transport and a new client and server on it.
    fn connect(&mut self) {
        let t = self.transport;
        self.lanes = Rc::new(RefCell::new([
            Lane {
                chunk: usize::from(t[0]).max(1) * 8,
                pending_mask: t[1],
                ..Lane::default()
            },
            Lane {
                chunk: usize::from(t[2]).max(1) * 8,
                pending_mask: t[3],
                ..Lane::default()
            },
        ]));
        let end = |side| End {
            lanes: self.lanes.clone(),
            side,
        };
        self.sent = [Vec::new(), Vec::new()];
        self.received = [Vec::new(), Vec::new()];
        self.early.clear();

        let alpn = || vec![b"fuzz".to_vec()];
        let connect = match self.mode & 3 {
            0 => self.connector.connect(server_name(), end(CLIENT)),
            1 => self
                .connector
                .connect_with(server_name(), end(CLIENT), |c| {
                    c.set_buffer_limit(Some(4096))
                }),
            2 => self
                .connector
                .with_alpn(alpn())
                .connect(server_name(), end(CLIENT)),
            _ => self
                .connector
                .with_alpn(alpn())
                .connect_with(server_name(), end(CLIENT), |_| {}),
        };
        self.client = if self.mode & 4 != 0 {
            Client::Fallible(connect.into_fallible())
        } else {
            Client::Connecting(connect)
        };
        self.early_attempted = false;

        let acceptor = TlsAcceptor::from(self.server_config.clone());
        self.server = match (self.mode >> 3) & 3 {
            0 => self.accept(acceptor.accept(end(SERVER))),
            1 => self.accept(acceptor.accept_with(end(SERVER), |s| s.set_buffer_limit(Some(4096)))),
            _ => Server::Lazy(LazyConfigAcceptor::new(Acceptor::default(), end(SERVER))),
        };
    }

    fn accept(&self, accept: Accept<End>) -> Server {
        if self.mode & 0x20 != 0 {
            Server::Fallible(accept.into_fallible())
        } else {
            Server::Accepting(accept)
        }
    }

    fn poll_handshake(&mut self, side: usize) {
        let mut cx = cx();
        if side == CLIENT {
            let done = match &mut self.client {
                Client::Connecting(f) => match Pin::new(f).poll(&mut cx) {
                    Poll::Ready(r) => Some(r.ok()),
                    Poll::Pending => None,
                },
                Client::Fallible(f) => match Pin::new(f).poll(&mut cx) {
                    Poll::Ready(r) => Some(r.ok()),
                    Poll::Pending => None,
                },
                _ => None,
            };
            if let Some(stream) = done {
                self.client = match stream {
                    Some(stream) => {
                        self.early_attempted = stream.get_ref().1.is_handshaking();
                        Client::Ready(stream.into())
                    }
                    None => Client::Gone,
                };
            }
            return;
        }
        match &mut self.server {
            Server::Lazy(lazy) => match Pin::new(lazy).poll(&mut cx) {
                Poll::Ready(Ok(start)) => {
                    let _ = start.client_hello().server_name();
                    let config = self.server_config.clone();
                    let accept = match (self.mode >> 3) & 3 {
                        2 => start.into_stream(config),
                        _ => {
                            let (accepted, io) = start.into_inner();
                            StartHandshake::from_parts(accepted, io)
                                .into_stream_with(config, |s| s.set_buffer_limit(Some(4096)))
                        }
                    };
                    self.server = self.accept(accept);
                }
                Poll::Ready(Err(_)) => {}
                Poll::Pending => {}
            },
            Server::Accepting(f) => match Pin::new(f).poll(&mut cx) {
                Poll::Ready(Ok(s)) => self.server = Server::Ready(s.into()),
                Poll::Ready(Err(_)) => self.server = Server::Gone,
                Poll::Pending => {}
            },
            Server::Fallible(f) => match Pin::new(f).poll(&mut cx) {
                Poll::Ready(Ok(s)) => self.server = Server::Ready(s.into()),
                Poll::Ready(Err((_, _io))) => self.server = Server::Gone,
                Poll::Pending => {}
            },
            _ => {}
        }
    }

    fn stream(&mut self, side: usize) -> Option<&mut TlsStream<End>> {
        match (side, &mut self.client, &mut self.server) {
            (CLIENT, Client::Ready(s), _) | (SERVER, _, Server::Ready(s)) => Some(s),
            _ => None,
        }
    }

    fn write(&mut self, side: usize, vectored: bool, data: &[u8]) {
        let Some(stream) = self.stream(side) else {
            return;
        };
        let mut cx = cx();
        let poll = if vectored && data.len() > 1 {
            let (a, b) = data.split_at(data.len() / 2);
            Pin::new(stream).poll_write_vectored(&mut cx, &[IoSlice::new(a), IoSlice::new(b)])
        } else {
            Pin::new(stream).poll_write(&mut cx, data)
        };
        if let Poll::Ready(Ok(n)) = poll {
            assert!(n <= data.len(), "wrote more than given");
            assert!(n > 0 || data.is_empty(), "Ok(0) for a non-empty write");
            self.sent[side].extend_from_slice(&data[..n]);
        }
    }

    fn read(&mut self, side: usize, buffered: bool, size: usize) {
        let Some(stream) = self.stream(side) else {
            return;
        };
        let mut cx = cx();
        let mut got = Vec::new();
        if buffered {
            if let Poll::Ready(Ok(chunk)) = Pin::new(&mut *stream).poll_fill_buf(&mut cx) {
                let n = chunk.len().min(size.max(1));
                got.extend_from_slice(&chunk[..n]);
                Pin::new(stream).consume(n);
            }
        } else {
            let mut buf = vec![0; size.max(1)];
            let mut rb = ReadBuf::new(&mut buf);
            if let Poll::Ready(Ok(())) = Pin::new(stream).poll_read(&mut cx, &mut rb) {
                got.extend_from_slice(rb.filled());
            }
        }
        self.received[side].extend_from_slice(&got);
        self.check();
    }

    /// The server reads the 0-RTT data it accepted.
    fn early_read(&mut self) {
        if let Server::Ready(TlsStream::Server(s)) = &mut self.server
            && let Some(mut early) = s.get_mut().1.early_data()
        {
            let _ = early.read_to_end(&mut self.early);
        }
        self.check();
    }

    fn take_stream(&mut self, side: usize) -> Option<TlsStream<End>> {
        self.stream(side)?;
        let taken = if side == CLIENT {
            std::mem::replace(&mut self.client, Client::Gone)
        } else {
            match std::mem::replace(&mut self.server, Server::Gone) {
                Server::Ready(stream) => Client::Ready(stream),
                _ => Client::Gone,
            }
        };
        match taken {
            Client::Ready(stream) => Some(stream),
            _ => None,
        }
    }

    fn put_stream(&mut self, side: usize, stream: TlsStream<End>) {
        if side == CLIENT {
            self.client = Client::Ready(stream);
        } else {
            self.server = Server::Ready(stream);
        }
    }

    /// One write, one flush and one read through the halves of `side`'s
    /// stream.
    fn use_halves<S>(
        &mut self,
        side: usize,
        (read, write): (&mut ReadHalf<S>, &mut WriteHalf<S>),
        vectored: bool,
        data: &[u8],
        size: usize,
    ) where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        assert!(read.is_pair_of(write) && write.is_pair_of(read));
        let mut cx = cx();
        let poll = if vectored && data.len() > 1 {
            let (a, b) = data.split_at(data.len() / 2);
            Pin::new(&mut *write).poll_write_vectored(&mut cx, &[IoSlice::new(a), IoSlice::new(b)])
        } else {
            Pin::new(&mut *write).poll_write(&mut cx, data)
        };
        if let Poll::Ready(Ok(n)) = poll {
            assert!(n <= data.len(), "wrote more than given");
            assert!(n > 0 || data.is_empty(), "Ok(0) for a non-empty write");
            self.sent[side].extend_from_slice(&data[..n]);
        }
        let _ = Pin::new(write).poll_flush(&mut cx);
        let mut buf = vec![0; size.max(1)];
        let mut rb = ReadBuf::new(&mut buf);
        if let Poll::Ready(Ok(())) = Pin::new(read).poll_read(&mut cx, &mut rb) {
            self.received[side].extend_from_slice(rb.filled());
        }
    }

    /// Splits `side`'s stream (the unified stream, or the client or server
    /// stream in it), uses the halves and puts the stream back together.
    fn split(&mut self, side: usize, how: u8, data: &[u8], size: usize) {
        let Some(stream) = self.take_stream(side) else {
            return;
        };
        let (inner, write_first, vectored) = (how & 1 != 0, how & 2 != 0, how & 4 != 0);
        let stream = match stream {
            TlsStream::Client(client) if inner => {
                let (mut read, mut write) = client.into_split();
                self.use_halves(side, (&mut read, &mut write), vectored, data, size);
                TlsStream::Client(rejoin(read, write, write_first))
            }
            TlsStream::Server(server) if inner => {
                let (mut read, mut write) = server.into_split();
                self.use_halves(side, (&mut read, &mut write), vectored, data, size);
                TlsStream::Server(rejoin(read, write, write_first))
            }
            stream => {
                let (mut read, mut write) = stream.into_split();
                self.use_halves(side, (&mut read, &mut write), vectored, data, size);
                // The peer's stream is another stream: its halves pair with
                // neither of these, and a refused reunion returns both.
                if let Some(other) = self.take_stream(1 - side) {
                    let (other_read, other_write) = other.into_split();
                    assert!(!read.is_pair_of(&other_write) && !other_write.is_pair_of(&read));
                    let Err(ReuniteError(back, other_write)) = read.reunite(other_write) else {
                        panic!("halves of two streams reunited");
                    };
                    let Err(ReuniteError(other_read, back_write)) = write.reunite(other_read)
                    else {
                        panic!("halves of two streams reunited");
                    };
                    (read, write) = (back, back_write);
                    self.put_stream(1 - side, rejoin(other_read, other_write, !write_first));
                }
                rejoin(read, write, write_first)
            }
        };
        self.put_stream(side, stream);
        self.check();
    }

    fn check(&self) {
        assert_prefix(&self.received[CLIENT], &self.sent[SERVER], "client read");
        assert_prefix(&self.early, &self.sent[CLIENT], "0-RTT data");
        if !self.early_attempted {
            assert_prefix(&self.received[SERVER], &self.sent[CLIENT], "server read");
        }
    }

    fn flush_or_shutdown(&mut self, side: usize, shutdown: bool) {
        if let Some(stream) = self.stream(side) {
            let mut cx = cx();
            let _ = if shutdown {
                Pin::new(stream).poll_shutdown(&mut cx)
            } else {
                Pin::new(stream).poll_flush(&mut cx)
            };
        }
    }

    fn accessors(&mut self, side: usize) {
        let _ = (self.connector.config(), self.server_config.fips());
        match (side, &mut self.client, &mut self.server) {
            // A handshake future shows a connection only while it shows its
            // transport (it may have only an alert left to send, or nothing
            // at all once it returned), and `&` and `&mut` access agree.
            (CLIENT, Client::Connecting(f), _) => {
                let io = (f.get_ref().is_some(), f.get_mut().is_some());
                let conn = (f.connection().is_some(), f.connection_mut().is_some());
                check_future_accessors(io, conn);
            }
            (CLIENT, Client::Fallible(f), _) => {
                let io = (f.get_ref().is_some(), f.get_mut().is_some());
                let conn = (f.connection().is_some(), f.connection_mut().is_some());
                check_future_accessors(io, conn);
            }
            (SERVER, _, Server::Accepting(f)) => {
                let io = (f.get_ref().is_some(), f.get_mut().is_some());
                let conn = (f.connection().is_some(), f.connection_mut().is_some());
                check_future_accessors(io, conn);
                if let Some(conn) = f.connection() {
                    let _ = (conn.is_handshaking(), conn.server_name());
                }
            }
            (SERVER, _, Server::Fallible(f)) => {
                let io = (f.get_ref().is_some(), f.get_mut().is_some());
                let conn = (f.connection().is_some(), f.connection_mut().is_some());
                check_future_accessors(io, conn);
            }
            (CLIENT, Client::Ready(s), _) | (SERVER, _, Server::Ready(s)) => {
                let _ = s.get_ref().1.is_handshaking();
                let _ = s.get_mut().1.wants_write();
                match s {
                    TlsStream::Client(c) => {
                        let _ = c.get_ref().1.alpn_protocol();
                        let _ = c.get_mut().0.side;
                    }
                    TlsStream::Server(s) => {
                        let _ = s.get_ref().1.server_name();
                        let _ = s.get_mut().0.side;
                    }
                }
            }
            _ => {}
        }
        let _ = TlsAcceptor::from(self.server_config.clone()).config();
    }

    /// Polls handshakes, flushes and reads on both sides until a round
    /// changes nothing (bounded).
    fn pump(&mut self) {
        for _ in 0..2048 {
            let before = self.progress();
            for side in [CLIENT, SERVER] {
                self.poll_handshake(side);
                self.flush_or_shutdown(side, false);
                self.read(side, false, 4096);
            }
            if self.progress() == before {
                break;
            }
        }
    }

    fn progress(&self) -> (usize, usize, usize, usize, [u32; 2], [u32; 2], u8) {
        let lanes = self.lanes.borrow();
        let state = |c: bool, s: bool| u8::from(c) | u8::from(s) << 1;
        (
            lanes[0].bytes.len(),
            lanes[1].bytes.len(),
            self.received[0].len(),
            self.received[1].len(),
            lanes[0].calls,
            lanes[1].calls,
            state(
                matches!(self.client, Client::Ready(_)),
                matches!(self.server, Server::Ready(_)),
            ),
        )
    }

    /// Takes every stream apart, through `into_inner`.
    fn finish(&mut self) {
        for side in [CLIENT, SERVER] {
            let taken = if side == CLIENT {
                std::mem::replace(&mut self.client, Client::Gone)
            } else {
                match std::mem::replace(&mut self.server, Server::Gone) {
                    Server::Ready(s) => Client::Ready(s),
                    _ => Client::Gone,
                }
            };
            if let Client::Ready(stream) = taken {
                match stream {
                    TlsStream::Client(c) => drop(c.into_inner()),
                    TlsStream::Server(s) => drop(s.into_inner()),
                }
            }
        }
    }
}

pub fn run(data: &[u8]) {
    if let Some(mut world) = play(data) {
        world.finish();
    }
}

/// Runs the input's operations, leaving the world as they left it.
fn play(data: &[u8]) -> Option<World> {
    crate::init();
    let mut input = Input::new(data);
    let knobs = Knobs::read(&mut input);
    let mode = input.byte();
    let transport = input.array::<4>();
    let (Some(client_config), Some(server_config)) = (knobs.client_config(), knobs.server_config())
    else {
        return None;
    };
    let mut world = World::new(client_config, server_config, mode, transport);
    let mut connections = 1;

    for _ in 0..MAX_OPS {
        if input.is_empty() {
            break;
        }
        let op = *input.pick(&OPS);
        let side = usize::from(input.byte() & 1);
        match op {
            Op::Poll => world.poll_handshake(side),
            Op::Write => {
                let vectored = input.bool();
                let data = input.short_field();
                world.write(side, vectored, data);
            }
            Op::Read => {
                let buffered = input.bool();
                let size = usize::from(input.byte());
                world.read(side, buffered, size);
            }
            Op::Flush => world.flush_or_shutdown(side, false),
            Op::Shutdown => world.flush_or_shutdown(side, true),
            Op::Damage => {
                let position = usize::from(input.u16());
                let xor = input.byte().max(1);
                let mut lanes = world.lanes.borrow_mut();
                let lane = &mut lanes[side];
                if !lane.bytes.is_empty() {
                    let i = position % lane.bytes.len();
                    lane.bytes[i] ^= xor;
                }
            }
            Op::Inject => {
                let bytes = input.short_field();
                world.lanes.borrow_mut()[side].bytes.extend(bytes);
            }
            Op::Close => world.lanes.borrow_mut()[side].closed = true,
            Op::KeyUpdate => match world.stream(side) {
                Some(TlsStream::Client(c)) => drop(c.get_mut().1.refresh_traffic_keys()),
                Some(TlsStream::Server(s)) => drop(s.get_mut().1.refresh_traffic_keys()),
                None => {}
            },
            Op::Accessors => world.accessors(side),
            Op::EarlyRead => world.early_read(),
            Op::TakeIo => {
                if let Server::Lazy(lazy) = &mut world.server {
                    if let Some(io) = lazy.take_io() {
                        drop(io);
                    }
                    let mut cx = cx();
                    // A lazy acceptor without its transport fails.
                    assert!(matches!(Pin::new(lazy).poll(&mut cx), Poll::Ready(Err(_))));
                    world.server = Server::Gone;
                }
            }
            Op::Pump => world.pump(),
            Op::Reconnect => {
                if connections < MAX_CONNECTIONS {
                    connections += 1;
                    world.finish();
                    world.connect();
                }
            }
            Op::Split => {
                let how = input.byte();
                let data = input.short_field();
                let size = usize::from(input.byte());
                world.split(side, how, data, size);
            }
            Op::Handoff => {
                let flags = input.byte();
                world.handoff(side, flags);
            }
        }
    }
    Some(world)
}

/// Seeds: every creation mode with a full exchange, 0-RTT on a resumed
/// connection, a refused plain-text request, damaged handshakes, and an
/// exchange through split halves.
pub fn seeds() -> Vec<Vec<u8>> {
    let op = |out: &mut Vec<u8>, op: Op, side: usize| {
        out.push(op as u8);
        out.push(side as u8);
    };
    let exchange = |out: &mut Vec<u8>| {
        op(out, Op::Accessors, CLIENT);
        op(out, Op::Accessors, SERVER);
        op(out, Op::Pump, 0);
        for side in [CLIENT, SERVER] {
            op(out, Op::Write, side);
            out.push(u8::from(side == SERVER));
            put_short_field(out, b"hello through tokio");
        }
        op(out, Op::Pump, 0);
        op(out, Op::KeyUpdate, SERVER);
        op(out, Op::Write, SERVER);
        out.push(0);
        put_short_field(out, b"after a key update");
        op(out, Op::Pump, 0);
        op(out, Op::Read, CLIENT);
        out.extend([1, 7]);
        op(out, Op::Accessors, CLIENT);
        op(out, Op::Accessors, SERVER);
        op(out, Op::Shutdown, CLIENT);
        op(out, Op::Pump, 0);
        op(out, Op::Shutdown, SERVER);
        op(out, Op::Pump, 0);
    };
    let mut seeds = Vec::new();
    // TLS 1.3 then TLS 1.2, every creation mode, plain and choppy transport.
    for versions in [1u8, 2] {
        for mode in [0u8, 1, 2, 3, 4, 8, 0x0d, 0x10, 0x18, 0x20, 0x33] {
            for transport in [[255u8, 0, 255, 0], [16, 0b0101_0101, 3, 0b0011_0011]] {
                let mut s = vec![versions, 0, 0, 0, 0, mode];
                s.extend(transport);
                exchange(&mut s);
                seeds.push(s);
            }
        }
    }
    // 0-RTT: a first connection leaves a ticket, the second writes early.
    let mut s = vec![0x41, 0, 0, 0, 0, 0x40, 255, 0, 255, 0];
    op(&mut s, Op::Pump, 0);
    op(&mut s, Op::Write, SERVER);
    s.push(0);
    put_short_field(&mut s, b"ticket");
    op(&mut s, Op::Pump, 0);
    op(&mut s, Op::Reconnect, 0);
    // The connect future returns at once, before the handshake.
    op(&mut s, Op::Poll, CLIENT);
    op(&mut s, Op::Write, CLIENT);
    s.push(0);
    put_short_field(&mut s, b"early request");
    op(&mut s, Op::Pump, 0);
    op(&mut s, Op::EarlyRead, SERVER);
    op(&mut s, Op::Write, CLIENT);
    s.push(1);
    put_short_field(&mut s, b"later");
    op(&mut s, Op::Pump, 0);
    seeds.push(s);
    // Split halves, of the unified stream and of each side's own, in every
    // way to write and to reunite; each side reads what the peer's halves
    // wrote in the round before.
    for versions in [1u8, 2] {
        let mut s = vec![versions, 0, 0, 0, 0, 0, 255, 0, 255, 0];
        op(&mut s, Op::Pump, 0);
        for how in 0..SPLIT_ROUNDS {
            for side in [CLIENT, SERVER] {
                op(&mut s, Op::Split, side);
                s.push(how);
                put_short_field(&mut s, SPLIT_DATA);
                s.push(64);
            }
        }
        op(&mut s, Op::Pump, 0);
        seeds.push(s);
    }
    // A lazy acceptor refusing a plain-text request, then giving the
    // transport back.
    let mut s = vec![1, 0, 0, 0, 0, 0x10, 255, 0, 255, 0];
    op(&mut s, Op::Inject, CLIENT);
    put_short_field(&mut s, b"GET / HTTP/1.1\r\n\r\n");
    op(&mut s, Op::Poll, SERVER);
    op(&mut s, Op::TakeIo, SERVER);
    seeds.push(s);
    // Damaged handshakes, an early end of file, a lazy acceptor's refusal of
    // the configuration.
    for (lane, damage) in [
        (CLIENT, Op::Damage),
        (SERVER, Op::Damage),
        (CLIENT, Op::Close),
    ] {
        let mut s = vec![1, 0, 0, 0, 0, 0x24, 255, 0, 255, 0];
        op(&mut s, Op::Poll, CLIENT);
        op(&mut s, Op::Poll, SERVER);
        op(&mut s, damage, lane);
        if matches!(damage, Op::Damage) {
            s.extend([0, 40, 0x55]);
        }
        op(&mut s, Op::Pump, 0);
        op(&mut s, Op::Read, CLIENT);
        s.extend([0, 16]);
        seeds.push(s);
    }
    seeds.extend(handoff::seeds());
    seeds
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seeds do what they are meant to, so the harness's checks run on
    /// real traffic: data both ways, 0-RTT accepted, the lazy acceptor's
    /// refusal.
    #[test]
    fn seeds_exchange_data() {
        let seeds = seeds();
        let mut exchanged = 0;
        for seed in &seeds {
            let Some(world) = play(seed) else { continue };
            if world.received[CLIENT].ends_with(b"after a key update")
                && world.received[SERVER] == b"hello through tokio"
            {
                exchanged += 1;
            }
        }
        // Every TLS 1.3 and TLS 1.2 creation-mode seed (11 modes, two
        // transports each).
        assert_eq!(exchanged, 44);

        let early = seeds.iter().find(|s| s[5] == 0x40).expect("0-RTT seed");
        let world = play(early).expect("configurations");
        assert!(world.early_attempted);
        assert_eq!(world.early, b"early request");
        assert_eq!(world.received[SERVER], b"later");

        let split: Vec<_> = seeds
            .iter()
            .filter(|s| s.get(12) == Some(&(Op::Split as u8)))
            .collect();
        assert_eq!(split.len(), 2);
        for seed in split {
            let world = play(seed).expect("configurations");
            let all = SPLIT_DATA.repeat(usize::from(SPLIT_ROUNDS));
            assert_eq!(world.received[CLIENT], all);
            assert_eq!(world.received[SERVER], all);
            assert!(matches!(world.client, Client::Ready(_)));
            assert!(matches!(world.server, Server::Ready(_)));
        }

        let refused = seeds
            .iter()
            .find(|s| s[5] == 0x10 && s.len() < 40)
            .expect("lazy seed");
        let world = play(refused).expect("configurations");
        assert!(matches!(world.server, Server::Gone));
        assert!(!world.lanes.borrow()[SERVER].bytes.is_empty(), "no alert");
    }

    /// The handoff seeds do what they are meant to: with secret extraction
    /// a polled stream becomes ready with the unread plaintext set aside,
    /// without it the stream is refused untouched, and every stream that
    /// comes back carries on.
    #[test]
    fn handoff_seeds_hand_streams_over() {
        use handoff::{AFTER, BEFORE};
        for case in handoff::cases() {
            let (_, extraction, side, flags) = case;
            let world = play(&handoff::seed(case)).expect("configurations");
            let gone = match side {
                CLIENT => matches!(world.client, Client::Gone),
                _ => matches!(world.server, Server::Gone),
            };
            let got = &world.received[side];
            if handoff::ends_the_stream(extraction, flags) {
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
        let world = play(&handoff::early_seed()).expect("configurations");
        assert!(world.early_attempted);
        assert_eq!(world.early, handoff::EARLY);
        assert_eq!(
            world.received[SERVER],
            [handoff::AFTER_EARLY, b"more"].concat()
        );
    }
}
