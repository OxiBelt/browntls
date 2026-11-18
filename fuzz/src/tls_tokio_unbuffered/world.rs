//! The two ends of one connection of `tls_tokio_unbuffered`, how they are
//! made, and the operations that poll them; the checks are in `model.rs`.

use std::cell::RefCell;
use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, Waker};

use browntls::client::UnbufferedClientConnection;
use browntls::crypto::CryptoProvider;
use browntls::server::{ServerSessionMemoryCache, UnbufferedAcceptor, UnbufferedServerConnection};
use browntls::{ClientConfig, ServerConfig, version};
use browntls_tokio::unbuffered as ub;
use browntls_tokio::{client, server};
use tokio::io::{AsyncBufRead, AsyncWrite, ReadBuf};

use super::model::{Call, Notes, Stats};
use super::transport::{End, Wire};
use crate::tls_conn::setup::{Knobs, Pki, server_name};

pub(super) const CLIENT: usize = 0;
pub(super) const SERVER: usize = 1;
/// The most plaintext one write of an unbuffered stream takes.
pub(super) const MAX_WRITE: usize = 4 * 16_384;
/// The most plaintext a vectored write gathers into one record.
pub(super) const MAX_GATHER: usize = 16_384;
/// The plaintext all writes of one input may take together.
const PLAINTEXT_BUDGET: usize = 192 * 1024;

pub(super) fn cx() -> Context<'static> {
    Context::from_waker(Waker::noop())
}

/// TLS 1.3 configurations whose record protection is the identity transform
/// (`connection::provider`): the handshake stays genuine, and records the
/// input writes are accepted once keys exist.
fn forgeable_configs(knobs: Knobs) -> Option<(ClientConfig, ServerConfig)> {
    // The provider's cipher suites are leaked to be `'static`: one provider
    // serves the whole process, or every input would leak them again.
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    let provider = PROVIDER
        .get_or_init(|| crate::connection::provider(true))
        .clone();
    let pki = Pki::get();
    let mut client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&version::TLS13])
        .ok()?
        .with_root_certificates(pki.roots.clone())
        .with_no_client_auth();
    client.enable_early_data = knobs.early_data();
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .ok()?
        .with_no_client_auth()
        .with_single_cert(pki.server_chain.clone(), pki.server_key())
        .ok()?;
    server.session_storage = ServerSessionMemoryCache::new(8);
    server.max_early_data_size = if knobs.early_data() { 1024 } else { 0 };
    Some((client, server))
}

/// What the harness needs of a stream, whichever API is behind it.
pub(super) trait Duplex: AsyncBufRead + AsyncWrite + Unpin {}

impl<T: AsyncBufRead + AsyncWrite + Unpin> Duplex for T {}

/// A stream whose handshake future returned.
pub(super) enum Stream {
    Client(Box<ub::ClientTlsStream<End>>),
    Server(Box<ub::ServerTlsStream<End>>),
    /// The streams at the crate root, as peers of the unbuffered ones.
    BufferedClient(Box<client::TlsStream<End>>),
    BufferedServer(Box<server::TlsStream<End>>),
}

impl Stream {
    pub(super) fn io(&mut self) -> Pin<&mut dyn Duplex> {
        match self {
            Self::Client(s) => Pin::new(&mut **s),
            Self::Server(s) => Pin::new(&mut **s),
            Self::BufferedClient(s) => Pin::new(&mut **s),
            Self::BufferedServer(s) => Pin::new(&mut **s),
        }
    }

    pub(super) fn unbuffered(&self) -> bool {
        matches!(self, Self::Client(_) | Self::Server(_))
    }
}

/// A handshake future.
pub(super) enum Handshake {
    Connect(ub::Connect<End>),
    FallibleConnect(ub::FallibleConnect<End>),
    Accept(ub::Accept<End>),
    FallibleAccept(ub::FallibleAccept<End>),
    BufferedConnect(browntls_tokio::Connect<End>),
    BufferedAccept(browntls_tokio::Accept<End>),
}

impl Handshake {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Stream>> {
        // A fallible future hands the transport back with the error.
        fn returned((err, io): (io::Error, End)) -> io::Error {
            let _ = io.side;
            err
        }
        match self {
            Self::Connect(f) => Pin::new(f).poll(cx).map_ok(|s| Stream::Client(Box::new(s))),
            Self::FallibleConnect(f) => Pin::new(f)
                .poll(cx)
                .map_ok(|s| Stream::Client(Box::new(s)))
                .map_err(returned),
            Self::Accept(f) => Pin::new(f).poll(cx).map_ok(|s| Stream::Server(Box::new(s))),
            Self::FallibleAccept(f) => Pin::new(f)
                .poll(cx)
                .map_ok(|s| Stream::Server(Box::new(s)))
                .map_err(returned),
            Self::BufferedConnect(f) => Pin::new(f)
                .poll(cx)
                .map_ok(|s| Stream::BufferedClient(Box::new(s))),
            Self::BufferedAccept(f) => Pin::new(f)
                .poll(cx)
                .map_ok(|s| Stream::BufferedServer(Box::new(s))),
        }
    }
}

/// The connection of a stream that was taken apart (`into_parts`), which
/// the harness goes on driving by hand.
pub(super) enum ManualConnection {
    Client(UnbufferedClientConnection),
    Server(UnbufferedServerConnection),
}

pub(super) struct Manual {
    pub(super) connection: ManualConnection,
    /// Received TLS bytes the connection has not processed yet.
    pub(super) incoming: Vec<u8>,
    /// The connection closed or failed: nothing more is processed.
    pub(super) done: bool,
}

/// One end of the connection.
pub(super) enum Side {
    Handshaking(Box<Handshake>),
    /// The lazy acceptor, and whether it failed already.
    Lazy(Box<ub::LazyConfigAcceptor<End>>, bool),
    /// A ClientHello read by the harness itself, for `from_parts`.
    ByHand(Box<UnbufferedAcceptor>, Vec<u8>, End),
    Ready(Stream),
    Manual(Box<Manual>),
    Gone,
}

impl Side {
    pub(super) fn established(&self) -> bool {
        matches!(self, Self::Ready(_) | Self::Manual(_))
    }

    /// A number that changes with the state.
    pub(super) fn stage(&self) -> u8 {
        match self {
            Self::Handshaking(_) => 0,
            Self::Lazy(_, failed) => 1 + u8::from(*failed),
            Self::ByHand(..) => 3,
            Self::Ready(_) => 4,
            Self::Manual(manual) => 5 + u8::from(manual.done),
            Self::Gone => 7,
        }
    }
}

pub(super) struct World {
    pub(super) knobs: Knobs,
    client_config: Arc<ClientConfig>,
    pub(super) server_config: Arc<ServerConfig>,
    /// A configuration for other protocol versions, which a lazy acceptor
    /// may choose: it serves some ClientHellos and refuses others.
    other_server_config: Option<Arc<ServerConfig>>,
    pub(super) connector: ub::TlsConnector,
    pub(super) acceptor: ub::TlsAcceptor,
    /// How each side is created (see the module documentation).
    pub(super) mode: [u8; 2],
    transport: [u8; 8],
    pub(super) wire: Rc<RefCell<Wire>>,
    pub(super) sides: [Side; 2],
    /// Plaintext each side wrote.
    pub(super) sent: [Vec<u8>; 2],
    /// Plaintext each side read, as ordinary data.
    pub(super) received: [Vec<u8>; 2],
    /// 0-RTT data taken from the server.
    pub(super) early: Vec<u8>,
    /// The client's connect returned before its handshake (0-RTT).
    pub(super) early_attempted: bool,
    pub(super) notes: [Notes; 2],
    /// Bytes on the wire were damaged, inserted or cut off, or a lane was
    /// made to fail: errors are expected, and arrival is not.
    pub(super) disturbed: bool,
    /// Something was asked of the connection whose refusal is legitimate
    /// (many key updates, post-handshake authentication).
    pub(super) lenient: bool,
    /// The configurations protect TLS 1.3 records with the identity
    /// transform: what the input writes on the wire is accepted as records.
    pub(super) forgeable: bool,
    pub(super) key_updates: u32,
    /// The exporter value each side derived.
    pub(super) exporters: [Option<[u8; 32]>; 2],
    /// The most received TLS bytes a stream may hold unprocessed.
    pub(super) unprocessed_limit: usize,
    budget: usize,
    pub(super) stats: Stats,
}

impl World {
    pub(super) fn new(knobs: Knobs, mode: [u8; 2], transport: [u8; 8]) -> Option<Self> {
        let forgeable = mode[SERVER] & 0x40 != 0;
        let (client_config, server_config) = if forgeable {
            forgeable_configs(knobs)?
        } else {
            (knobs.client_config()?, knobs.server_config()?)
        };
        let (client_config, server_config) = (Arc::new(client_config), Arc::new(server_config));
        let other_versions = match knobs.flags & 3 {
            2 => 1,
            _ => 2,
        };
        let other = Knobs {
            flags: knobs.flags & !3 | other_versions,
            ..knobs
        };
        let other_server_config = match forgeable {
            true => None,
            false => other.server_config().map(Arc::new),
        };
        let mut world = Self {
            knobs,
            connector: ub::TlsConnector::from(client_config.clone()),
            acceptor: ub::TlsAcceptor::from(server_config.clone()),
            client_config,
            server_config,
            other_server_config,
            mode,
            transport,
            wire: Wire::new(transport),
            sides: [Side::Gone, Side::Gone],
            sent: [Vec::new(), Vec::new()],
            received: [Vec::new(), Vec::new()],
            early: Vec::new(),
            early_attempted: false,
            notes: [Notes::default(); 2],
            disturbed: false,
            lenient: false,
            forgeable,
            key_updates: 0,
            exporters: [None; 2],
            unprocessed_limit: super::model::MAX_RECORD_LEN,
            budget: PLAINTEXT_BUDGET,
            stats: Stats::default(),
        };
        world.connect(mode);
        Some(world)
    }

    fn end(&self, side: usize) -> End {
        End {
            wire: self.wire.clone(),
            side,
        }
    }

    /// A fresh transport and a new client and server on it.
    pub(super) fn connect(&mut self, mode: [u8; 2]) {
        self.mode = mode;
        self.wire = Wire::new(self.transport);
        self.sent = [Vec::new(), Vec::new()];
        self.received = [Vec::new(), Vec::new()];
        self.early.clear();
        self.early_attempted = false;
        self.notes = [Notes::default(); 2];
        self.disturbed = false;
        self.lenient = false;
        self.key_updates = 0;
        self.exporters = [None; 2];
        self.unprocessed_limit = super::model::MAX_RECORD_LEN;

        let buffered_client = mode[CLIENT] & 8 != 0;
        let client = if buffered_client {
            let connector = browntls_tokio::TlsConnector::from(self.client_config.clone())
                .early_data(mode[CLIENT] & 0x10 != 0);
            Handshake::BufferedConnect(connector.connect(server_name(), self.end(CLIENT)))
        } else {
            let (name, end) = (server_name(), self.end(CLIENT));
            let alpn = || vec![b"fuzz".to_vec()];
            let connect = match mode[CLIENT] & 3 {
                0 => self.connector.connect(name, end),
                1 => self.connector.connect_with(name, end, |conn| {
                    let _ = conn.is_handshaking();
                }),
                2 => self.connector.with_alpn(alpn()).connect(name, end),
                _ => self
                    .connector
                    .with_alpn(alpn())
                    .connect_with(name, end, |_| ()),
            };
            if mode[CLIENT] & 4 != 0 {
                self.stats.fallible[CLIENT] += 1;
                Handshake::FallibleConnect(connect.into_fallible())
            } else {
                Handshake::Connect(connect)
            }
        };
        self.sides[CLIENT] = Side::Handshaking(Box::new(client));

        let end = self.end(SERVER);
        self.sides[SERVER] = match mode[SERVER] & 7 {
            1 => self.accepting(self.acceptor.accept_with(end, |conn| {
                let _ = conn.is_handshaking();
            })),
            2 | 3 => Side::Lazy(
                Box::new(ub::LazyConfigAcceptor::new(UnbufferedAcceptor::new(), end)),
                false,
            ),
            // One end is always unbuffered.
            4 if !buffered_client => {
                let acceptor = browntls_tokio::TlsAcceptor::from(self.server_config.clone());
                Side::Handshaking(Box::new(Handshake::BufferedAccept(acceptor.accept(end))))
            }
            5 => Side::ByHand(Box::new(UnbufferedAcceptor::new()), Vec::new(), end),
            _ => self.accepting(self.acceptor.accept(end)),
        };
    }

    fn accepting(&mut self, accept: ub::Accept<End>) -> Side {
        Side::Handshaking(Box::new(if self.mode[SERVER] & 8 != 0 {
            self.stats.fallible[SERVER] += 1;
            Handshake::FallibleAccept(accept.into_fallible())
        } else {
            Handshake::Accept(accept)
        }))
    }

    /// The configuration a lazy acceptor continues with.
    fn chosen_config(&self) -> Arc<ServerConfig> {
        match &self.other_server_config {
            Some(other) if self.mode[SERVER] & 0x10 != 0 => other.clone(),
            _ => self.server_config.clone(),
        }
    }

    /// Continues from a ClientHello the lazy acceptor read.
    fn start(&mut self, start: ub::StartHandshake<End>) -> Side {
        let _ = start.client_hello().server_name();
        let _ = format!("{start:?}");
        let config = self.chosen_config();
        let accept = if self.mode[SERVER] & 7 == 2 {
            start.into_stream(config)
        } else {
            let (accepted, io, incoming_tls) = start.into_parts();
            assert!(
                incoming_tls.len() <= self.unprocessed_limit,
                "{} bytes behind a ClientHello",
                incoming_tls.len()
            );
            ub::StartHandshake::from_parts(accepted, io, incoming_tls)
                .into_stream_with(config, |conn| conn.set_resumption_data(b"fuzz"))
        };
        self.accepting(accept)
    }

    /// Polls a side's handshake once.
    pub(super) fn poll_handshake(&mut self, side: usize) {
        let mut cx = cx();
        let next = match std::mem::replace(&mut self.sides[side], Side::Gone) {
            Side::Handshaking(mut handshake) => match handshake.poll(&mut cx) {
                Poll::Ready(Ok(stream)) => {
                    self.stats.handshakes += 1;
                    if let Stream::BufferedClient(stream) = &stream {
                        self.early_attempted = stream.get_ref().1.is_handshaking();
                    }
                    Side::Ready(stream)
                }
                Poll::Ready(Err(_)) => {
                    self.notes[side].errored = true;
                    Side::Gone
                }
                Poll::Pending => Side::Handshaking(handshake),
            },
            Side::Lazy(mut lazy, failed) => match Pin::new(&mut *lazy).poll(&mut cx) {
                Poll::Ready(Ok(start)) => {
                    assert!(!failed, "a lazy acceptor that failed read a ClientHello");
                    assert!(lazy.take_io().is_none(), "the transport was given twice");
                    self.start(start)
                }
                Poll::Ready(Err(_)) => {
                    self.notes[side].errored = true;
                    Side::Lazy(lazy, true)
                }
                Poll::Pending => {
                    assert!(!failed, "a lazy acceptor that failed waits again");
                    Side::Lazy(lazy, false)
                }
            },
            Side::ByHand(mut acceptor, mut incoming, end) => {
                self.wire.borrow_mut().take_all(side, &mut incoming);
                let status = acceptor.accept(&mut incoming);
                incoming.drain(..status.discard.min(incoming.len()));
                match status.state {
                    Ok(Some(accepted)) => {
                        // More than a record may be waiting behind the hello.
                        self.unprocessed_limit = self.unprocessed_limit.max(incoming.len());
                        let start = ub::StartHandshake::from_parts(accepted, end, incoming);
                        let config = self.chosen_config();
                        self.accepting(start.into_stream(config))
                    }
                    Ok(None) => Side::ByHand(acceptor, incoming, end),
                    Err(_) => {
                        self.notes[side].errored = true;
                        Side::Gone
                    }
                }
            }
            other => other,
        };
        self.sides[side] = next;
        self.audit(side);
    }

    /// The lazy acceptor gives its transport back, once.
    pub(super) fn take_io(&mut self) {
        if let Side::Lazy(lazy, _) = &mut self.sides[SERVER] {
            assert!(
                lazy.take_io().is_some(),
                "a waiting lazy acceptor has no transport"
            );
            assert!(lazy.take_io().is_none(), "the transport was given twice");
            let _ = format!("{lazy:?}");
            let poll = Pin::new(&mut **lazy).poll(&mut cx());
            assert!(
                matches!(poll, Poll::Ready(Err(_))),
                "a lazy acceptor without its transport must fail"
            );
            self.sides[SERVER] = Side::Gone;
        }
    }

    /// One write. Returns whether the stream took bytes.
    pub(super) fn write(&mut self, side: usize, vectored: bool, data: &[u8]) -> bool {
        let data = &data[..data.len().min(self.budget)];
        let Side::Ready(stream) = &mut self.sides[side] else {
            return false;
        };
        let unbuffered = stream.unbuffered();
        let mut cx = cx();
        let (poll, expected) = if vectored {
            // Four slices, one of them empty.
            let (a, rest) = data.split_at(data.len() / 4);
            let (b, c) = rest.split_at(rest.len() / 3);
            let bufs = [a, &[], b, c].map(IoSlice::new);
            let poll = stream.io().poll_write_vectored(&mut cx, &bufs);
            (poll, super::model::vectored_take(&bufs))
        } else {
            let poll = stream.io().poll_write(&mut cx, data);
            (poll, data.len().min(MAX_WRITE))
        };
        let notes = self.notes[side];
        let mut took = false;
        match poll {
            Poll::Ready(Ok(n)) => {
                assert!(n <= data.len(), "wrote more than given");
                assert!(n > 0 || data.is_empty(), "Ok(0) for a non-empty write");
                if unbuffered {
                    assert_eq!(n, expected, "a write of {} bytes", data.len());
                    assert!(n == 0 || !notes.shut, "a write after shutdown");
                    assert!(n == 0 || !notes.tls_failed, "a write after a TLS failure");
                }
                self.sent[side].extend_from_slice(&data[..n]);
                self.budget -= n;
                took = n > 0;
            }
            Poll::Ready(Err(err)) => {
                if unbuffered && notes.shut {
                    // The one error an undisturbed connection reports.
                    assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "{err}");
                } else {
                    self.failed(side, Call::Write, &err);
                }
            }
            Poll::Pending => {
                assert!(!(unbuffered && notes.shut), "a write after shutdown waits");
            }
        }
        self.audit(side);
        took
    }

    /// One read, through `poll_read` or through `poll_fill_buf` and
    /// `consume`. Returns whether it produced data.
    pub(super) fn read(&mut self, side: usize, buffered: bool, size: usize) -> bool {
        let Side::Ready(stream) = &mut self.sides[side] else {
            return false;
        };
        let unbuffered = stream.unbuffered();
        let mut cx = cx();
        let size = size.max(1);
        // An empty result is the end of the stream.
        let poll = if buffered {
            let mut io = stream.io();
            match io.as_mut().poll_fill_buf(&mut cx) {
                Poll::Ready(Ok(chunk)) => {
                    assert!(
                        !unbuffered || chunk.len() <= MAX_GATHER,
                        "{} bytes lent at once",
                        chunk.len()
                    );
                    let got = chunk[..chunk.len().min(size)].to_vec();
                    io.consume(got.len());
                    Poll::Ready(Ok(got))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            let mut buf = vec![0; size];
            let mut read_buf = ReadBuf::new(&mut buf);
            stream
                .io()
                .poll_read(&mut cx, &mut read_buf)
                .map_ok(|()| read_buf.filled().to_vec())
        };
        let notes = self.notes[side];
        let mut produced = false;
        match poll {
            Poll::Ready(Ok(got)) if got.is_empty() => {
                self.notes[side].eof = true;
                if unbuffered {
                    self.ended(side);
                }
            }
            Poll::Ready(Ok(got)) => {
                if unbuffered {
                    assert!(!notes.eof, "data after the end of the stream");
                    assert!(!notes.read_failed, "data after a failed read");
                }
                self.received[side].extend_from_slice(&got);
                self.check();
                produced = true;
            }
            Poll::Ready(Err(err)) => {
                assert!(!(unbuffered && notes.eof), "an error after the end: {err}");
                self.failed(side, Call::Read, &err);
            }
            Poll::Pending => {
                assert!(!(unbuffered && notes.eof), "a read after the end waits");
            }
        }
        self.audit(side);
        produced
    }

    /// One flush or shutdown. Returns whether it completed.
    pub(super) fn flush(&mut self, side: usize, shutdown: bool) -> bool {
        let Side::Ready(stream) = &mut self.sides[side] else {
            return false;
        };
        let mut cx = cx();
        let poll = if shutdown {
            self.notes[side].shut = true;
            stream.io().poll_shutdown(&mut cx)
        } else {
            stream.io().poll_flush(&mut cx)
        };
        if let Poll::Ready(Err(err)) = &poll {
            self.failed(side, Call::Flush, err);
        }
        self.audit(side);
        matches!(poll, Poll::Ready(Ok(())))
    }

    /// Ends every stream: through `into_inner`, or `into_parts` when the
    /// side's mode says so.
    pub(super) fn finish(&mut self) {
        self.check();
        for side in [CLIENT, SERVER] {
            let keep = self.mode[side] & 0x20 != 0;
            match std::mem::replace(&mut self.sides[side], Side::Gone) {
                Side::Ready(Stream::Client(stream)) if keep => {
                    let _ = format!("{:?}", stream.into_parts());
                }
                Side::Ready(Stream::Server(stream)) if keep => {
                    let _ = format!("{:?}", stream.into_parts());
                }
                Side::Ready(Stream::Client(stream)) => drop(stream.into_inner()),
                Side::Ready(Stream::Server(stream)) => drop(stream.into_inner()),
                Side::Ready(Stream::BufferedClient(stream)) => drop(stream.into_inner()),
                Side::Ready(Stream::BufferedServer(stream)) => drop(stream.into_inner()),
                _ => {}
            }
        }
    }
}
