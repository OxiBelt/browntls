//! Streams over `browntls`'s unbuffered connection API
//! ([`browntls::unbuffered`]): records are decrypted where the transport put
//! them and encrypted straight into the bytes the transport is given.
//!
//! [`TlsConnector`] and [`TlsAcceptor`] here are used like the ones at the
//! crate root, and return a [`TlsStream`] over an
//! [`UnbufferedClientConnection`] or an [`UnbufferedServerConnection`]
//! ([`ClientTlsStream`], [`ServerTlsStream`]):
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use browntls_tokio::browntls::pki_types::ServerName;
//! use browntls_tokio::browntls::ClientConfig;
//! use browntls_tokio::unbuffered::TlsConnector;
//! use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
//! use tokio::net::TcpStream;
//!
//! # async fn run(config: Arc<ClientConfig>) -> std::io::Result<()> {
//! let tcp = TcpStream::connect("example.com:443").await?;
//! let name = ServerName::try_from("example.com").expect("valid DNS name");
//! let mut tls = TlsConnector::from(config).connect(name, tcp).await?;
//!
//! tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
//! tls.flush().await?;
//! // The plaintext of one record, borrowed from the receive buffer.
//! let record = tls.fill_buf().await?;
//! let len = record.len();
//! tls.consume(len);
//! # Ok(())
//! # }
//! ```
//!
//! # What differs from the streams at the crate root
//!
//! The streams at the crate root keep each connection's records in the
//! queues of a buffered [`ClientConnection`](browntls::ClientConnection) or
//! [`ServerConnection`](browntls::ServerConnection): the plaintext of a
//! received record is copied out of the connection's receive buffer into
//! an allocation of its own, which [`AsyncBufRead`] lends and
//! [`AsyncRead`] copies into the caller's buffer. Here the stream owns two
//! buffers and the connection none:
//!
//! * **Reading.** TLS bytes are read from the transport into one receive
//!   buffer of 18 437 bytes (the largest record), allocated at the first
//!   read. Each record is decrypted in place. [`AsyncBufRead`] lends that
//!   plaintext, one record per `fill_buf`, with no copy; [`AsyncRead`]
//!   copies it once, into the caller's buffer. (The received start of a
//!   record, still encrypted, moves to the front of the buffer when the
//!   rest of it would not fit behind it.)
//! * **Writing.** A write encrypts up to 65 536 bytes (four records of the
//!   largest size) into the outgoing buffer and hands it to the transport
//!   as far as the transport takes it without waiting. The next write
//!   waits until the transport took all of it, so the outgoing buffer
//!   holds the records of one write at most, besides the answers below; it
//!   grows to what that takes and is reused. A vectored write of several
//!   small slices gathers up to 16 384 bytes of them into one record.
//! * **Answers to the peer.** As at the crate root, a read writes the
//!   KeyUpdate answer, post-handshake authentication response or alert its
//!   input calls for at once, as far as the transport takes it. While more
//!   than 16 KiB of such records wait for the transport, reads take no more
//!   input.
//! * **The connection.** [`TlsStream::get_ref`] gives an unbuffered
//!   connection: the negotiated parameters, exporters and status accessors
//!   are there, the buffered connection's reader, writer and I/O methods are
//!   not. [`TlsStream::into_parts`] returns the buffers too, to go on with
//!   [`process_tls_records`] by hand or to hand the connection to the
//!   kernel. One generic [`TlsStream`] serves both sides; there is no enum
//!   over a client and a server stream.
//! * **0-RTT.** A client does not send early data here; a configuration
//!   that enables it handshakes without sending any. A server that accepts
//!   early data ([`ServerConfig::max_early_data_size`]) has it collected
//!   during the handshake: [`TlsStream::early_data`]. The acceptors have no
//!   `early_data` option: a stream is returned only after the handshake.
//!
//! Flushing, closing and errors are as described at the
//! [crate root](crate). Two things described there are not here yet. The
//! streams of this module have no `into_split`; [`tokio::io::split`] splits
//! them. And they take nothing from Tokio's task budget themselves (the
//! `coop` feature does not cover this module): a task that drives one
//! yields when its transport does, as Tokio's sockets do.
//!
//! [`tokio::io::split`]: https://docs.rs/tokio/1/tokio/io/fn.split.html
//! [`process_tls_records`]: browntls::unbuffered::UnbufferedConnectionCommon::process_tls_records
//! [`ServerConfig::max_early_data_size`]: browntls::ServerConfig::max_early_data_size
//! [`UnbufferedClientConnection`]: browntls::client::UnbufferedClientConnection
//! [`UnbufferedServerConnection`]: browntls::server::UnbufferedServerConnection

use std::fmt;
use std::io;
use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use browntls::SideData;
use browntls::client::UnbufferedClientConnection;
use browntls::server::UnbufferedServerConnection;
use browntls::unbuffered::UnbufferedConnectionCommon;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::common::{PeerRevocation, TlsState};

mod buffers;
mod driver;
mod handshake;
mod lazy;

use buffers::{Incoming, Outgoing};
pub use handshake::{
    Accept, Connect, FallibleAccept, FallibleConnect, TlsAcceptor, TlsConnector,
    TlsConnectorWithAlpn,
};
pub use lazy::{LazyConfigAcceptor, StartHandshake};

/// A TLS connection over a transport `IO`, driven through the unbuffered
/// connection `C`; see the [module documentation](self).
///
/// Reads and writes plaintext; [`AsyncWriteExt::shutdown`] sends
/// `close_notify` and shuts the transport's write side. Records the
/// transport did not take at once wait in the stream until a later write or
/// [`AsyncWriteExt::flush`].
///
/// [`AsyncWriteExt::shutdown`]: https://docs.rs/tokio/1/tokio/io/trait.AsyncWriteExt.html#method.shutdown
/// [`AsyncWriteExt::flush`]: https://docs.rs/tokio/1/tokio/io/trait.AsyncWriteExt.html#method.flush
pub struct TlsStream<IO, C> {
    io: IO,
    conn: C,
    /// Received TLS bytes, and the plaintext of the record decrypted last.
    incoming: Incoming,
    /// Encoded TLS bytes the transport has not taken yet.
    outgoing: Outgoing,
    /// 0-RTT data a server accepted during the handshake.
    early_data: Vec<u8>,
    /// Scratch space of vectored writes; empty between them.
    gather: Vec<u8>,
    state: TlsState,
    /// TLS bytes reached the transport and were not flushed yet.
    need_flush: bool,
    /// The handshake failed; its alert is on its way out.
    handshake_failure: Option<io::Error>,
    /// A read error met after a read already returned bytes.
    deferred_error: Option<io::Error>,
    /// The waker of the last write, flush or shutdown that returned
    /// `Pending`. A read that writes to the transport (to answer the peer)
    /// may take over the transport's write-readiness registration, so it
    /// registers this waker too and wakes it when it moved bytes.
    write_waker: Option<Waker>,
    /// The waker of a read waiting for the transport to take records it
    /// owes the peer. A write, flush or shutdown may take over the
    /// transport's write-readiness registration and write those bytes
    /// itself, so it wakes this waker when it moved bytes or failed.
    read_waker: Option<Waker>,
    /// A read encoded records the peer may be waiting for, and they may not
    /// all be written and flushed yet: later reads go on with that.
    answering: bool,
    /// How many bytes of records the connection queued by itself were
    /// encoded since the outgoing buffer was last empty or took a write.
    control_bytes: usize,
    /// The poll in progress wrote TLS bytes to the transport.
    moved: bool,
    /// The answers to the connection's certificate status queries.
    revocation: PeerRevocation,
}

/// A [`TlsStream`] from [`TlsConnector`].
pub type ClientTlsStream<IO> = TlsStream<IO, UnbufferedClientConnection>;

/// A [`TlsStream`] from [`TlsAcceptor`].
pub type ServerTlsStream<IO> = TlsStream<IO, UnbufferedServerConnection>;

impl<IO, C> TlsStream<IO, C> {
    /// A stream about to handshake; `incoming` holds what was received
    /// before the connection existed.
    fn new(io: IO, conn: C, incoming: Incoming, revocation: PeerRevocation) -> Self {
        Self {
            io,
            conn,
            incoming,
            outgoing: Outgoing::new(),
            early_data: Vec::new(),
            gather: Vec::new(),
            state: TlsState::Stream,
            need_flush: false,
            handshake_failure: None,
            deferred_error: None,
            write_waker: None,
            read_waker: None,
            answering: false,
            control_bytes: 0,
            moved: false,
            revocation,
        }
    }

    /// The transport and the connection.
    pub fn get_ref(&self) -> (&IO, &C) {
        (&self.io, &self.conn)
    }

    /// The transport and the connection.
    ///
    /// Reading from or writing to the transport directly corrupts the TLS
    /// stream, and so does giving the connection received bytes
    /// (`process_tls_records` with input) or encoding the records it has
    /// queued (`EncodeTlsData::encode`): the stream holds bytes of both.
    ///
    /// `process_tls_records(&mut [])`, with no input, decrypts nothing and
    /// is the way to the connection's `WriteTraffic`, for
    /// `refresh_traffic_keys`; when it returns another state, drop that:
    /// the stream handles it. What a call queues on the connection (a
    /// KeyUpdate, a server's `request_client_auth`) is sent by the next
    /// write or flush.
    pub fn get_mut(&mut self) -> (&mut IO, &mut C) {
        (&mut self.io, &mut self.conn)
    }

    /// The transport and the connection, ending the stream.
    ///
    /// Drops what the stream buffered: plaintext not read yet, TLS bytes
    /// received and not processed, and TLS bytes not written. Use
    /// [`Self::into_parts`] to keep them.
    pub fn into_inner(self) -> (IO, C) {
        (self.io, self.conn)
    }

    /// Takes the stream apart without losing what it buffered.
    ///
    /// Flush the stream first: TLS bytes already written to the transport
    /// are not flushed here. A connection whose peer has closed (reads
    /// returned end of file) reports `WriteTraffic` or `Closed` from then
    /// on, not `PeerClosed` again.
    pub fn into_parts(self) -> StreamParts<IO, C> {
        let (plaintext, incoming_tls) = self.incoming.into_parts();
        StreamParts {
            io: self.io,
            connection: self.conn,
            plaintext,
            incoming_tls,
            outgoing_tls: self.outgoing.into_unsent(),
            early_data: self.early_data,
        }
    }
}

impl<IO> TlsStream<IO, UnbufferedServerConnection> {
    /// The 0-RTT ("early") data the client sent and the server accepted
    /// during the handshake, not taken yet; empty when there was none.
    ///
    /// Early data is **replayable** by an attacker: act on it only where
    /// repeating the request is harmless. It is kept apart from the data
    /// reads return for that reason. A server accepts at most
    /// [`ServerConfig::max_early_data_size`] bytes of it (none by default).
    ///
    /// [`ServerConfig::max_early_data_size`]: browntls::ServerConfig::max_early_data_size
    pub fn early_data(&self) -> &[u8] {
        &self.early_data
    }

    /// Takes the accepted 0-RTT data out; see [`Self::early_data`].
    pub fn take_early_data(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.early_data)
    }
}

/// Lengths and state only: the buffers hold application plaintext.
impl<IO: fmt::Debug, C: fmt::Debug> fmt::Debug for TlsStream<IO, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("io", &self.io)
            .field("conn", &self.conn)
            .field("incoming", &self.incoming)
            .field("outgoing", &self.outgoing)
            .field("early_data", &self.early_data.len())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// What [`TlsStream::into_parts`] returns: the transport, the connection,
/// and everything the stream had buffered.
#[non_exhaustive]
pub struct StreamParts<IO, C> {
    /// The transport.
    pub io: IO,
    /// The connection.
    pub connection: C,
    /// Application data received and decrypted, and not read yet.
    pub plaintext: Vec<u8>,
    /// TLS bytes received from the transport and not processed yet: the
    /// front of what the next `process_tls_records` call is given. A
    /// connection handed to the kernel must have none.
    pub incoming_tls: Vec<u8>,
    /// TLS bytes encoded and not written yet: they go to the transport
    /// before anything else the connection sends.
    pub outgoing_tls: Vec<u8>,
    /// 0-RTT data a server accepted and that was not taken; see
    /// [`TlsStream::early_data`].
    pub early_data: Vec<u8>,
}

/// Lengths only: the buffers hold application plaintext.
impl<IO: fmt::Debug, C: fmt::Debug> fmt::Debug for StreamParts<IO, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamParts")
            .field("io", &self.io)
            .field("connection", &self.connection)
            .field("plaintext", &self.plaintext.len())
            .field("incoming_tls", &self.incoming_tls.len())
            .field("outgoing_tls", &self.outgoing_tls.len())
            .field("early_data", &self.early_data.len())
            .finish()
    }
}

impl<IO, C, D> AsyncRead for TlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut<Target = UnbufferedConnectionCommon<D>> + Unpin,
    D: SideData,
{
    /// Copies plaintext into `buf`, then keeps filling while more is ready
    /// without waiting. An error met after some bytes were copied is kept
    /// and returned by the next read.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(err) = this.deferred_error.take() {
            return Poll::Ready(Err(err));
        }
        let mut copied = false;
        while buf.remaining() > 0 {
            match this.poll_fill(cx) {
                Poll::Ready(Ok(())) => {
                    let chunk = this.incoming.plaintext();
                    if chunk.is_empty() {
                        break;
                    }
                    let len = chunk.len().min(buf.remaining());
                    buf.put_slice(&chunk[..len]);
                    this.incoming.consume(len);
                    copied = true;
                }
                Poll::Ready(Err(err)) if copied => {
                    this.deferred_error = Some(err);
                    break;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending if copied => break,
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<IO, C, D> AsyncBufRead for TlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut<Target = UnbufferedConnectionCommon<D>> + Unpin,
    D: SideData,
{
    /// The plaintext of the record received last that was not consumed
    /// yet, in the receive buffer; empty at the end of the stream.
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();
        if let Some(err) = this.deferred_error.take() {
            return Poll::Ready(Err(err));
        }
        ready!(this.poll_fill(cx))?;
        Poll::Ready(Ok(this.incoming.plaintext()))
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.incoming.consume(amt);
    }
}

impl<IO, C, D> AsyncWrite for TlsStream<IO, C>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    C: DerefMut<Target = UnbufferedConnectionCommon<D>> + Unpin,
    D: SideData,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_plain(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_slices(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_flush_all(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_shutdown_all(cx)
    }
}

/// File descriptor and socket access to the transport, for socket options.
/// Reading or writing through it corrupts the TLS stream.
#[cfg(unix)]
mod os {
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

    use super::TlsStream;

    impl<IO: AsRawFd, C> AsRawFd for TlsStream<IO, C> {
        fn as_raw_fd(&self) -> RawFd {
            self.io.as_raw_fd()
        }
    }

    impl<IO: AsFd, C> AsFd for TlsStream<IO, C> {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.io.as_fd()
        }
    }
}

/// Socket access to the transport, for socket options. Reading or writing
/// through it corrupts the TLS stream.
#[cfg(windows)]
mod os {
    use std::os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket, RawSocket};

    use super::TlsStream;

    impl<IO: AsRawSocket, C> AsRawSocket for TlsStream<IO, C> {
        fn as_raw_socket(&self) -> RawSocket {
            self.io.as_raw_socket()
        }
    }

    impl<IO: AsSocket, C> AsSocket for TlsStream<IO, C> {
        fn as_socket(&self) -> BorrowedSocket<'_> {
            self.io.as_socket()
        }
    }
}
