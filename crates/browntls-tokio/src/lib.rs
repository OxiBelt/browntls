//! Asynchronous TLS streams for [Tokio](https://tokio.rs), built on
//! [`browntls`].
//!
//! [`TlsConnector`] and [`TlsAcceptor`] run a handshake over any transport
//! that implements Tokio's [`AsyncRead`] and [`AsyncWrite`] (a
//! `tokio::net::TcpStream`, a `UnixStream`, an in-memory `DuplexStream`)
//! and return a [`client::TlsStream`] or [`server::TlsStream`], which
//! implement [`AsyncRead`], [`AsyncBufRead`] and [`AsyncWrite`] over the
//! plaintext.
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use browntls_tokio::browntls::pki_types::ServerName;
//! use browntls_tokio::browntls::{ClientConfig, RootCertStore};
//! use browntls_tokio::TlsConnector;
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use tokio::net::TcpStream;
//!
//! # async fn run(roots: RootCertStore) -> std::io::Result<()> {
//! let config = ClientConfig::builder()
//!     .with_root_certificates(roots)
//!     .with_no_client_auth();
//! let connector = TlsConnector::from(Arc::new(config));
//!
//! let tcp = TcpStream::connect("example.com:443").await?;
//! let name = ServerName::try_from("example.com").expect("valid DNS name");
//! let mut tls = connector.connect(name, tcp).await?;
//!
//! tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
//! tls.flush().await?;
//! let mut response = Vec::new();
//! tls.read_to_end(&mut response).await?;
//! # Ok(())
//! # }
//! ```
//!
//! [`LazyConfigAcceptor`] reads the ClientHello first, so a server can
//! choose its [`ServerConfig`](browntls::ServerConfig) by server name, ALPN
//! or cipher suites before the handshake goes on.
//!
//! [`TlsConnector::early_data`] lets [`TlsConnector::connect`] return
//! before the handshake on a resumed TLS 1.3 session, so the first writes go
//! out as 0-RTT data. A server reads accepted early data through
//! [`server::TlsStream::early_data`], apart from ordinary reads: after the
//! handshake, or, with [`TlsAcceptor::early_data`], as it arrives, from a
//! stream that [`TlsAcceptor::accept`] returns before the client's Finished.
//! Early data can be replayed; [`TlsAcceptor::early_data`] says what that
//! means for a server that acts on it before the handshake completes.
//!
//! # Flushing
//!
//! A write encrypts the plaintext into TLS records and writes as many of
//! them to the transport as it takes without waiting; the rest stay queued
//! when the transport is not ready. Call [`flush`] when a batch of writes is
//! done: it waits until every queued record reached the transport, and
//! flushes the transport.
//!
//! A read that receives a message calling for an answer (a TLS 1.3
//! `KeyUpdate` asking for ours, a post-handshake `CertificateRequest`, a
//! failure alert) writes the answer at once, as far as the transport takes
//! it without waiting: the peer may wait for it before sending what the
//! read is waiting for. What is left goes out with the next write or flush.
//!
//! # Closing
//!
//! [`shutdown`] sends `close_notify` and then shuts the transport's write
//! side. Nothing may be written afterwards (RFC 9846 §6.1): writes then fail
//! with `BrokenPipe`. Reads go on until the peer's `close_notify`, which
//! reads as end of file. A transport that ends without one is a truncation
//! and fails the read with `UnexpectedEof`; protocols that delimit their own
//! messages may choose to treat that as end of file.
//!
//! # Splitting
//!
//! The streams are single objects, as TLS ties both directions to one
//! connection state. [`tokio::io::split`] gives independent read and write
//! halves for concurrent use from two tasks.
//!
//! [`tokio::io::split`]: https://docs.rs/tokio/1/tokio/io/fn.split.html
//!
//! # Errors
//!
//! Errors are `io::Error`s. A TLS failure (a bad record, an alert from the
//! peer, a certificate the verifier refused) has kind `InvalidData` and
//! wraps the [`browntls::Error`]:
//!
//! ```
//! fn tls_error(err: &std::io::Error) -> Option<&browntls_tokio::browntls::Error> {
//!     err.get_ref()?.downcast_ref()
//! }
//! ```
//!
//! # Features
//!
//! The crypto provider, protocol and compression features (`native`,
//! `rustcrypto`, `tls12`, `logging`, `prefer-post-quantum`, `zlib`,
//! `brotli`, `zstd`) are passed through to `browntls`. The default set
//! matches `browntls`'s.
//!
//! [`flush`]: https://docs.rs/tokio/1/tokio/io/trait.AsyncWriteExt.html#method.flush
//! [`shutdown`]: https://docs.rs/tokio/1/tokio/io/trait.AsyncWriteExt.html#method.shutdown

#![cfg_attr(docsrs, feature(doc_cfg))]

use std::io;
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket, RawSocket};
use std::pin::Pin;
use std::task::{Context, Poll};

pub use browntls;
use browntls::CommonState;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

macro_rules! ready {
    ($e:expr) => {
        match $e {
            std::task::Poll::Ready(t) => t,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

pub mod client;
mod common;
pub mod server;

pub use client::{Connect, FallibleConnect, TlsConnector, TlsConnectorWithAlpn};
pub use server::{Accept, FallibleAccept, LazyConfigAcceptor, StartHandshake, TlsAcceptor};

/// A client or a server stream, for code that handles both.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum TlsStream<T> {
    /// A stream from [`TlsConnector`].
    Client(client::TlsStream<T>),
    /// A stream from [`TlsAcceptor`].
    Server(server::TlsStream<T>),
}

impl<T> TlsStream<T> {
    /// The transport and the connection state both sides share.
    pub fn get_ref(&self) -> (&T, &CommonState) {
        match self {
            Self::Client(stream) => {
                let (io, session) = stream.get_ref();
                (io, session)
            }
            Self::Server(stream) => {
                let (io, session) = stream.get_ref();
                (io, session)
            }
        }
    }

    /// The transport and the connection state both sides share.
    pub fn get_mut(&mut self) -> (&mut T, &mut CommonState) {
        match self {
            Self::Client(stream) => {
                let (io, session) = stream.get_mut();
                (io, session)
            }
            Self::Server(stream) => {
                let (io, session) = stream.get_mut();
                (io, session)
            }
        }
    }
}

impl<T> From<client::TlsStream<T>> for TlsStream<T> {
    fn from(stream: client::TlsStream<T>) -> Self {
        Self::Client(stream)
    }
}

impl<T> From<server::TlsStream<T>> for TlsStream<T> {
    fn from(stream: server::TlsStream<T>) -> Self {
        Self::Server(stream)
    }
}

macro_rules! dispatch {
    ($self:expr, $s:ident => $e:expr) => {
        match $self {
            TlsStream::Client($s) => $e,
            TlsStream::Server($s) => $e,
        }
    };
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        dispatch!(self.get_mut(), s => Pin::new(s).poll_read(cx, buf))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncBufRead for TlsStream<T> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        dispatch!(self.get_mut(), s => Pin::new(s).poll_fill_buf(cx))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        dispatch!(self.get_mut(), s => Pin::new(s).consume(amt))
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        dispatch!(self.get_mut(), s => Pin::new(s).poll_write(cx, buf))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        dispatch!(self.get_mut(), s => Pin::new(s).poll_write_vectored(cx, bufs))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        dispatch!(self.get_mut(), s => Pin::new(s).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        dispatch!(self.get_mut(), s => Pin::new(s).poll_shutdown(cx))
    }
}

/// File descriptor and socket access to the transport, for socket options.
/// Reading or writing through it corrupts the TLS stream.
macro_rules! impl_os_handles {
    ($($ty:ty),* $(,)?) => {$(
        #[cfg(unix)]
        impl<T: AsRawFd> AsRawFd for $ty {
            fn as_raw_fd(&self) -> RawFd {
                self.get_ref().0.as_raw_fd()
            }
        }

        #[cfg(unix)]
        impl<T: AsFd> AsFd for $ty {
            fn as_fd(&self) -> BorrowedFd<'_> {
                self.get_ref().0.as_fd()
            }
        }

        #[cfg(windows)]
        impl<T: AsRawSocket> AsRawSocket for $ty {
            fn as_raw_socket(&self) -> RawSocket {
                self.get_ref().0.as_raw_socket()
            }
        }

        #[cfg(windows)]
        impl<T: AsSocket> AsSocket for $ty {
            fn as_socket(&self) -> BorrowedSocket<'_> {
                self.get_ref().0.as_socket()
            }
        }
    )*};
}

impl_os_handles!(TlsStream<T>, client::TlsStream<T>, server::TlsStream<T>);

/// Compiles the README's examples as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
