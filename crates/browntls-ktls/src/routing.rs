//! Kernel TLS as the first of the places that protect a connection's
//! records, under the native provider's load-aware routing.
//!
//! The native provider can route cryptographic work between its backends
//! by what they cost at the moment (`browntls::crypto::native::accel::load`).
//! Its order of places for the records of a connection has kernel TLS in
//! front (`accel::load::kernel`) once this module has found that the
//! running kernel takes connections:
//!
//! 1. kernel TLS, after [`activate`];
//! 2. the provider's backends in userspace, in their usual order (those
//!    with dedicated instructions before those with SIMD alone).
//!
//! [`RoutedStream::new`] follows that order for one connection. While
//! kernel TLS is not active it leaves the connection in userspace. While
//! it is, the connection goes to the kernel, unless the kernel cannot take
//! it or, with `accel::load` enabled, the routing keeps it in userspace
//! because writes to the kernel have become slower than they usually are
//! and userspace measures cheaper. A connection keeps its place for life:
//! the kernel does not give one back.
//!
//! Both kinds of stream report what their writes cost (one write in
//! sixteen of at least 4096 bytes, in processor time of the calling
//! thread, so that waiting for the peer does not count), which is what
//! the routing compares. [`KtlsStream`] and `AsyncKtlsStream` report
//! theirs however they were made.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let config: std::sync::Arc<browntls::ClientConfig> = unimplemented!();
//! use std::io::Write;
//!
//! use browntls::crypto::native::accel::load;
//! use browntls_ktls::routing::{self, RoutedStream};
//!
//! // Once per process: route by load, with kernel TLS first if the
//! // kernel has it.
//! load::enable(load::Config::DEFAULT)?;
//! if let Err(err) = routing::activate() {
//!     eprintln!("no kernel TLS, staying in userspace: {err}");
//! }
//!
//! // `config` has `enable_secret_extraction` set.
//! let tcp = std::net::TcpStream::connect("example.com:443")?;
//! let conn = browntls::ClientConnection::new(config, "example.com".try_into()?)?;
//! let mut tls = RoutedStream::new(conn, tcp).map_err(|e| e.into_io_error())?;
//! println!("records protected by {}", tls.place());
//! tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")?;
//! # Ok(())
//! # }
//! ```
//!
//! # Tokio
//!
//! With the `tokio` feature, `AsyncRoutedStream::from_client` and
//! `AsyncRoutedStream::from_server` place a `browntls-tokio` stream over a
//! Tokio TCP socket by the same rules. One placed with the kernel is
//! handed over as by `AsyncKtlsStream`; one that stays in userspace is
//! kept as it is, in an `AsyncUserspaceStream` that reports what its
//! writes cost. A write is timed one poll at a time, in processor time of
//! the thread that runs the poll: the time between two polls is not
//! counted, and a poll that found the socket without room for all it
//! encrypted is reported cheaper than it is. The handshake of such a
//! stream is done before it is placed, except in a 0-RTT phase: a server
//! that accepted early data is placed by its cipher suite, a client that
//! has none yet by the order alone.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};

use browntls::Stream;
use browntls::crypto::native::accel::load::kernel;
pub use browntls::crypto::native::accel::load::kernel::{Place, Records};

use crate::meter::{Meter, records_of};
use crate::stream::{HandoffError, KtlsStream, Offload, refused, transient, unsupported};

#[cfg(feature = "tokio")]
mod async_stream;
mod probe;
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub use async_stream::{AsyncOffload, AsyncRoutedStream, AsyncUserspaceStream};

/// Puts kernel TLS at the head of the routing order, if the running
/// kernel has it: from now on [`RoutedStream::new`] hands connections to
/// the kernel (see the [module documentation](self)).
///
/// # Errors
///
/// When the kernel does not attach the `tls` upper layer protocol to a
/// TCP socket (`ENOENT` without the `tls` module), or no loopback
/// connection could be made to try it on. The order is then unchanged.
pub fn activate() -> io::Result<()> {
    probe::upper_layer_protocol()?;
    probe::forget();
    kernel::activate();
    Ok(())
}

/// Takes kernel TLS out of the routing order again: new connections stay
/// in userspace. Those the kernel has stay with it.
pub fn deactivate() {
    kernel::deactivate();
    probe::forget();
}

/// Whether kernel TLS is at the head of the routing order.
#[must_use]
pub fn is_active() -> bool {
    kernel::is_active()
}

/// A connection whose records are protected where the routing placed it:
/// by the kernel or in userspace.
///
/// Both variants read and write application data alike. What only the
/// kernel can do ([`KtlsStream::sendfile`]) is reached through the
/// variant; an application that depends on it should hand its connections
/// over with [`KtlsStream::new`] instead of asking the routing.
// One per connection, and moved rarely.
#[allow(clippy::large_enum_variant)]
pub enum RoutedStream<C: Offload, S> {
    /// The kernel protects the records.
    Kernel(KtlsStream<S, C::Data>),
    /// The connection's provider protects the records in userspace.
    Userspace(UserspaceStream<C, S>),
}

impl<C, S> RoutedStream<C, S>
where
    C: Offload,
    S: AsFd + Read + Write,
{
    /// Completes the handshake of `conn` over `socket` if needed, writes
    /// the records it left queued, then leaves the connection where the
    /// routing places it.
    ///
    /// For the kernel, `socket` must be a connected TCP socket and `conn`
    /// must have been made with `enable_secret_extraction` set, as for
    /// [`KtlsStream::new`]. A connection that the kernel cannot take (no
    /// `tls` module, a cipher suite or a configuration without a kernel
    /// form, a cipher the running kernel does not have) stays in
    /// userspace, and [`UserspaceStream::kernel_refusal`] tells why. The
    /// kernel is asked for the cipher once, with keys of zeros on a
    /// loopback socket of its own, since its refusal of a connection's
    /// own keys would come too late for the connection.
    ///
    /// # 0-RTT data
    ///
    /// A server that accepts 0-RTT data should complete the handshake and
    /// read `early_data()` before this call. What is left unread then
    /// comes where the place puts it: with the kernel it is the first
    /// data the stream returns, as with [`KtlsStream::new`], and nothing
    /// tells it from data sent after the handshake, although an attacker
    /// can replay it; in userspace it stays in `early_data()` of
    /// [`UserspaceStream::connection_mut`], unless a handover that the
    /// kernel refused had already taken it
    /// ([`UserspaceStream::received`]).
    ///
    /// # Errors
    ///
    /// [`HandoffError::Refused`] returns the connection and the socket
    /// when I/O failed before anything was given to the kernel (the
    /// handshake, or the records to be written and read before a
    /// handover; `WouldBlock` on a non-blocking socket). Its `received`
    /// is application data the handover had already taken from the
    /// connection: the caller must deliver it before anything else, also
    /// when it makes the call again with what was returned, since the
    /// next call does not take it back.
    /// [`HandoffError::Failed`] means the kernel took part of the
    /// connection's state and then failed: the connection is lost.
    pub fn new(mut conn: C, mut socket: S) -> Result<Self, HandoffError<C, S>> {
        while conn.is_handshaking() {
            let done = match conn.complete_io(&mut socket) {
                Ok((0, 0)) if conn.is_handshaking() => Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            };
            if let Err(error) = done {
                return Err(refused(conn, socket, Vec::new(), error));
            }
        }
        // The handshake's last records (a client's Finished) may still be
        // queued, and a peer that waits for them would wait for as long as
        // the caller writes and reads nothing.
        while conn.wants_write() {
            let written = match conn.write_tls(&mut socket) {
                Ok(0) => Err(io::ErrorKind::WriteZero.into()),
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            };
            if let Err(error) = written {
                return Err(refused(conn, socket, Vec::new(), error));
            }
        }
        if let Err(error) = socket.flush() {
            return Err(refused(conn, socket, Vec::new(), error));
        }
        let suite = conn.negotiated_cipher_suite();
        let records = suite.and_then(records_of);
        let place = match records {
            Some(records) => kernel::place(records),
            // No stream compares the places of such records (AES-CCM):
            // the order alone decides.
            None if kernel::is_active() => Place::Kernel,
            None => Place::Userspace,
        };
        let userspace = |conn, socket, received, refusal| {
            Ok(Self::Userspace(UserspaceStream {
                conn,
                socket,
                received,
                taken: 0,
                meter: Meter::userspace(records),
                refusal,
            }))
        };
        if place == Place::Userspace {
            return userspace(conn, socket, Vec::new(), None);
        }
        // What the kernel cannot take is found out before anything is
        // consumed, and is no error here: the next place takes it.
        if let Some(blocker) = conn.kernel_handoff_blocker()
            && !transient(blocker, &conn)
        {
            return userspace(conn, socket, Vec::new(), Some(unsupported(blocker)));
        }
        if let Err(error) = probe::ready(suite, socket.as_fd()) {
            return userspace(conn, socket, Vec::new(), Some(error));
        }
        match KtlsStream::new(conn, socket) {
            Ok(stream) => Ok(Self::Kernel(stream)),
            Err(HandoffError::Refused {
                conn,
                socket,
                received,
                error,
            }) if error.kind() == io::ErrorKind::Unsupported => {
                userspace(conn, socket, received, Some(error))
            }
            Err(other) => Err(other),
        }
    }
}

impl<C: Offload, S> RoutedStream<C, S> {
    /// Where the connection's records are protected.
    pub fn place(&self) -> Place {
        match self {
            Self::Kernel(_) => Place::Kernel,
            Self::Userspace(_) => Place::Userspace,
        }
    }
}

impl<C: Offload, S: AsFd + Read + Write> RoutedStream<C, S> {
    /// Sends `close_notify`; nothing can be written afterwards. The
    /// socket stays open for reading the rest of the peer's data.
    /// `WouldBlock` on a non-blocking socket means it waits for room:
    /// call [`Write::flush`] until it succeeds.
    pub fn send_close_notify(&mut self) -> io::Result<()> {
        match self {
            Self::Kernel(stream) => stream.send_close_notify(),
            Self::Userspace(stream) => stream.send_close_notify(),
        }
    }
}

impl<C: Offload, S: AsFd + Read + Write> Read for RoutedStream<C, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Kernel(stream) => stream.read(buf),
            Self::Userspace(stream) => stream.read(buf),
        }
    }
}

impl<C: Offload, S: AsFd + Read + Write> Write for RoutedStream<C, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Kernel(stream) => stream.write(buf),
            Self::Userspace(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Kernel(stream) => stream.flush(),
            Self::Userspace(stream) => stream.flush(),
        }
    }
}

impl<C: Offload, S: AsFd> AsFd for RoutedStream<C, S> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Kernel(stream) => stream.as_fd(),
            Self::Userspace(stream) => stream.socket.as_fd(),
        }
    }
}

impl<C: Offload, S> fmt::Debug for RoutedStream<C, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel(stream) => f.debug_tuple("Kernel").field(stream).finish(),
            Self::Userspace(stream) => f.debug_tuple("Userspace").field(stream).finish(),
        }
    }
}

/// A connection that the routing left in userspace, over its socket: a
/// [`browntls::StreamOwned`] that reports what its writes cost, and that
/// first returns the application data a refused handover had already
/// taken from the connection.
pub struct UserspaceStream<C, S> {
    conn: C,
    socket: S,
    /// Application data a refused handover took from the connection.
    received: Vec<u8>,
    /// How much of `received` was read.
    taken: usize,
    meter: Meter,
    refusal: Option<io::Error>,
}

impl<C, S> UserspaceStream<C, S> {
    /// The connection.
    pub fn connection(&self) -> &C {
        &self.conn
    }

    /// The connection. Application data read from it directly comes
    /// before its time while [`Self::received`] is not empty.
    pub fn connection_mut(&mut self) -> &mut C {
        &mut self.conn
    }

    /// The socket.
    pub fn get_ref(&self) -> &S {
        &self.socket
    }

    /// The socket.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.socket
    }

    /// Why the kernel did not take the connection, when the routing had
    /// placed it there: the kernel did not attach the `tls` upper layer
    /// protocol, or the connection has no kernel form or a cipher the
    /// running kernel does not take ([`io::ErrorKind::Unsupported`]).
    /// `None` for a connection the routing kept in userspace.
    pub fn kernel_refusal(&self) -> Option<&io::Error> {
        self.refusal.as_ref()
    }

    /// The application data that the next reads return before anything
    /// from the connection: what a refused handover had taken from it.
    /// On a server it begins with the 0-RTT data that was accepted and
    /// not read before [`RoutedStream::new`], which nothing here tells
    /// from the rest (see there).
    pub fn received(&self) -> &[u8] {
        &self.received[self.taken..]
    }

    /// The connection, the socket and [`Self::received`], which must be
    /// read before anything the connection yields.
    pub fn into_parts(mut self) -> (C, S, Vec<u8>) {
        self.received.drain(..self.taken);
        (self.conn, self.socket, self.received)
    }
}

impl<C: Offload, S: Read + Write> UserspaceStream<C, S> {
    /// Sends `close_notify`; nothing can be written afterwards.
    /// `WouldBlock` on a non-blocking socket means it waits for room:
    /// call [`Write::flush`] until it succeeds.
    pub fn send_close_notify(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        self.flush()
    }
}

impl<C: Offload, S: Read + Write> Read for UserspaceStream<C, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let received = &self.received[self.taken..];
        if !received.is_empty() && !buf.is_empty() {
            let n = received.len().min(buf.len());
            buf[..n].copy_from_slice(&received[..n]);
            self.taken += n;
            if self.taken == self.received.len() {
                self.received = Vec::new();
                self.taken = 0;
            }
            return Ok(n);
        }
        Stream::new(&mut self.conn, &mut self.socket).read(buf)
    }
}

impl<C: Offload, S: Read + Write> Write for UserspaceStream<C, S> {
    /// Encrypts `buf` and writes the records, as [`browntls::Stream`]
    /// does. The routing times some writes: on a non-blocking socket that
    /// had no room, such a write is reported cheaper than it is.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let timing = self.meter.start(buf.len());
        let written = Stream::new(&mut self.conn, &mut self.socket).write(buf)?;
        if let Some(timing) = timing {
            timing.done(written);
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Stream::new(&mut self.conn, &mut self.socket).flush()
    }
}

impl<C, S> fmt::Debug for UserspaceStream<C, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserspaceStream")
            .field("received", &(self.received.len() - self.taken))
            .field("kernel_refusal", &self.refusal)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::Arc;
    use std::thread;

    use browntls::{ClientConnection, ServerConnection};

    use super::*;
    use crate::common::{Pki, localhost, offloadable_suites, tcp_pair};

    /// What a refused handover had taken from the connection is read
    /// first, in pieces, then what the connection yields.
    #[test]
    fn the_data_of_a_refused_handover_is_read_first() {
        let pki = Pki::new();
        let suite = offloadable_suites()[0];
        let (client_tcp, server_tcp) = tcp_pair();
        let (client, server) = thread::scope(|scope| {
            let server = scope.spawn(|| {
                let conn = ServerConnection::new(Arc::new(pki.server_config(suite))).unwrap();
                RoutedStream::new(conn, server_tcp).unwrap()
            });
            let config = Arc::new(pki.client_config(suite));
            let conn = ClientConnection::new(config, localhost()).unwrap();
            // The client's last handshake records are sent by this call:
            // the server's returns without the client writing anything.
            let mut client = RoutedStream::new(conn, client_tcp).unwrap();
            let server = server.join().unwrap();
            client.write_all(b", then sent").unwrap();
            client.flush().unwrap();
            (client, server)
        });
        // No test of this process puts kernel TLS in the order.
        let (RoutedStream::Userspace(_client), RoutedStream::Userspace(server)) = (client, server)
        else {
            panic!("kernel TLS is in the order");
        };
        assert!(server.kernel_refusal().is_none());
        let (conn, socket, received) = server.into_parts();
        assert!(received.is_empty());
        let mut server = UserspaceStream {
            conn,
            socket,
            received: b"taken first".to_vec(),
            taken: 0,
            meter: Meter::userspace(None),
            refusal: Some(io::ErrorKind::Unsupported.into()),
        };

        let mut first = [0u8; 6];
        assert_eq!(server.read(&mut first).unwrap(), 6);
        assert_eq!(&first, b"taken ");
        assert_eq!(server.received(), b"first");
        // A read with room for more returns what is left of it alone.
        let mut rest = [0u8; 64];
        assert_eq!(server.read(&mut rest).unwrap(), 5);
        assert_eq!(&rest[..5], b"first");
        assert!(server.received().is_empty());
        let mut sent = [0u8; 11];
        server.read_exact(&mut sent).unwrap();
        assert_eq!(&sent, b", then sent");
        assert!(format!("{server:?}").contains("received: 0"));
        assert_eq!(
            server.kernel_refusal().map(io::Error::kind),
            Some(io::ErrorKind::Unsupported)
        );

        // Given up part of the way, the rest comes with the connection.
        server.received = b"0123456789".to_vec();
        server.read_exact(&mut [0u8; 4]).unwrap();
        let (_, _, received) = server.into_parts();
        assert_eq!(received, b"456789");
    }
}
