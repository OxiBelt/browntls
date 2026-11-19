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

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, BorrowedFd};

use browntls::Stream;
use browntls::crypto::native::accel::load::kernel;
pub use browntls::crypto::native::accel::load::kernel::{Place, Records};

use crate::meter::{Meter, records_of};
use crate::stream::{HandoffError, KtlsStream, Offload, refused, transient, unsupported};
use crate::sys;

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
    probe()?;
    kernel::activate();
    Ok(())
}

/// Takes kernel TLS out of the routing order again: new connections stay
/// in userspace. Those the kernel has stay with it.
pub fn deactivate() {
    kernel::deactivate();
}

/// Whether kernel TLS is at the head of the routing order.
#[must_use]
pub fn is_active() -> bool {
    kernel::is_active()
}

/// Asks the kernel to attach the `tls` upper layer protocol to one end of
/// a loopback connection, which it does only for a connected TCP socket.
fn probe() -> io::Result<()> {
    let mut last = None;
    for address in [
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
    ] {
        // The listener's queue completes the connection; nothing has to
        // accept it.
        let connected = TcpListener::bind(address).and_then(|listener| {
            let socket = TcpStream::connect(listener.local_addr()?)?;
            Ok((listener, socket))
        });
        match connected {
            Ok((_listener, socket)) => return sys::set_ulp_tls(socket.as_fd()),
            Err(err) => last = Some(err),
        }
    }
    Err(last.unwrap_or_else(|| io::ErrorKind::AddrNotAvailable.into()))
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
    /// Completes the handshake of `conn` over `socket` if needed, then
    /// leaves the connection where the routing places it.
    ///
    /// For the kernel, `socket` must be a connected TCP socket and `conn`
    /// must have been made with `enable_secret_extraction` set, as for
    /// [`KtlsStream::new`]. A connection that the kernel cannot take (no
    /// `tls` module, a cipher suite or a configuration without a kernel
    /// form) stays in userspace, and
    /// [`UserspaceStream::kernel_refusal`] tells why.
    ///
    /// # Errors
    ///
    /// [`HandoffError::Refused`] returns the connection and the socket
    /// when I/O failed before anything was given to the kernel (the
    /// handshake, or the records to be written and read before a
    /// handover; `WouldBlock` on a non-blocking socket, after which the
    /// call can be made again with what was returned).
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
        let records = conn.negotiated_cipher_suite().and_then(records_of);
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
        if let Err(error) = sys::set_ulp_tls(socket.as_fd()) {
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
    /// protocol, or the connection has no kernel form
    /// ([`io::ErrorKind::Unsupported`]). `None` for a connection the
    /// routing kept in userspace.
    pub fn kernel_refusal(&self) -> Option<&io::Error> {
        self.refusal.as_ref()
    }

    /// The application data that the next reads return before anything
    /// from the connection: what a refused handover had taken from it.
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
