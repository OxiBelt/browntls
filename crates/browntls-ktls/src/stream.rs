//! [`KtlsStream`]: a socket whose records the kernel protects, and the
//! handover that makes one.

use std::fmt;
use std::io::{self, Read, Write};
use std::ops::DerefMut;
use std::os::fd::{AsFd, BorrowedFd};

use browntls::kernel::{KernelConnection, KernelHandoffBlocker};
use browntls::{
    ClientConnection, ConnectionCommon, Error, ExtractedSecrets, ServerConnection, SideData,
};

use crate::engine::{Engine, invalid_data};
use crate::sys;

mod sealed {
    pub trait Sealed {}
    impl Sealed for browntls::ClientConnection {}
    impl Sealed for browntls::ServerConnection {}
}

/// A buffered browntls connection that [`KtlsStream::new`] can hand to the
/// kernel: [`ClientConnection`] or [`ServerConnection`].
pub trait Offload:
    sealed::Sealed + DerefMut<Target = ConnectionCommon<Self::Data>> + Sized
{
    /// The connection's side.
    type Data: SideData;

    /// Moves 0-RTT data a server accepted and has not read into `out`.
    #[doc(hidden)]
    fn take_early_data(&mut self, out: &mut Vec<u8>) -> io::Result<()>;

    /// `dangerous_into_kernel_connection`.
    #[doc(hidden)]
    fn into_kernel(self) -> Result<(ExtractedSecrets, KernelConnection<Self::Data>), Error>;
}

impl Offload for ClientConnection {
    type Data = browntls::client::ClientConnectionData;

    fn take_early_data(&mut self, _out: &mut Vec<u8>) -> io::Result<()> {
        Ok(())
    }

    fn into_kernel(self) -> Result<(ExtractedSecrets, KernelConnection<Self::Data>), Error> {
        self.dangerous_into_kernel_connection()
    }
}

impl Offload for ServerConnection {
    type Data = browntls::server::ServerConnectionData;

    fn take_early_data(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        match self.early_data() {
            Some(mut early) => early.read_to_end(out).map(|_| ()),
            None => Ok(()),
        }
    }

    fn into_kernel(self) -> Result<(ExtractedSecrets, KernelConnection<Self::Data>), Error> {
        self.dangerous_into_kernel_connection()
    }
}

/// Why [`KtlsStream::new`] did not hand a connection to the kernel.
pub enum HandoffError<C, S> {
    /// Nothing was given to the kernel: the connection and the socket are
    /// returned as they were, and can go on in userspace (or try again,
    /// for example after `WouldBlock` on a non-blocking socket).
    ///
    /// The socket may carry the kernel's `tls` upper layer protocol without
    /// keys, which leaves its bytes untouched.
    Refused {
        /// The connection, still usable unless `error` came from it.
        conn: C,
        /// The socket.
        socket: S,
        /// Application data the handover had already taken from the
        /// connection, to be read before anything the connection yields.
        received: Vec<u8>,
        /// What stood in the way: the kernel did not attach the `tls`
        /// upper layer protocol (no `tls` module: `ENOENT`; a peer that
        /// has already closed TCP: `ENOTCONN`), the connection cannot be
        /// offloaded (a [`KernelHandoffBlocker`] wrapped as
        /// [`io::ErrorKind::Unsupported`]), or I/O failed while the
        /// handshake was completed or the received records drained.
        error: io::Error,
    },
    /// The kernel took part of the connection's state and then failed: the
    /// connection is lost and the socket was closed.
    Failed(io::Error),
}

impl<C, S> HandoffError<C, S> {
    /// The error, dropping the connection and the socket.
    pub fn into_io_error(self) -> io::Error {
        match self {
            Self::Refused { error, .. } | Self::Failed(error) => error,
        }
    }
}

impl<C, S> fmt::Debug for HandoffError<C, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused {
                error, received, ..
            } => f
                .debug_struct("Refused")
                .field("error", error)
                .field("received", &received.len())
                .finish_non_exhaustive(),
            Self::Failed(error) => f.debug_tuple("Failed").field(error).finish(),
        }
    }
}

impl<C, S> fmt::Display for HandoffError<C, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { error, .. } => write!(f, "kernel TLS handover refused: {error}"),
            Self::Failed(error) => write!(f, "kernel TLS handover failed: {error}"),
        }
    }
}

impl<C, S> std::error::Error for HandoffError<C, S> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused { error, .. } | Self::Failed(error) => Some(error),
        }
    }
}

/// A TCP socket whose records Linux kernel TLS protects, with the browntls
/// connection that handles everything that is not application data.
///
/// Reading returns the application data the kernel decrypted; records of
/// other types are handled on the way (a TLS 1.3 KeyUpdate is answered and
/// the new keys installed, tickets are stored, `close_notify` ends the
/// stream). Writing gives the bytes to the kernel, which makes records of
/// them, and counts those records against the cipher suite's
/// confidentiality limit, refreshing the TLS 1.3 keys when it is reached.
///
/// Errors from the connection are reported as [`io::ErrorKind::InvalidData`]
/// with the [`browntls::Error`] inside; the connection has then sent its
/// alert and failed for good.
///
/// The socket may be non-blocking: `WouldBlock` then means "call again when
/// the socket is readable or writable", since a read may first have to send
/// a control record (a KeyUpdate answer) that did not fit.
///
/// Known kernel limitation, on non-blocking sockets (and, as the kernel's
/// code reads, untested here, on sockets with a send timeout): Linux
/// reports a write as done once the record is encrypted, even when TCP
/// had no room for all of it, and sends the rest when room appears;
/// nothing tells userspace when that has happened. Shutting the socket's write side or closing it
/// before then drops what is left, and the peer sees a truncated stream.
/// Waiting until the socket is writable before closing it covers the wait
/// for room, but not the moment between room appearing and the kernel
/// sending: where the last bytes matter, let the peer confirm them (its
/// `close_notify`) before closing. A blocking socket without a send
/// timeout waits inside the write and needs no such care.
///
/// Known kernel limitation: Linux pauses reception when a handshake record
/// merely starts with the KeyUpdate type byte, or holds only the start of a
/// KeyUpdate. browntls then has no new keys to give, so the read fails
/// (`EKEYEXPIRED` from the kernel) and the connection is lost.
pub struct KtlsStream<S, Data> {
    socket: S,
    engine: Engine<Data>,
}

impl<S, Data> KtlsStream<S, Data>
where
    S: AsFd,
    Data: SideData,
{
    /// Completes the handshake of `conn` over `socket` if needed, then
    /// hands the connection to the kernel.
    ///
    /// `socket` must be a connected TCP socket, and `conn` must have been
    /// made with `enable_secret_extraction` set. Before the handover the
    /// stream writes the queued records, keeps the application data already
    /// received (it is read first), and reads exactly up to the next record
    /// boundary, so that the kernel starts with a whole record.
    ///
    /// When the kernel lacks TLS support (no `tls` module), or the
    /// connection cannot be offloaded, the connection and the socket come
    /// back unharmed in [`HandoffError::Refused`].
    ///
    /// A refused handover can be tried again on the same socket.
    pub fn new<C>(mut conn: C, mut socket: S) -> Result<Self, HandoffError<C, S>>
    where
        C: Offload<Data = Data>,
        S: Read + Write,
    {
        if let Some(blocker) = conn.kernel_handoff_blocker()
            && !transient(blocker, &conn)
        {
            return Err(refused(conn, socket, Vec::new(), unsupported(blocker)));
        }
        // Checks kernel support before anything is consumed: with the
        // upper layer protocol attached but no keys, the socket passes its
        // bytes through unchanged.
        if let Err(error) = sys::set_ulp_tls(socket.as_fd()) {
            return Err(refused(conn, socket, Vec::new(), error));
        }

        let mut pending = Vec::new();
        while let Some(blocker) = conn.kernel_handoff_blocker() {
            let step = if transient(blocker, &conn) {
                drain_step(&mut conn, &mut socket, blocker, &mut pending)
            } else {
                Err(unsupported(blocker))
            };
            if let Err(error) = step {
                return Err(refused(conn, socket, pending, error));
            }
        }
        if let Err(error) = check_record_size(&conn, socket.as_fd()) {
            return Err(refused(conn, socket, pending, error));
        }
        match install(conn, socket.as_fd(), pending) {
            Ok(engine) => Ok(Self { socket, engine }),
            Err(error) => Err(HandoffError::Failed(error)),
        }
    }
}

impl<S: AsFd, Data: SideData> KtlsStream<S, Data> {
    /// The connection's state after the handover.
    pub fn kernel_connection(&self) -> &KernelConnection<Data> {
        self.engine.conn()
    }

    /// The socket.
    ///
    /// Bytes sent on it directly (for example with `sendfile`) become
    /// application data records the stream did not count: report them with
    /// [`Self::records_sent`].
    pub fn get_ref(&self) -> &S {
        &self.socket
    }

    /// Reports `records` application data records sent on the socket
    /// directly, then carries out what the connection asks for (a key
    /// refresh at the confidentiality limit). Overcount when unsure: one
    /// `send` of `n` bytes without `MSG_MORE` makes at most
    /// `n.div_ceil(16384)` records.
    ///
    /// On a non-blocking socket what the socket has no room for is sent by
    /// the next write or [`Write::flush`].
    pub fn records_sent(&mut self, records: u64) -> io::Result<()> {
        self.engine.records_sent(self.socket.as_fd(), records)
    }

    /// Rotates the TLS 1.3 transmit keys and asks the peer to rotate theirs.
    ///
    /// On a non-blocking socket the KeyUpdate may wait for room; it is sent,
    /// and the new keys installed, by the next write or [`Write::flush`].
    pub fn refresh_traffic_keys(&mut self) -> io::Result<()> {
        self.engine.refresh_traffic_keys(self.socket.as_fd())
    }

    /// Sends `close_notify`; nothing can be written afterwards. The socket
    /// stays open for reading the rest of the peer's data. `WouldBlock`
    /// means it waits for room: call [`Write::flush`] until it succeeds.
    pub fn send_close_notify(&mut self) -> io::Result<()> {
        self.engine.queue_close_notify()?;
        self.engine.flush_outputs(self.socket.as_fd())
    }
}

impl<S: AsFd, Data: SideData> Read for KtlsStream<S, Data> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.engine.read(self.socket.as_fd(), buf)
    }
}

impl<S: AsFd, Data: SideData> Write for KtlsStream<S, Data> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.engine.write(self.socket.as_fd(), buf)
    }

    /// Sends what waits, including a fatal alert after a failure.
    fn flush(&mut self) -> io::Result<()> {
        self.engine.flush(self.socket.as_fd())
    }
}

impl<S: AsFd, Data> AsFd for KtlsStream<S, Data> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }
}

impl<S, Data> fmt::Debug for KtlsStream<S, Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KtlsStream")
            .field("engine", &self.engine)
            .finish_non_exhaustive()
    }
}

/// Refuses a connection whose peer asked for smaller records than the
/// kernel can be told to make: `TLS_TX_MAX_PAYLOAD_LEN` needs Linux 6.18.
/// Asked with the upper layer protocol attached and before any key is set,
/// while a refusal still leaves the connection usable.
pub(crate) fn check_record_size<Data: SideData>(
    conn: &ConnectionCommon<Data>,
    fd: BorrowedFd<'_>,
) -> io::Result<()> {
    if conn.max_tx_payload_len().is_none() || sys::has_tx_max_payload_len(fd)? {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the peer's record_size_limit needs TLS_TX_MAX_PAYLOAD_LEN (Linux 6.18)",
    ))
}

/// Hands `conn`, which has nothing in flight, to the kernel socket `fd`
/// (with the upper layer protocol attached). A failure leaves the
/// connection lost: the kernel may have taken part of its state.
pub(crate) fn install<C: Offload>(
    conn: C,
    fd: BorrowedFd<'_>,
    received: Vec<u8>,
) -> io::Result<Engine<C::Data>> {
    let (secrets, conn) = conn.into_kernel().map_err(io::Error::other)?;
    Engine::install(conn, secrets, received, fd)
}

/// Whether driving the connection on can clear `blocker`.
fn transient<C: Offload>(blocker: KernelHandoffBlocker, conn: &C) -> bool {
    match blocker {
        KernelHandoffBlocker::HandshakeIncomplete => conn.is_handshaking(),
        KernelHandoffBlocker::UnreadPlaintext
        | KernelHandoffBlocker::UnprocessedInput
        | KernelHandoffBlocker::UnsentRecords => true,
        _ => false,
    }
}

/// One step towards a handover: completes the handshake, writes the queued
/// records, takes the received plaintext, or reads up to a record boundary.
fn drain_step<C, S>(
    conn: &mut C,
    socket: &mut S,
    blocker: KernelHandoffBlocker,
    pending: &mut Vec<u8>,
) -> io::Result<()>
where
    C: Offload,
    S: Read + Write,
{
    match blocker {
        KernelHandoffBlocker::HandshakeIncomplete => {
            let (read, written) = conn.complete_io(socket)?;
            if read == 0 && written == 0 && conn.is_handshaking() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        KernelHandoffBlocker::UnsentRecords => {
            if conn.write_tls(socket)? == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
        }
        KernelHandoffBlocker::UnreadPlaintext => {
            conn.take_early_data(pending)?;
            let mut chunk = [0u8; 4096];
            loop {
                match conn.reader().read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => pending.extend_from_slice(&chunk[..n]),
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) => return Err(err),
                }
            }
        }
        KernelHandoffBlocker::UnprocessedInput => {
            let state = conn.process_new_packets().map_err(invalid_data)?;
            if conn.kernel_handoff_blocker() != Some(blocker) {
                return Ok(());
            }
            if state.peer_has_closed() {
                // Processing stops at the peer's close_notify: what follows
                // it, whole or in part, would stay unprocessed for good.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "data follows the peer's close_notify",
                ));
            }
            let missing = conn.bytes_to_record_boundary();
            if missing == 0 {
                // Whole records that processing left in place.
                return Err(unsupported(blocker));
            }
            // Exactly the rest of the record: what follows is the kernel's.
            // The next step processes it.
            let mut limited = Read::take(&mut *socket, missing as u64);
            if conn.read_tls(&mut limited)? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        other => return Err(unsupported(other)),
    }
    Ok(())
}

pub(crate) fn refused<C, S>(
    conn: C,
    socket: S,
    received: Vec<u8>,
    error: io::Error,
) -> HandoffError<C, S> {
    HandoffError::Refused {
        conn,
        socket,
        received,
        error,
    }
}

pub(crate) fn unsupported(blocker: KernelHandoffBlocker) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, blocker.to_string())
}
