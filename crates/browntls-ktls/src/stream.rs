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

use crate::engine::{Engine, invalid_data, option_error};
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
/// On non-blocking sockets (and, as the kernel's code reads, untested
/// here, on sockets with a send timeout) Linux reports a write as done
/// once the record is encrypted, even when TCP had no room for all of it,
/// and sends the rest when room appears. Shutting the socket's write side
/// or closing it before then drops what is left, and the peer sees a
/// truncated stream. [`unsent`](Self::unsent) tells how much the kernel
/// still holds: before closing such a socket, send what the stream itself
/// still holds ([`Write::flush`] until it succeeds) and wait until
/// `unsent` is zero. While it is not, wait for the socket to be writable;
/// if it is writable already, the kernel is about to send, usually within
/// microseconds, so ask again after a short pause and not in a tight loop.
/// A blocking socket without a send timeout waits inside the write and
/// needs no such care.
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
    ///
    /// The stream then no longer knows what the socket was given:
    /// [`Self::unsent`] reports `Unsupported` from this call on.
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

    /// How many bytes of TLS records the kernel has accepted from this
    /// stream and not yet given to TCP.
    ///
    /// Zero means that everything the kernel accepted so far, control
    /// records included, is in TCP's hands, which delivers it or reports a
    /// failure as for any socket: the write side can then be shut, or the
    /// socket closed, without cutting the stream short. A control record
    /// the socket had no room for at all (`WouldBlock` from
    /// [`Self::send_close_notify`] or [`Write::flush`]) is still with the
    /// stream and not counted here. On a blocking socket without a send
    /// timeout this is zero after every call. On other sockets the kernel
    /// sends what is left when TCP has room (see the type's
    /// documentation for how to wait). The number may be reported higher
    /// than it is when acknowledgements kept arriving while it was read,
    /// never lower.
    ///
    /// It is worked out from two counters the kernel keeps (the records it
    /// has made and the bytes TCP has taken) and the plaintext this stream
    /// handed over. The error is [`io::ErrorKind::Unsupported`] when the
    /// stream has no such count: the counters could not be read at the
    /// handover, or bytes were sent on the socket directly
    /// ([`Self::records_sent`]). Any other error means the counters cannot
    /// be read or do not fit together, as after the write side was shut
    /// (TCP counts the FIN).
    pub fn unsent(&self) -> io::Result<u64> {
        let backlog = self.engine.backlog(self.socket.as_fd())?;
        Ok(backlog.unsent)
    }

    /// Tells the kernel whether to expect the peer's TLS 1.3 records to be
    /// unpadded (`TLS_RX_EXPECT_NO_PAD`; off after the handover). Setting
    /// it takes Linux 7.2 or later.
    ///
    /// A TLS 1.3 record may end in padding, which hides its content type
    /// and the length of its data until it is decrypted, so the kernel
    /// decrypts into a buffer of its own and copies the data out. With
    /// this set it decrypts straight into the buffer of a read that has
    /// room for the whole record. A record that turns out to be padded, or
    /// not application data, is decrypted a second time the usual way, so
    /// the peer decides how often the work is done twice: set it only for
    /// peers trusted not to exploit that. browntls and the Linux kernel
    /// never pad the records they send. The kernel counts the second
    /// decryptions (`TlsDecryptRetry` and `TlsRxNoPadViolation` in
    /// `/proc/net/tls_stat`).
    ///
    /// The kernel has had the option since Linux 6.0, but before 7.2 it
    /// copies the second decryption to the wrong place in the reader's
    /// buffer, so that a peer that pads corrupts what the application
    /// reads. The stream therefore refuses to set it on a kernel whose
    /// release (as `uname` gives it) is older, including an older kernel
    /// that was given the correction.
    ///
    /// While it is set, a read zeroes its buffer for up to a record's
    /// length behind the bytes it returns: the kernel's first attempt may
    /// have left plaintext there that is not application data.
    ///
    /// Setting it fails with [`io::ErrorKind::Unsupported`] on a kernel
    /// before 7.2 (a release candidate of 7.2 counts as one: the
    /// correction came with the last of them), and for TLS 1.2, whose
    /// records have no padding and are decrypted into the reader's buffer
    /// as they are. Taking it back where it was not set is no error.
    pub fn set_rx_expect_no_pad(&mut self, expect: bool) -> io::Result<()> {
        self.engine
            .set_rx_expect_no_pad(self.socket.as_fd(), expect)
    }

    /// Whether the kernel expects unpadded records
    /// ([`Self::set_rx_expect_no_pad`]). The error is
    /// [`io::ErrorKind::Unsupported`] for TLS 1.2 and when the kernel
    /// lacks the option (it came with Linux 6.0).
    pub fn rx_expect_no_pad(&self) -> io::Result<bool> {
        self.engine.rx_expect_no_pad(self.socket.as_fd())
    }

    /// Lets a network device that encrypts the records itself (kernel TLS
    /// device offload) send the pages of a file given to `sendfile`
    /// without the kernel copying them first (`TLS_TX_ZEROCOPY_RO`, Linux
    /// 5.19; off after the handover).
    ///
    /// The file must then not change until the peer has acknowledged its
    /// bytes: a retransmission would carry the changed bytes, and the
    /// peer, finding a record that does not authenticate, ends the
    /// connection. Where the kernel encrypts in software (no such device)
    /// the option is accepted and changes nothing: the ciphertext goes to
    /// pages of the kernel's own either way. The error is
    /// [`io::ErrorKind::Unsupported`] when the kernel lacks the option.
    pub fn set_tx_zerocopy_sendfile(&mut self, enable: bool) -> io::Result<()> {
        sys::set_tx_zerocopy_ro(self.socket.as_fd(), enable).map_err(option_error)
    }

    /// Whether `sendfile` may skip the kernel's copy
    /// ([`Self::set_tx_zerocopy_sendfile`]).
    pub fn tx_zerocopy_sendfile(&self) -> io::Result<bool> {
        sys::tx_zerocopy_ro(self.socket.as_fd()).map_err(option_error)
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
