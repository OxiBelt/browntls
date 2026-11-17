//! [`KtlsStream`]: a socket whose records the kernel protects, and the
//! handover that makes one.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Read, Write};
use std::ops::DerefMut;
use std::os::fd::{AsFd, BorrowedFd};

use browntls::kernel::{KernelConnection, KernelHandoffBlocker, KernelOutput};
use browntls::{
    ClientConnection, ConnectionCommon, ConnectionTrafficSecrets, ContentType, Error,
    ExtractedSecrets, ProtocolVersion, ServerConnection, SideData,
};

use crate::crypto_info::CryptoInfo;
use crate::sys;

/// The most plaintext in one record (RFC 9846 §5.1), which the kernel puts
/// into the records it makes unless told otherwise.
const MAX_PAYLOAD: usize = 16384;

/// The most records one `write` hands to the kernel, so that the
/// connection sees the confidentiality limit coming in steps it can act on
/// (it may be passed by fewer than this many records, far below the
/// suite's margin).
const RECORDS_PER_WRITE: usize = 64;

/// `ContentType::ApplicationData`.
const APPLICATION_DATA: u8 = 23;

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
        /// What stood in the way: the kernel lacks TLS support, the
        /// connection cannot be offloaded (a [`KernelHandoffBlocker`]
        /// wrapped as [`io::ErrorKind::Unsupported`]), or I/O failed while
        /// the handshake was completed or the received records drained.
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
/// Known kernel limitation: Linux pauses reception when a handshake record
/// merely starts with the KeyUpdate type byte, or holds only the start of a
/// KeyUpdate. browntls then has no new keys to give, so the read fails
/// (`EKEYEXPIRED` from the kernel) and the connection is lost.
pub struct KtlsStream<S, Data> {
    socket: S,
    conn: KernelConnection<Data>,
    /// Plaintext received before the handover, read first.
    pending: Vec<u8>,
    pending_pos: usize,
    /// A control record being received in parts: its type and bytes.
    control: Option<(u8, Vec<u8>)>,
    /// Where the later parts of a control record are received.
    scratch: Vec<u8>,
    /// Outputs waiting behind a record the socket had no room for, in
    /// order; carried out first next time.
    backlog: VecDeque<KernelOutput>,
    /// The connection failed; every later call reports this.
    failed: Option<(io::ErrorKind, Error)>,
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
        // A smaller record size needs Linux 6.18; ask before any key is
        // set, while a refusal still leaves the connection usable.
        if conn.max_tx_payload_len().is_some() {
            match sys::has_tx_max_payload_len(socket.as_fd()) {
                Ok(true) => {}
                Ok(false) => {
                    let error = io::Error::new(
                        io::ErrorKind::Unsupported,
                        "the peer's record_size_limit needs TLS_TX_MAX_PAYLOAD_LEN (Linux 6.18)",
                    );
                    return Err(refused(conn, socket, pending, error));
                }
                Err(error) => return Err(refused(conn, socket, pending, error)),
            }
        }

        let (secrets, conn) = conn
            .into_kernel()
            .map_err(|err| HandoffError::Failed(io::Error::other(err)))?;
        let mut stream = Self {
            socket,
            conn,
            pending,
            pending_pos: 0,
            control: None,
            scratch: Vec::new(),
            backlog: VecDeque::new(),
            failed: None,
        };
        stream
            .install(secrets)
            .and_then(|()| stream.flush_outputs())
            .map_err(HandoffError::Failed)?;
        Ok(stream)
    }

    /// Installs the keys of the handover: transmit, its record size, then
    /// receive.
    fn install(&mut self, secrets: ExtractedSecrets) -> io::Result<()> {
        let version = self.conn.protocol_version();
        let (tx_seq, tx) = &secrets.tx;
        let (rx_seq, rx) = &secrets.rx;
        let tx = CryptoInfo::new(version, tx, *tx_seq).map_err(io::Error::other)?;
        let rx = CryptoInfo::new(version, rx, *rx_seq).map_err(io::Error::other)?;
        let fd = self.socket.as_fd();
        sys::set_crypto_info(fd, false, tx.as_bytes())?;
        if let Some(len) = self.conn.max_tx_payload_len() {
            // After `TLS_TX`, so that the kernel applies the TLS 1.3 bound.
            sys::set_tx_max_payload_len(fd, len)?;
        }
        sys::set_crypto_info(fd, true, rx.as_bytes())
    }
}

impl<S: AsFd, Data: SideData> KtlsStream<S, Data> {
    /// The connection's state after the handover.
    pub fn kernel_connection(&self) -> &KernelConnection<Data> {
        &self.conn
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
        self.check()?;
        let result = self.conn.records_sent(records);
        self.flush_outputs_if_room()?;
        result.map_err(|err| self.fail(err))
    }

    /// Rotates the TLS 1.3 transmit keys and asks the peer to rotate theirs.
    ///
    /// On a non-blocking socket the KeyUpdate may wait for room; it is sent,
    /// and the new keys installed, by the next write or [`Write::flush`].
    pub fn refresh_traffic_keys(&mut self) -> io::Result<()> {
        self.check()?;
        let result = self.conn.refresh_traffic_keys();
        self.flush_outputs_if_room()?;
        result.map_err(invalid_data)
    }

    /// Sends `close_notify`; nothing can be written afterwards. The socket
    /// stays open for reading the rest of the peer's data. `WouldBlock`
    /// means it waits for room: call [`Write::flush`] until it succeeds.
    pub fn send_close_notify(&mut self) -> io::Result<()> {
        self.check()?;
        self.conn.send_close_notify();
        self.flush_outputs()
    }

    /// Carries out the connection's outputs in order: control records,
    /// then new keys.
    ///
    /// When the socket has no room for a record (`WouldBlock`), the record
    /// and every output after it wait in the backlog, except new receive
    /// keys, which are installed at once: reception must not wait for
    /// transmission, and the two directions' keys are independent.
    fn flush_outputs(&mut self) -> io::Result<()> {
        while let Some(output) = self.conn.pop_output() {
            self.backlog.push_back(output);
        }
        let version = self.conn.protocol_version();
        while let Some(output) = self.backlog.pop_front() {
            let fd = self.socket.as_fd();
            let result = match &output {
                KernelOutput::Record { typ, payload } => {
                    sys::send_record(fd, u8::from(*typ), payload)
                }
                KernelOutput::TxKeys(secrets) => install_keys(fd, version, false, secrets),
                KernelOutput::RxKeys(secrets) => install_keys(fd, version, true, secrets),
                other => Err(io::Error::other(format!("unknown kernel output {other:?}"))),
            };
            match result {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.backlog.push_front(output);
                    return match self.install_waiting_rx_keys(version) {
                        Ok(()) => Err(err),
                        Err(err) => Err(self.output_failed(err)),
                    };
                }
                Err(err) => return Err(self.output_failed(err)),
            }
        }
        Ok(())
    }

    /// Installs the receive keys waiting in the backlog, keeping the rest
    /// in order.
    fn install_waiting_rx_keys(&mut self, version: ProtocolVersion) -> io::Result<()> {
        let mut rest = VecDeque::with_capacity(self.backlog.len());
        while let Some(output) = self.backlog.pop_front() {
            match output {
                KernelOutput::RxKeys(secrets) => {
                    install_keys(self.socket.as_fd(), version, true, &secrets)?;
                }
                other => rest.push_back(other),
            }
        }
        self.backlog = rest;
        Ok(())
    }

    /// An output that did not happen leaves the kernel's state behind the
    /// connection's: nothing more can be sent safely.
    fn output_failed(&mut self, err: io::Error) -> io::Error {
        // What was queued behind it (records, keys) would now go out of
        // step with the kernel: drop it.
        self.backlog.clear();
        while self.conn.pop_output().is_some() {}
        self.fail_with(err.kind(), Error::General(format!("kernel TLS: {err}")))
    }

    /// Carries out the outputs, tolerating a full socket: what waits is
    /// sent by a later call.
    fn flush_outputs_if_room(&mut self) -> io::Result<()> {
        match self.flush_outputs() {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(()),
            other => other,
        }
    }

    fn check(&self) -> io::Result<()> {
        match &self.failed {
            Some((kind, err)) => Err(io::Error::new(*kind, err.clone())),
            None => Ok(()),
        }
    }

    fn fail(&mut self, err: Error) -> io::Error {
        self.fail_with(io::ErrorKind::InvalidData, err)
    }

    fn fail_with(&mut self, kind: io::ErrorKind, err: Error) -> io::Error {
        self.failed = Some((kind, err.clone()));
        io::Error::new(kind, err)
    }

    /// Takes plaintext received before the handover.
    fn read_pending(&mut self, buf: &mut [u8]) -> Option<usize> {
        let rest = self.pending.get(self.pending_pos..)?;
        if rest.is_empty() {
            return None;
        }
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.pending_pos += n;
        if self.pending_pos == self.pending.len() {
            self.pending = Vec::new();
            self.pending_pos = 0;
        }
        Some(n)
    }

    /// Handles a whole control record.
    fn handle_control(&mut self, typ: u8, payload: &[u8]) -> io::Result<()> {
        let result = self.conn.handle_record(ContentType::from(typ), payload);
        // A failure leaves a fatal alert to send; one the socket has no
        // room for is sent by `flush`.
        let flushed = self.flush_outputs_if_room();
        result.map_err(|err| self.fail(err))?;
        flushed
    }
}

impl<S: AsFd, Data: SideData> Read for KtlsStream<S, Data> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(n) = self.read_pending(buf) {
            return Ok(n);
        }
        loop {
            self.check()?;
            if self.conn.peer_has_closed() {
                return Ok(0);
            }
            // Keys to install come before the next record; answers owed are
            // sent when there is room (or by the next write or flush).
            self.flush_outputs_if_room()?;
            let continuing = self.control.as_ref().map(|(typ, _)| *typ);
            let into: &mut [u8] = if continuing.is_some() {
                self.scratch.resize(MAX_PAYLOAD + 256, 0);
                &mut self.scratch
            } else {
                buf
            };
            let received = match sys::recv(self.socket.as_fd(), into, false) {
                Ok(received) => received,
                Err(err) if err.raw_os_error() == Some(libc::EKEYEXPIRED) => {
                    // Every new receive key was installed before this read,
                    // so the kernel paused for a KeyUpdate browntls did not
                    // see whole (see the type's documentation).
                    return Err(self.fail(Error::General(
                        "kernel TLS paused reception without a complete KeyUpdate".into(),
                    )));
                }
                Err(err) => return Err(err),
            };
            let Some(typ) = received.record_type else {
                // No record: the peer closed TCP.
                if received.len == 0 {
                    return Err(self.fail_with(
                        io::ErrorKind::UnexpectedEof,
                        Error::General("peer closed the connection without close_notify".into()),
                    ));
                }
                return Err(self.fail(Error::General("kernel TLS reported no record type".into())));
            };
            if continuing.is_some_and(|t| t != typ) {
                return Err(self.fail(Error::General("kernel TLS interleaved record types".into())));
            }
            if typ == APPLICATION_DATA {
                if received.len == 0 {
                    continue;
                }
                self.conn.application_data_received();
                return Ok(received.len);
            }
            let (_, bytes) = self.control.get_or_insert_with(|| (typ, Vec::new()));
            if continuing.is_some() {
                bytes.extend_from_slice(&self.scratch[..received.len]);
            } else {
                bytes.extend_from_slice(&buf[..received.len]);
                // Control record bytes (session tickets, for example) do
                // not stay in the caller's buffer.
                buf[..received.len].fill(0);
            }
            if !received.end_of_record {
                continue;
            }
            if let Some((typ, payload)) = self.control.take() {
                self.handle_control(typ, &payload)?;
            }
        }
    }
}

impl<S: AsFd, Data: SideData> Write for KtlsStream<S, Data> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check()?;
        self.flush_outputs()?;
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.conn.may_send_application_data() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the connection is closed for sending",
            ));
        }
        let max = self
            .conn
            .max_tx_payload_len()
            .map_or(MAX_PAYLOAD, usize::from);
        let take = buf.len().min(max * RECORDS_PER_WRITE);
        let sent = sys::send(self.socket.as_fd(), &buf[..take])?;
        // A plain `send` closes its last record, so `sent` bytes made at
        // most this many (barring the kernel closing records early under
        // memory pressure).
        let records = u64::try_from(sent.div_ceil(max)).unwrap_or(u64::MAX);
        let result = self.conn.records_sent(records);
        if let Err(err) = result {
            // The bytes were sent; the next call reports the failure.
            self.failed = Some((io::ErrorKind::InvalidData, err));
        }
        // The bytes were sent, so this call succeeds whatever happens to
        // the outputs (a key refresh): what waits goes out next time, and
        // a failure is reported by the next call.
        let _ = self.flush_outputs();
        Ok(sent)
    }

    /// Sends what waits, including a fatal alert after a failure.
    fn flush(&mut self) -> io::Result<()> {
        if self.failed.is_some() && self.backlog.is_empty() && !self.conn.has_output() {
            return self.check();
        }
        let flushed = self.flush_outputs();
        self.check()?;
        flushed
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
            .field("conn", &self.conn)
            .field("pending", &(self.pending.len() - self.pending_pos))
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

/// Installs new keys for one direction from sequence number zero.
fn install_keys(
    fd: BorrowedFd<'_>,
    version: ProtocolVersion,
    receive: bool,
    secrets: &ConnectionTrafficSecrets,
) -> io::Result<()> {
    let info = CryptoInfo::new(version, secrets, 0).map_err(io::Error::other)?;
    sys::set_crypto_info(fd, receive, info.as_bytes())
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
            let missing = conn.bytes_to_record_boundary();
            if missing > 0 {
                // Exactly the rest of the record: what follows is the
                // kernel's.
                let mut limited = Read::take(&mut *socket, missing as u64);
                if conn.read_tls(&mut limited)? == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
            }
            let state = conn.process_new_packets().map_err(invalid_data)?;
            if state.peer_has_closed()
                && conn.kernel_handoff_blocker() == Some(KernelHandoffBlocker::UnprocessedInput)
            {
                // Processing stops at the peer's close_notify: what follows
                // it would stay unprocessed for good.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "data follows the peer's close_notify",
                ));
            }
        }
        other => return Err(unsupported(other)),
    }
    Ok(())
}

fn refused<C, S>(conn: C, socket: S, received: Vec<u8>, error: io::Error) -> HandoffError<C, S> {
    HandoffError::Refused {
        conn,
        socket,
        received,
        error,
    }
}

fn unsupported(blocker: KernelHandoffBlocker) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, blocker.to_string())
}

fn invalid_data(err: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}
