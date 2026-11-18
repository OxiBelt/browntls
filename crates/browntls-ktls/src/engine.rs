//! What a kernel TLS socket needs from userspace after the handover, apart
//! from the socket itself: the [`KernelConnection`], the plaintext received
//! before the handover, control records in transit and the outputs waiting
//! for room. [`KtlsStream`](crate::KtlsStream) and the Tokio stream both
//! drive one [`Engine`], passing the descriptor to every call.
//!
//! Every call that reaches the socket may return `WouldBlock` on a
//! non-blocking one. [`Engine::read`] does so only when the kernel has no
//! record to give (it tolerates a full socket for what it has to send);
//! [`Engine::write`], [`Engine::flush`] and [`Engine::flush_outputs`] only
//! when the socket has no room.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::os::fd::BorrowedFd;

use browntls::kernel::{KernelConnection, KernelOutput};
use browntls::{
    ConnectionTrafficSecrets, ContentType, Error, ExtractedSecrets, ProtocolVersion, SideData,
};

use crate::crypto_info::CryptoInfo;
use crate::ledger::{Backlog, Ledger};
use crate::sys;

/// The most plaintext in one record (RFC 9846 §5.1), which the kernel puts
/// into the records it makes unless told otherwise.
const MAX_PAYLOAD: usize = 16384;

/// The most records one `write` hands to the kernel, so that the
/// connection sees the confidentiality limit coming in steps it can act on
/// (it may be passed by fewer than this many records, far below the
/// suite's margin).
const RECORDS_PER_WRITE: usize = 64;

/// The smallest page of the architectures Linux runs on: `sendfile` takes
/// a file in parts of at least one page (but for its ends).
const SMALLEST_PAGE: usize = 4096;

/// `ContentType::ApplicationData`.
const APPLICATION_DATA: u8 = 23;

pub(crate) struct Engine<Data> {
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
    /// What the kernel was given to send, to be set against what TCP has
    /// taken. `None` when the kernel's counters could not be read, or when
    /// the socket was given bytes the engine did not see.
    ledger: Option<Ledger>,
}

impl<Data: SideData> Engine<Data> {
    /// Gives the keys of the handover to the kernel socket `fd` (which has
    /// the `tls` upper layer protocol attached) and keeps `conn` for what
    /// follows. `pending` is the plaintext received before the handover.
    pub(crate) fn install(
        conn: KernelConnection<Data>,
        secrets: ExtractedSecrets,
        pending: Vec<u8>,
        fd: BorrowedFd<'_>,
    ) -> io::Result<Self> {
        let mut engine = Self {
            conn,
            pending,
            pending_pos: 0,
            control: None,
            scratch: Vec::new(),
            backlog: VecDeque::new(),
            failed: None,
            ledger: None,
        };
        engine.install_handover_keys(fd, secrets)?;
        // The keys are in the kernel: an output a full non-blocking socket
        // has no room for waits for the next call instead of failing the
        // handover.
        engine.flush_outputs_if_room(fd)?;
        Ok(engine)
    }

    /// Installs the keys of the handover: transmit, its record size, then
    /// receive.
    fn install_handover_keys(
        &mut self,
        fd: BorrowedFd<'_>,
        secrets: ExtractedSecrets,
    ) -> io::Result<()> {
        let version = self.conn.protocol_version();
        let (tx_seq, tx) = &secrets.tx;
        let (rx_seq, rx) = &secrets.rx;
        let tx = CryptoInfo::new(version, tx, *tx_seq).map_err(io::Error::other)?;
        let rx = CryptoInfo::new(version, rx, *rx_seq).map_err(io::Error::other)?;
        sys::set_crypto_info(fd, false, tx.as_bytes())?;
        // From here on the socket's output is records; none was made yet.
        self.ledger = Ledger::open(fd, &tx, *tx_seq).ok();
        if let Some(len) = self.conn.max_tx_payload_len() {
            // After `TLS_TX`, so that the kernel applies the TLS 1.3 bound.
            sys::set_tx_max_payload_len(fd, len)?;
        }
        sys::set_crypto_info(fd, true, rx.as_bytes())
    }

    pub(crate) fn conn(&self) -> &KernelConnection<Data> {
        &self.conn
    }

    /// Whether outputs (control records, keys) wait to be carried out.
    pub(crate) fn has_outputs(&self) -> bool {
        !self.backlog.is_empty() || self.conn.has_output()
    }

    /// Whether [`Self::read`] returns without asking the kernel: plaintext
    /// from before the handover is left, the peer closed, or the
    /// connection failed.
    #[cfg(feature = "tokio")]
    pub(crate) fn reads_without_socket(&self) -> bool {
        self.pending_pos < self.pending.len()
            || self.failed.is_some()
            || self.conn.peer_has_closed()
    }

    /// See [`KtlsStream::records_sent`](crate::KtlsStream::records_sent).
    pub(crate) fn records_sent(&mut self, fd: BorrowedFd<'_>, records: u64) -> io::Result<()> {
        self.check()?;
        // Their bytes went past the engine: its count of the plaintext no
        // longer covers what the socket was given.
        self.ledger = None;
        let result = self.conn.records_sent(records);
        self.flush_outputs_if_room(fd)?;
        result.map_err(|err| self.fail(err))
    }

    /// See [`KtlsStream::refresh_traffic_keys`](crate::KtlsStream::refresh_traffic_keys).
    pub(crate) fn refresh_traffic_keys(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        self.check()?;
        let result = self.conn.refresh_traffic_keys();
        self.flush_outputs_if_room(fd)?;
        result.map_err(invalid_data)
    }

    /// See [`KtlsStream::unsent`](crate::KtlsStream::unsent).
    pub(crate) fn backlog(&self, fd: BorrowedFd<'_>) -> io::Result<Backlog> {
        match &self.ledger {
            Some(ledger) => ledger.backlog(fd),
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the stream has no count of what the kernel was given to send",
            )),
        }
    }

    /// Queues `close_notify` (once); [`Self::flush_outputs`] sends it.
    pub(crate) fn queue_close_notify(&mut self) -> io::Result<()> {
        self.check()?;
        self.conn.send_close_notify();
        Ok(())
    }

    /// Carries out the connection's outputs in order: control records,
    /// then new keys.
    ///
    /// When the socket has no room for a record (`WouldBlock`), the record
    /// and every output after it wait in the backlog, except new receive
    /// keys, which are installed at once: reception must not wait for
    /// transmission, and the two directions' keys are independent.
    pub(crate) fn flush_outputs(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        while let Some(output) = self.conn.pop_output() {
            self.backlog.push_back(output);
        }
        let version = self.conn.protocol_version();
        while let Some(output) = self.backlog.pop_front() {
            let result = match &output {
                KernelOutput::Record { typ, payload } => {
                    let sent = sys::send_record(fd, u8::from(*typ), payload);
                    if let (Ok(()), Some(ledger)) = (&sent, &mut self.ledger) {
                        ledger.sent(payload.len());
                    }
                    sent
                }
                KernelOutput::TxKeys(secrets) => {
                    // The kernel counts the records of new keys from zero:
                    // what the old keys made is read before they go.
                    let made = self.ledger.as_ref().map(|ledger| ledger.records_made(fd));
                    let installed = install_keys(fd, version, false, secrets);
                    if installed.is_ok() {
                        match (&mut self.ledger, made) {
                            (Some(ledger), Some(Ok(made))) => ledger.rekeyed(made),
                            _ => self.ledger = None,
                        }
                    }
                    installed
                }
                KernelOutput::RxKeys(secrets) => install_keys(fd, version, true, secrets),
                other => Err(io::Error::other(format!("unknown kernel output {other:?}"))),
            };
            match result {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    self.backlog.push_front(output);
                    return match self.install_waiting_rx_keys(fd, version) {
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
    fn install_waiting_rx_keys(
        &mut self,
        fd: BorrowedFd<'_>,
        version: ProtocolVersion,
    ) -> io::Result<()> {
        let mut rest = VecDeque::with_capacity(self.backlog.len());
        while let Some(output) = self.backlog.pop_front() {
            match output {
                KernelOutput::RxKeys(secrets) => {
                    install_keys(fd, version, true, &secrets)?;
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
        // step with the kernel: drop it. So is the count of what the
        // kernel was given (it may have taken part of a record).
        self.ledger = None;
        self.backlog.clear();
        while self.conn.pop_output().is_some() {}
        self.fail_with(err.kind(), Error::General(format!("kernel TLS: {err}")))
    }

    /// Carries out the outputs, tolerating a full socket: what waits is
    /// sent by a later call.
    fn flush_outputs_if_room(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        match self.flush_outputs(fd) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(()),
            other => other,
        }
    }

    /// The failure every call reports once the connection has failed.
    pub(crate) fn check(&self) -> io::Result<()> {
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
    fn handle_control(&mut self, fd: BorrowedFd<'_>, typ: u8, payload: &[u8]) -> io::Result<()> {
        let result = self.conn.handle_record(ContentType::from(typ), payload);
        // A failure leaves a fatal alert to send; one the socket has no
        // room for is sent by `flush`.
        let flushed = self.flush_outputs_if_room(fd);
        result.map_err(|err| self.fail(err))?;
        flushed
    }

    /// Reads application data: what was received before the handover, then
    /// what the kernel decrypts. Records of other types are handled on the
    /// way. `Ok(0)` (for a non-empty `buf`) is the peer's `close_notify`.
    pub(crate) fn read(&mut self, fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
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
            self.flush_outputs_if_room(fd)?;
            let continuing = self.control.as_ref().map(|(typ, _)| *typ);
            let into: &mut [u8] = if continuing.is_some() {
                self.scratch.resize(MAX_PAYLOAD + 256, 0);
                &mut self.scratch
            } else {
                buf
            };
            let received = match sys::recv(fd, into, false) {
                Ok(received) => received,
                Err(err) if err.raw_os_error() == Some(libc::EKEYEXPIRED) => {
                    // Every new receive key was installed before this read,
                    // so the kernel paused for a KeyUpdate browntls did not
                    // see whole (see `KtlsStream`'s documentation).
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
                self.handle_control(fd, typ, &payload)?;
            }
        }
    }

    /// Gives application data to the kernel: first the outputs that wait,
    /// then one `send` of at most [`RECORDS_PER_WRITE`] records.
    pub(crate) fn write(&mut self, fd: BorrowedFd<'_>, buf: &[u8]) -> io::Result<usize> {
        let Some(max) = self.before_application_data(fd, buf.len())? else {
            return Ok(0);
        };
        let take = buf.len().min(max * RECORDS_PER_WRITE);
        let sent = sys::send(fd, &buf[..take])?;
        // A plain `send` closes its last record, so `sent` bytes made at
        // most this many (barring the kernel closing records early under
        // memory pressure).
        let records = u64::try_from(sent.div_ceil(max)).unwrap_or(u64::MAX);
        Ok(self.application_data_sent(fd, sent, records))
    }

    /// See [`KtlsStream::sendfile`](crate::KtlsStream::sendfile): first the
    /// outputs that wait, then one `sendfile` of at most
    /// [`RECORDS_PER_WRITE`] records' worth of the file.
    pub(crate) fn sendfile(
        &mut self,
        fd: BorrowedFd<'_>,
        file: BorrowedFd<'_>,
        offset: u64,
        count: usize,
    ) -> io::Result<usize> {
        let Some(max) = self.before_application_data(fd, count)? else {
            return Ok(0);
        };
        let take = count.min(max * RECORDS_PER_WRITE);
        let made_before = self.records_made(fd);
        let sent = sys::sendfile(fd, file, offset, take)?;
        if sent == 0 {
            // The end of the file.
            return Ok(0);
        }
        // The kernel takes the file in parts and may close a record at the
        // end of each, so the bytes alone do not bound the records. Its
        // own count does; one more for a record a shortened call left
        // open, which a later call closes without counting it.
        let records = match (made_before, self.records_made(fd)) {
            (Some(before), Some(after)) if after >= before => after - before + 1,
            // Without the kernel's count: a record closed after every page
            // of the file, the smallest part the kernel takes it in.
            _ => u64::try_from(sent.div_ceil(max) + sent.div_ceil(SMALLEST_PAGE) + 1)
                .unwrap_or(u64::MAX),
        };
        Ok(self.application_data_sent(fd, sent, records))
    }

    /// The records the kernel has made under the current transmit keys,
    /// where it can be asked.
    fn records_made(&self, fd: BorrowedFd<'_>) -> Option<u64> {
        self.ledger.as_ref()?.records_made(fd).ok()
    }

    /// What comes before `len` bytes of application data are given to the
    /// kernel: the connection must not have failed, the outputs that wait
    /// go first, and the connection must be open for sending. Returns the
    /// most plaintext the kernel puts into one record, or `None` when
    /// there is nothing to send.
    fn before_application_data(
        &mut self,
        fd: BorrowedFd<'_>,
        len: usize,
    ) -> io::Result<Option<usize>> {
        self.check()?;
        self.flush_outputs(fd)?;
        if len == 0 {
            return Ok(None);
        }
        if !self.conn.may_send_application_data() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the connection is closed for sending",
            ));
        }
        Ok(Some(
            self.conn
                .max_tx_payload_len()
                .map_or(MAX_PAYLOAD, usize::from),
        ))
    }

    /// Counts `sent` bytes of application data the kernel accepted, in at
    /// most `records` records, and carries out what the connection then
    /// asks for. Returns `sent`.
    fn application_data_sent(&mut self, fd: BorrowedFd<'_>, sent: usize, records: u64) -> usize {
        if let Some(ledger) = &mut self.ledger {
            ledger.sent(sent);
        }
        let result = self.conn.records_sent(records);
        if let Err(err) = result {
            // The bytes were sent; the next call reports the failure.
            self.failed = Some((io::ErrorKind::InvalidData, err));
        }
        // The bytes were sent, so the call succeeds whatever happens to
        // the outputs (a key refresh): what waits goes out next time, and
        // a failure is reported by the next call.
        let _ = self.flush_outputs(fd);
        sent
    }

    /// Sends what waits, including a fatal alert after a failure.
    pub(crate) fn flush(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        if self.failed.is_some() && !self.has_outputs() {
            return self.check();
        }
        let flushed = self.flush_outputs(fd);
        self.check()?;
        flushed
    }
}

impl<Data> fmt::Debug for Engine<Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine")
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

/// The error of a kernel TLS option the running kernel does not have.
pub(crate) fn option_error(err: io::Error) -> io::Error {
    if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "the kernel has no such kernel TLS option (it came with Linux 5.19)",
        )
    } else {
        err
    }
}

pub(crate) fn invalid_data(err: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}
