//! What a kernel TLS socket needs from userspace after the handover, apart
//! from the socket itself: the [`KernelConnection`], the plaintext received
//! before the handover, control records in transit and the outputs waiting
//! for room. [`KtlsStream`](crate::KtlsStream) and the Tokio stream both
//! drive one [`Engine`], passing the descriptor to every call.
//!
//! Every call that reaches the socket may return `WouldBlock` on a
//! non-blocking one. [`Engine::read`] does so only when the kernel has no
//! record to give, or when the outputs waiting for room cost more than
//! their budget ([`Engine::reading_paused`]); short of that it tolerates a
//! full socket for what it has to send. [`Engine::write`],
//! [`Engine::sendfile`], [`Engine::flush`] and [`Engine::flush_outputs`]
//! return it only when the socket has no room.

use std::fmt;
use std::io;
use std::os::fd::BorrowedFd;

use browntls_core::kernel::{KernelConnection, KernelOutput};
use browntls_core::{
    ConnectionTrafficSecrets, ContentType, Error, ExtractedSecrets, ProtocolVersion, SideData,
};

use crate::crypto_info::CryptoInfo;
use crate::ledger::{Backlog, Ledger};
use crate::meter::Meter;
use crate::outputs::Waiting;
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
/// a file in pieces of at least one page (but for its ends).
const SMALLEST_PAGE: usize = 4096;

/// `ContentType::ApplicationData`.
const APPLICATION_DATA: u8 = 23;

/// A read either produced application data (or EOF), or used its receive
/// budget while handling records that produced no application data.
pub(crate) enum ReadResult {
    Bytes(usize),
    Yield,
}

/// The first Linux release that can be trusted with
/// `TLS_RX_EXPECT_NO_PAD`. The option makes the kernel decrypt a TLS 1.3
/// record into the reader's buffer and, when the record turns out to be
/// padded or not application data, a second time into a buffer of its own
/// that it copies out. Before this release it does not take back the
/// reader's position the first attempt advanced, so the copy lands behind
/// the first attempt's output and the application reads bytes the peer
/// never sent as data.
const NO_PAD_SINCE: (u32, u32) = (7, 2);

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
    /// order; carried out first next time. Never new receive keys.
    waiting: Waiting,
    /// The connection failed; every later call reports this.
    failed: Option<(io::ErrorKind, Error)>,
    /// What the kernel was given to send, to be set against what TCP has
    /// taken. `None` when the kernel's counters could not be read, or when
    /// the socket was given bytes the engine did not see.
    ledger: Option<Ledger>,
    /// The kernel was told to expect unpadded records
    /// (`TLS_RX_EXPECT_NO_PAD`): it decrypts into the reader's buffer
    /// before it knows what a record holds.
    rx_no_pad: bool,
    /// Times the writes the load-aware routing asks for (`native`).
    meter: Meter,
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
            waiting: Waiting::default(),
            failed: None,
            ledger: None,
            rx_no_pad: false,
            meter: Meter::kernel(&secrets.tx.1),
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

    /// How many outputs wait for room (tests).
    #[cfg(test)]
    pub(crate) fn waiting_len(&self) -> usize {
        self.waiting.len()
    }

    pub(crate) fn conn(&self) -> &KernelConnection<Data> {
        &self.conn
    }

    /// Whether outputs (control records, keys) wait to be carried out.
    pub(crate) fn has_outputs(&self) -> bool {
        !self.waiting.is_empty() || self.conn.has_output()
    }

    /// Whether reading has stopped until the socket takes the outputs that
    /// wait: they cost more than [`crate::outputs::BUDGET`]. A peer that
    /// asks for answers (KeyUpdates, post-handshake authentication) and
    /// reads none of them cannot make them pile up without bound, as the
    /// userspace connection's `wants_read` ensures.
    pub(crate) fn reading_paused(&self) -> bool {
        self.waiting.over_budget()
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

    /// See
    /// [`KtlsStream::refresh_traffic_keys`](crate::KtlsStream::refresh_traffic_keys).
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

    /// See
    /// [`KtlsStream::set_rx_expect_no_pad`](crate::KtlsStream::set_rx_expect_no_pad).
    pub(crate) fn set_rx_expect_no_pad(
        &mut self,
        fd: BorrowedFd<'_>,
        expect: bool,
    ) -> io::Result<()> {
        if !expect && !self.rx_no_pad {
            // Never set here: nothing to take back, whatever the kernel
            // and the protocol version. (An option set on the descriptor
            // behind the engine's back is not the engine's to know.)
            return Ok(());
        }
        self.tls13_only()?;
        if expect {
            no_pad_is_safe(&sys::kernel_release()?)?;
        }
        sys::set_rx_expect_no_pad(fd, expect).map_err(option_error)?;
        self.rx_no_pad = expect;
        Ok(())
    }

    /// See
    /// [`KtlsStream::rx_expect_no_pad`](crate::KtlsStream::rx_expect_no_pad).
    pub(crate) fn rx_expect_no_pad(&self, fd: BorrowedFd<'_>) -> io::Result<bool> {
        self.tls13_only()?;
        sys::rx_expect_no_pad(fd).map_err(option_error)
    }

    /// Padding exists in TLS 1.3 records only; the kernel refuses the
    /// option for TLS 1.2 without saying why.
    fn tls13_only(&self) -> io::Result<()> {
        if self.conn.protocol_version() == ProtocolVersion::TLSv1_3 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TLS 1.2 records have no padding: the kernel needs no promise about it",
            ))
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
    /// and every output after it wait, except new receive
    /// keys, which are installed at once: reception must not wait for
    /// transmission, and the two directions' keys are independent. Each
    /// call tries only the first waiting output before taking the new ones.
    pub(crate) fn flush_outputs(&mut self, fd: BorrowedFd<'_>) -> io::Result<()> {
        let version = self.conn.protocol_version();
        // What waits goes first, in order.
        while let Some(output) = self.waiting.front() {
            match carry_out(fd, version, &mut self.ledger, output) {
                Ok(()) => {
                    self.waiting.pop_front();
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    return Err(self.blocked(fd, version, err));
                }
                Err(err) => return Err(self.output_failed(err)),
            }
        }
        while let Some(output) = self.conn.pop_output() {
            match carry_out(fd, version, &mut self.ledger, &output) {
                Ok(()) => {}
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        && !matches!(output, KernelOutput::RxKeys(_)) =>
                {
                    self.waiting.push_back(output);
                    return Err(self.blocked(fd, version, err));
                }
                Err(err) => return Err(self.output_failed(err)),
            }
        }
        Ok(())
    }

    /// The socket had no room (`err`, `WouldBlock`): the connection's
    /// outputs not yet taken join those that wait, in order, except new
    /// receive keys, which are installed now. Only the outputs new since
    /// the last call are looked at.
    fn blocked(
        &mut self,
        fd: BorrowedFd<'_>,
        version: ProtocolVersion,
        err: io::Error,
    ) -> io::Error {
        while let Some(output) = self.conn.pop_output() {
            match output {
                KernelOutput::RxKeys(secrets) => {
                    if let Err(err) = install_keys(fd, version, true, &secrets) {
                        return self.output_failed(err);
                    }
                }
                other => self.waiting.push_back(other),
            }
        }
        err
    }

    /// An output that did not happen leaves the kernel's state behind the
    /// connection's: nothing more can be sent safely.
    fn output_failed(&mut self, err: io::Error) -> io::Error {
        // What was queued behind it (records, keys) would now go out of
        // step with the kernel: drop it. So is the count of what the
        // kernel was given (it may have taken part of a record).
        self.ledger = None;
        self.waiting.clear();
        while self.conn.pop_output().is_some() {}
        self.fail_with(err.kind(), Error::General(format!("kernel TLS: {err}")))
    }

    /// Carries out the outputs, tolerating a full socket: what waits is
    /// sent by a later call (and stops reading past its budget).
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
        match self.read_inner(fd, buf, None)? {
            ReadResult::Bytes(n) => Ok(n),
            // An unbudgeted read cannot yield.
            ReadResult::Yield => Err(io::Error::other("unexpected read budget exhaustion")),
        }
    }

    /// As above, but limits successful kernel receives within one caller
    /// poll. The caller retains `remaining` across readiness retries.
    #[cfg(feature = "tokio")]
    pub(crate) fn read_bounded(
        &mut self,
        fd: BorrowedFd<'_>,
        buf: &mut [u8],
        remaining: &mut usize,
    ) -> io::Result<ReadResult> {
        self.read_inner(fd, buf, Some(remaining))
    }

    fn read_inner(
        &mut self,
        fd: BorrowedFd<'_>,
        buf: &mut [u8],
        mut remaining: Option<&mut usize>,
    ) -> io::Result<ReadResult> {
        if buf.is_empty() {
            return Ok(ReadResult::Bytes(0));
        }
        if let Some(n) = self.read_pending(buf) {
            return Ok(ReadResult::Bytes(n));
        }
        loop {
            self.check()?;
            if self.conn.peer_has_closed() {
                return Ok(ReadResult::Bytes(0));
            }
            // Keys to install come before the next record; answers owed are
            // sent when there is room (or by the next write or flush).
            self.flush_outputs_if_room(fd)?;
            if self.reading_paused() {
                // Nothing more is read until the socket takes what waits.
                return Err(io::ErrorKind::WouldBlock.into());
            }
            if remaining.as_deref() == Some(&0) {
                return Ok(ReadResult::Yield);
            }
            let continuing = self.control.as_ref().map(|(typ, _)| *typ);
            let into: &mut [u8] = if continuing.is_some() {
                self.scratch.resize(MAX_PAYLOAD + 256, 0);
                &mut self.scratch
            } else {
                buf
            };
            let result = sys::recv(fd, into, false);
            if self.rx_no_pad && continuing.is_none() {
                // The kernel may have decrypted one more record into `buf`
                // than it reports: a control record behind the data, a
                // padded record's padding, or a record that did not
                // authenticate. None of that stays with the caller.
                // Before `WouldBlock` too: a padded record without content
                // is decrypted there and reports nothing.
                let kept = result.as_ref().map_or(0, |received| received.len);
                wipe_unreported(buf, kept);
            }
            let received = match result {
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
            if let Some(left) = remaining.as_deref_mut() {
                *left -= 1;
            }
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
                return Ok(ReadResult::Bytes(received.len));
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
        let timing = self.meter.start(take);
        let sent = sys::send(fd, &buf[..take])?;
        if let Some(timing) = timing {
            timing.done(sent);
        }
        // A plain `send` closes its last record, so `sent` bytes made at
        // most this many (barring the kernel closing records early under
        // memory pressure).
        let records = u64::try_from(sent.div_ceil(max)).unwrap_or(u64::MAX);
        Ok(self.application_data_sent(fd, sent, records))
    }

    /// See [`KtlsStream::sendfile`](crate::KtlsStream::sendfile): first the
    /// outputs that wait, then one `sendfile` of at most
    /// [`RECORDS_PER_WRITE`] records' worth of the file, and of no more
    /// than the file holds.
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
        let Some(len) = sys::regular_file_len(file)? else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "`sendfile` takes a regular file",
            ));
        };
        // Never past the end of the file: having found it, the kernel
        // sends what it holds and waits for room to do so, on a
        // non-blocking socket too. Asked for no more than there is, it
        // closes the last record like a write.
        let rest = usize::try_from(len.saturating_sub(offset)).unwrap_or(usize::MAX);
        let take = count.min(max * RECORDS_PER_WRITE).min(rest);
        if take == 0 {
            return Ok(0);
        }
        let made_before = self.records_made(fd);
        let sent = sys::sendfile(fd, file, offset, take)?;
        if sent == 0 {
            // The file was cut short meanwhile.
            return Ok(0);
        }
        // The bytes alone do not bound the records: a call cut short (no
        // room, a signal) leaves a record open that a later call closes,
        // and the kernel closes a record early when it has collected too
        // many pieces of pages or is short of memory. The kernel's own
        // count is exact; one more for the record left open, which is
        // counted here and not by the call that closes it.
        let records = match (made_before, self.records_made(fd)) {
            (Some(before), Some(after)) if after >= before => after - before + 1,
            // Without the kernel's count: as if every page of the file, the
            // smallest piece the kernel takes it in but for its ends,
            // closed a record.
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

/// Carries out one output on the socket `fd`, keeping `ledger` (the count
/// of what the kernel was given to send) in step.
fn carry_out(
    fd: BorrowedFd<'_>,
    version: ProtocolVersion,
    ledger: &mut Option<Ledger>,
    output: &KernelOutput,
) -> io::Result<()> {
    match output {
        KernelOutput::Record { typ, payload } => {
            let sent = sys::send_record(fd, u8::from(*typ), payload);
            if let (Ok(()), Some(ledger)) = (&sent, ledger.as_mut()) {
                ledger.sent(payload.len());
            }
            sent
        }
        KernelOutput::TxKeys(secrets) => {
            // The kernel counts the records of new keys from zero: what
            // the old keys made is read before they go.
            let made = ledger.as_ref().map(|ledger| ledger.records_made(fd));
            let installed = install_keys(fd, version, false, secrets);
            if installed.is_ok() {
                match (ledger.as_mut(), made) {
                    (Some(ledger), Some(Ok(made))) => ledger.rekeyed(made),
                    _ => *ledger = None,
                }
            }
            installed
        }
        KernelOutput::RxKeys(secrets) => install_keys(fd, version, true, secrets),
        other => Err(io::Error::other(format!("unknown kernel output {other:?}"))),
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
            "the running kernel does not have this kernel TLS option",
        )
    } else {
        err
    }
}

/// Whether a kernel of this release (as `uname` gives it) can be trusted
/// with `TLS_RX_EXPECT_NO_PAD`: see [`NO_PAD_SINCE`]. A release that
/// cannot be read is not trusted, and neither is a release candidate of
/// the first trusted version: the correction came with 7.2-rc7.
fn no_pad_is_safe(release: &[u8]) -> io::Result<()> {
    let trusted = release_version(release).is_some_and(|version| {
        version > NO_PAD_SINCE || (version == NO_PAD_SINCE && !is_release_candidate(release))
    });
    if trusted {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "before Linux 7.2 the kernel misplaces a padded record in the reader's buffer: \
             unpadded records are not promised to it",
        ))
    }
}

/// The major and minor number of a kernel release such as
/// `7.2.0-12-generic` or `7.2-rc1`.
fn release_version(release: &[u8]) -> Option<(u32, u32)> {
    let digits = |bytes: &[u8]| bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    let major = digits(release);
    let rest = release.get(major..)?.strip_prefix(b".")?;
    let number = |bytes: &[u8]| std::str::from_utf8(bytes).ok()?.parse().ok();
    Some((
        number(release.get(..major)?)?,
        number(rest.get(..digits(rest))?)?,
    ))
}

/// Whether a kernel release names a release candidate: `rc` and a digit,
/// not inside a word (`7.2.0-rc3`, `7.2.0-070200rc3-generic`; not
/// `7.2.1-arch1-1`).
fn is_release_candidate(release: &[u8]) -> bool {
    release.windows(3).enumerate().any(|(at, window)| {
        window.starts_with(b"rc")
            && window[2].is_ascii_digit()
            && !at
                .checked_sub(1)
                .and_then(|before| release.get(before))
                .is_some_and(u8::is_ascii_alphabetic)
    })
}

/// Zeroes what the kernel may have written into `buf` behind the `kept`
/// bytes it reported: at most one record's plaintext.
fn wipe_unreported(buf: &mut [u8], kept: usize) {
    let end = buf.len().min(kept.saturating_add(MAX_PAYLOAD + 256));
    if let Some(unreported) = buf.get_mut(kept..end) {
        unreported.fill(0);
    }
}

pub(crate) fn invalid_data(err: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_releases_are_told_apart() {
        for (release, version) in [
            (&b"7.2.0-12-generic"[..], Some((7, 2))),
            (b"7.2", Some((7, 2))),
            (b"7.2-rc1", Some((7, 2))),
            (b"7.10.3", Some((7, 10))),
            (b"10.0.0", Some((10, 0))),
            (b"6.18.44-fc-v595", Some((6, 18))),
            (b"7", None),
            (b"7.", None),
            (b".2", None),
            (b"7.x", None),
            (b"", None),
            (b"seven.two", None),
            (b"99999999999.1", None),
        ] {
            assert_eq!(release_version(release), version, "{release:?}");
        }
        for release in [
            &b"7.2.0"[..],
            b"7.2.1-arch1-1",
            b"7.2.0-1-aarch64",
            b"7.2.4-rc",
            b"7.3.5-070305-generic",
            b"7.3.0-rc1",
            b"8.0.0",
            b"10.1",
        ] {
            assert!(no_pad_is_safe(release).is_ok(), "{release:?}");
        }
        for release in [
            &b"7.2.0-rc6"[..],
            b"7.2.0-rc7",
            b"7.2-rc1",
            b"7.2.0-070200rc3-generic",
            b"7.2.0rc2",
            b"7.1.9",
            b"7.0.0-43-generic",
            b"6.18.1",
            b"5.19.0",
            b"junk",
            b"",
        ] {
            let err = no_pad_is_safe(release).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{release:?}");
        }
    }

    #[test]
    fn only_what_the_kernel_may_have_written_is_wiped() {
        let mut buf = vec![7u8; 40_000];
        wipe_unreported(&mut buf, 100);
        let end = 100 + MAX_PAYLOAD + 256;
        assert!(buf[..100].iter().all(|b| *b == 7));
        assert!(buf[100..end].iter().all(|b| *b == 0));
        assert!(buf[end..].iter().all(|b| *b == 7));

        let mut buf = [7u8; 300];
        wipe_unreported(&mut buf, 0);
        assert_eq!(buf, [0; 300]);
        let mut buf = [7u8; 300];
        wipe_unreported(&mut buf, 300);
        assert_eq!(buf, [7; 300]);
        wipe_unreported(&mut buf, usize::MAX);
        assert_eq!(buf, [7; 300]);
    }
}
