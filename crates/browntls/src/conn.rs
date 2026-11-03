//! The connection core: feeding records to the handshake state machine and
//! the buffered I/O API around it.

use alloc::boxed::Box;
use core::fmt::Debug;
use core::mem;
use core::ops::{Deref, DerefMut};

use crate::common_state::{CommonState, IoState};
use crate::enums::{AlertDescription, ContentType, ProtocolVersion};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::log::{debug, trace};
use crate::msgs::base::Payload;
use crate::msgs::codec::Reader;
use crate::msgs::deframer::{Deframed, DeframerVecBuffer, MessageDeframer};
use crate::msgs::handshake::HandshakeMessagePayload;
use crate::msgs::message::{InboundPlainMessage, Message, MessagePayload};
use crate::suites::{ExtractedSecrets, PartiallyExtractedSecrets};

/// One position in the handshake state machine.
pub(crate) trait State<Data>: Send + Sync {
    /// Handles `message`, returning the next state.
    fn handle(self: Box<Self>, cx: &mut Context<'_, Data>, message: Message<'_>) -> Result<Box<dyn State<Data>>, Error>;

    /// RFC 5705 / RFC 8446 §7.5 keying material export.
    fn export_keying_material(&self, _output: &mut [u8], _label: &[u8], _context: Option<&[u8]>) -> Result<(), Error> {
        Err(Error::HandshakeNotComplete)
    }

    /// The current traffic secrets, for kernel offload.
    fn extract_secrets(&self) -> Result<PartiallyExtractedSecrets, Error> {
        Err(Error::HandshakeNotComplete)
    }

    /// Sends a KeyUpdate requesting the peer to update too (TLS 1.3).
    fn send_key_update_request(&mut self, _common: &mut CommonState) -> Result<(), Error> {
        Err(Error::HandshakeNotComplete)
    }

    /// Hook called when a record failed to decrypt.
    fn handle_decrypt_error(&self) {}
}

/// What a state handler sees besides the message.
pub(crate) struct Context<'a, Data> {
    pub(crate) common: &'a mut CommonState,
    pub(crate) data: &'a mut Data,
}

/// Per-side connection data.
pub trait SideData: Debug {}

/// The state machine plus everything it needs.
pub(crate) struct ConnectionCore<Data> {
    pub(crate) state: Result<Box<dyn State<Data>>, Error>,
    pub(crate) data: Data,
    pub(crate) common_state: CommonState,
    pub(crate) deframer: MessageDeframer,
}

impl<Data> ConnectionCore<Data> {
    pub(crate) fn new(state: Box<dyn State<Data>>, data: Data, common_state: CommonState) -> Self {
        Self {
            state: Ok(state),
            data,
            common_state,
            deframer: MessageDeframer::default(),
        }
    }

    /// Processes every complete record in `buffer`.
    pub(crate) fn process_new_packets(&mut self, buffer: &mut DeframerVecBuffer) -> Result<IoState, Error> {
        let mut state = match mem::replace(&mut self.state, Err(Error::HandshakeNotComplete)) {
            Ok(state) => state,
            Err(e) => {
                self.state = Err(e.clone());
                return Err(e);
            }
        };

        if self.common_state.encrypt_failed {
            self.state = Err(Error::EncryptError);
            return Err(Error::EncryptError);
        }

        loop {
            if self.common_state.has_received_close_notify {
                // RFC 8446 §6.1: everything after close_notify is ignored.
                break;
            }

            let item = match self.deframer.pop(
                &mut self.common_state.record_layer,
                self.common_state.negotiated_version,
                buffer,
            ) {
                Ok(Some(item)) => item,
                Ok(None) => break,
                Err(err) => {
                    let err = self.handle_deframe_error(err, &*state);
                    self.state = Err(err.clone());
                    return Err(err);
                }
            };

            let result = match item {
                Deframed::Handshake { len, version } => {
                    let decrypt_epoch = self.common_state.record_layer.read_seq();
                    let was_decrypting = self.common_state.record_layer.is_decrypting();
                    let bytes = &self.deframer.joiner.buffered()[..len];
                    let parse_version = self.common_state.negotiated_version.unwrap_or(version);
                    let result = match HandshakeMessagePayload::read_version(&mut Reader::init(bytes), parse_version) {
                        Ok(parsed) => {
                            let msg = Message {
                                version,
                                payload: MessagePayload::Handshake {
                                    parsed,
                                    encoded: Payload::Borrowed(bytes),
                                },
                            };
                            Self::process_msg(&mut self.common_state, &mut self.data, state, msg)
                        }
                        Err(err) => {
                            let err = self
                                .common_state
                                .send_fatal_alert(AlertDescription::from(err), Error::from(err));
                            Err(err)
                        }
                    };
                    self.deframer.joiner.consume(len);
                    // RFC 8446 §5.1: a handshake message that changes the read
                    // key must end its record; nothing may follow it under the
                    // old key.
                    let key_changed = self.common_state.record_layer.is_decrypting() != was_decrypting
                        || (self.common_state.record_layer.is_decrypting()
                            && self.common_state.record_layer.read_seq() < decrypt_epoch);
                    match result {
                        Ok(_) if key_changed && !self.deframer.joiner.is_empty() => Err(self
                            .common_state
                            .send_fatal_alert(AlertDescription::UnexpectedMessage, PeerMisbehaved::KeyEpochWithPendingFragment)),
                        other => other,
                    }
                }
                Deframed::Record {
                    typ,
                    version,
                    plaintext,
                    consumed,
                    want_close_before_decrypt,
                } => {
                    if want_close_before_decrypt {
                        self.common_state.send_close_notify();
                    }
                    let payload = &buffer.filled()[plaintext];
                    let result = match Message::try_from(InboundPlainMessage { typ, version, payload }) {
                        Ok(msg) => Self::process_msg(&mut self.common_state, &mut self.data, state, msg),
                        Err(err) => Err(self
                            .common_state
                            .send_fatal_alert(AlertDescription::from(err), Error::from(err))),
                    };
                    buffer.discard(consumed);
                    result
                }
            };

            match result {
                Ok(new_state) => state = new_state,
                Err(err) => {
                    self.state = Err(err.clone());
                    return Err(err);
                }
            }
        }

        self.state = Ok(state);

        if self.common_state.refresh_traffic_keys_pending {
            self.common_state.refresh_traffic_keys_pending = false;
            self.refresh_traffic_keys()?;
        }

        Ok(self.common_state.current_io_state())
    }

    fn process_msg(
        common: &mut CommonState,
        data: &mut Data,
        state: Box<dyn State<Data>>,
        msg: Message<'_>,
    ) -> Result<Box<dyn State<Data>>, Error> {
        match &msg.payload {
            MessagePayload::Alert(alert) => {
                common.process_alert(alert)?;
                return Ok(state);
            }
            // Unprotected ChangeCipherSpec records in TLS 1.3 are middlebox
            // compatibility noise (RFC 8446 appendix D.4).
            MessagePayload::ChangeCipherSpec(_) if common.is_tls13() => {
                common.process_middlebox_ccs()?;
                return Ok(state);
            }
            MessagePayload::ApplicationData(_) if !common.may_receive_application_data && !common.early_traffic => {
                // Application data before the handshake is complete.
                return Err(common.send_fatal_alert(
                    AlertDescription::UnexpectedMessage,
                    Error::InappropriateMessage {
                        expect_types: alloc::vec![ContentType::Handshake],
                        got_type: ContentType::ApplicationData,
                    },
                ));
            }
            _ => {}
        }

        let mut cx = Context { common, data };
        match state.handle(&mut cx, msg) {
            Ok(next) => Ok(next),
            Err(err) => Err(Self::ensure_alert_sent(cx.common, err)),
        }
    }

    /// Makes sure every fatal error is accompanied by an alert.
    fn ensure_alert_sent(common: &mut CommonState, err: Error) -> Error {
        if common.sent_fatal_alert {
            return err;
        }
        let desc = match &err {
            Error::InvalidMessage(e) => AlertDescription::from(*e),
            Error::InappropriateMessage { .. } | Error::InappropriateHandshakeMessage { .. } => {
                AlertDescription::UnexpectedMessage
            }
            Error::PeerMisbehaved(_) => AlertDescription::IllegalParameter,
            Error::PeerIncompatible(_) => AlertDescription::HandshakeFailure,
            Error::InvalidCertificate(e) => AlertDescription::from(e.clone()),
            Error::InvalidCertRevocationList(_) => AlertDescription::BadCertificate,
            Error::NoCertificatesPresented => AlertDescription::CertificateRequired,
            Error::DecryptError => AlertDescription::BadRecordMac,
            Error::PeerSentOversizedRecord => AlertDescription::RecordOverflow,
            Error::NoApplicationProtocol => AlertDescription::NoApplicationProtocol,
            Error::AlertReceived(_) => return err,
            _ => AlertDescription::InternalError,
        };
        common.send_fatal_alert(desc, err)
    }

    fn handle_deframe_error(&mut self, err: Error, state: &dyn State<Data>) -> Error {
        match &err {
            Error::DecryptError => {
                state.handle_decrypt_error();
                self.common_state
                    .send_fatal_alert(AlertDescription::BadRecordMac, err)
            }
            Error::PeerSentOversizedRecord => self
                .common_state
                .send_fatal_alert(AlertDescription::RecordOverflow, err),
            Error::InvalidMessage(e) => {
                let desc = AlertDescription::from(*e);
                self.common_state.send_fatal_alert(desc, err)
            }
            Error::PeerMisbehaved(_) => self
                .common_state
                .send_fatal_alert(AlertDescription::UnexpectedMessage, err),
            _ => err,
        }
    }

    pub(crate) fn export_keying_material(&self, output: &mut [u8], label: &[u8], context: Option<&[u8]>) -> Result<(), Error> {
        if output.is_empty() {
            return Err(Error::general("export_keying_material: output buffer is empty"));
        }
        if context.is_some_and(|c| c.len() > usize::from(u16::MAX)) {
            return Err(Error::general("export_keying_material: context too long"));
        }
        match &self.state {
            Ok(state) => state.export_keying_material(output, label, context),
            Err(err) => Err(err.clone()),
        }
    }

    pub(crate) fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        if !self.common_state.enable_secret_extraction {
            return Err(Error::general("Secret extraction is disabled"));
        }
        let st = self.state?;
        let record_layer = &self.common_state.record_layer;
        let PartiallyExtractedSecrets { tx, rx } = st.extract_secrets()?;
        Ok(ExtractedSecrets {
            tx: (record_layer.write_seq(), tx),
            rx: (record_layer.read_seq(), rx),
        })
    }

    pub(crate) fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        match &mut self.state {
            Ok(st) => st.send_key_update_request(&mut self.common_state),
            Err(e) => Err(e.clone()),
        }
    }

    /// Reads one plaintext handshake message out of `buffer` without
    /// advancing the state machine; used by the server `Acceptor`.
    pub(crate) fn first_handshake_message(&mut self, buffer: &mut DeframerVecBuffer) -> Result<Option<Message<'static>>, Error> {
        match self.deframer.pop(
            &mut self.common_state.record_layer,
            self.common_state.negotiated_version,
            buffer,
        ) {
            Ok(Some(Deframed::Handshake { len, version })) => {
                let bytes = &self.deframer.joiner.buffered()[..len];
                let parsed = HandshakeMessagePayload::read_version(&mut Reader::init(bytes), ProtocolVersion::TLSv1_2)
                    .map_err(|e| self.common_state.send_fatal_alert(AlertDescription::from(e), Error::from(e)))?;
                let msg = Message {
                    version,
                    payload: MessagePayload::Handshake {
                        parsed,
                        encoded: Payload::Borrowed(bytes),
                    },
                }
                .into_owned();
                self.deframer.joiner.consume(len);
                Ok(Some(msg))
            }
            Ok(Some(Deframed::Record { typ, .. })) => Err(self.common_state.send_fatal_alert(
                AlertDescription::UnexpectedMessage,
                Error::InappropriateMessage {
                    expect_types: alloc::vec![ContentType::Handshake],
                    got_type: typ,
                },
            )),
            Ok(None) => Ok(None),
            Err(err) => Err(self.handle_deframe_error(err, &NoState)),
        }
    }
}

struct NoState;

impl<Data> State<Data> for NoState {
    fn handle(self: Box<Self>, _cx: &mut Context<'_, Data>, _message: Message<'_>) -> Result<Box<dyn State<Data>>, Error> {
        Err(Error::HandshakeNotComplete)
    }
}

/// A connection whose handshake is driven by the buffered API.
pub struct ConnectionCommon<Data> {
    pub(crate) core: ConnectionCore<Data>,
    pub(crate) deframer_buffer: DeframerVecBuffer,
}

impl<Data> ConnectionCommon<Data> {
    /// Processes every complete record received so far.
    ///
    /// Call this after `read_tls`. Returns what the connection now wants to
    /// do, or the fatal error that ended it (after which an alert is usually
    /// queued for `write_tls`).
    pub fn process_new_packets(&mut self) -> Result<IoState, Error> {
        self.core.process_new_packets(&mut self.deframer_buffer)
    }

    /// Derives keying material bound to this session (RFC 5705, RFC 8446 §7.5).
    pub fn export_keying_material<T: AsMut<[u8]>>(&self, mut output: T, label: &[u8], context: Option<&[u8]>) -> Result<T, Error> {
        self.core
            .export_keying_material(output.as_mut(), label, context)?;
        Ok(output)
    }

    /// Extracts the traffic secrets for kernel TLS offload.
    ///
    /// Requires `enable_secret_extraction` in the configuration and a
    /// completed handshake. The connection is consumed because no further
    /// records may be protected by this library afterwards.
    pub fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        if self.deframer_buffer.has_pending() || self.core.deframer.has_buffered_handshake() {
            return Err(Error::general("cannot extract secrets with unprocessed received data"));
        }
        self.core.dangerous_extract_secrets()
    }

    /// Limits the buffered outgoing data (`None` removes the limit).
    pub fn set_buffer_limit(&mut self, limit: Option<usize>) {
        self.core.common_state.set_buffer_limit(limit);
    }

    /// Rotates the traffic keys (TLS 1.3 only), asking the peer to do the same.
    pub fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        self.core.refresh_traffic_keys()
    }

    pub(crate) fn replace_state(&mut self, new: Box<dyn State<Data>>) {
        self.core.state = Ok(new);
    }
}

#[cfg(feature = "std")]
impl<Data> ConnectionCommon<Data> {
    /// Reads TLS bytes from `rd` into the connection. Returns the number of
    /// bytes read; zero means the transport reached end of file.
    ///
    /// Fails if received plaintext is waiting for the application, so that a
    /// peer cannot force unbounded buffering.
    pub fn read_tls(&mut self, rd: &mut dyn std::io::Read) -> Result<usize, std::io::Error> {
        if self.core.common_state.received_plaintext.is_full() {
            return Err(std::io::Error::other(
                "received plaintext buffer full; read it with reader() first",
            ));
        }
        let n = self.deframer_buffer.read(rd)?;
        if n == 0 {
            self.core.common_state.mark_eof();
        }
        Ok(n)
    }

    /// Writes queued TLS bytes to `wr`.
    pub fn write_tls(&mut self, wr: &mut dyn std::io::Write) -> Result<usize, std::io::Error> {
        self.core.common_state.sendable_tls.write_to(wr)
    }

    /// Plaintext received from the peer.
    pub fn reader(&mut self) -> Reader<'_> {
        Reader {
            common: &mut self.core.common_state,
        }
    }

    /// Plaintext to send to the peer.
    pub fn writer(&mut self) -> Writer<'_> {
        Writer {
            common: &mut self.core.common_state,
        }
    }

    /// Drives the connection over `io` until the handshake completes, or,
    /// once it has, until some plaintext was read or all queued TLS bytes
    /// were written. Returns `(bytes read, bytes written)`.
    pub fn complete_io<T>(&mut self, io: &mut T) -> Result<(usize, usize), std::io::Error>
    where
        T: std::io::Read + std::io::Write,
    {
        let until_handshaked = self.is_handshaking();
        let mut eof = false;
        let mut wrlen = 0;
        let mut rdlen = 0;

        loop {
            while self.wants_write() {
                wrlen += self.write_tls(io)?;
            }
            io.flush()?;

            if !until_handshaked && wrlen > 0 {
                return Ok((rdlen, wrlen));
            }

            while !eof && self.wants_read() {
                match self.read_tls(io) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(n) => {
                        rdlen += n;
                        break;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }

            if let Err(e) = self.process_new_packets() {
                // Deliver any alert before reporting the failure.
                let _ignored = self.write_tls(io);
                let _ignored = io.flush();
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
            }

            match (eof, until_handshaked, self.is_handshaking()) {
                (_, true, false) => return Ok((rdlen, wrlen)),
                (_, false, _) => return Ok((rdlen, wrlen)),
                (true, true, true) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "peer closed connection during handshake",
                    ));
                }
                (false, true, true) => {}
            }
        }
    }
}

impl<Data> Deref for ConnectionCommon<Data> {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        &self.core.common_state
    }
}

impl<Data> DerefMut for ConnectionCommon<Data> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core.common_state
    }
}

impl<Data> From<ConnectionCore<Data>> for ConnectionCommon<Data> {
    fn from(core: ConnectionCore<Data>) -> Self {
        Self {
            core,
            deframer_buffer: DeframerVecBuffer::default(),
        }
    }
}

/// Reads plaintext received from the peer.
#[cfg(feature = "std")]
pub struct Reader<'a> {
    common: &'a mut CommonState,
}

#[cfg(feature = "std")]
impl Reader<'_> {
    fn check_no_bytes_state(&self) -> std::io::Result<()> {
        if self.common.has_received_close_notify {
            // Clean EOF: the peer closed the session.
            return Ok(());
        }
        if self.common.has_seen_eof {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed connection without sending TLS close_notify: \
                 https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof",
            ));
        }
        Err(std::io::ErrorKind::WouldBlock.into())
    }
}

#[cfg(feature = "std")]
impl std::io::Read for Reader<'_> {
    /// Returns `Ok(0)` only after the peer's `close_notify`; before that,
    /// `WouldBlock` means no plaintext is buffered yet and `UnexpectedEof`
    /// means the transport closed without a `close_notify`.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.common.received_plaintext.read(buf);
        if len == 0 && !buf.is_empty() {
            self.check_no_bytes_state()?;
        }
        Ok(len)
    }
}

#[cfg(feature = "std")]
impl std::io::BufRead for Reader<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.common.received_plaintext.is_empty() {
            self.check_no_bytes_state()?;
        }
        Ok(self.common.received_plaintext.chunk().unwrap_or(&[]))
    }

    fn consume(&mut self, amt: usize) {
        self.common.received_plaintext.consume(amt);
    }
}

#[cfg(feature = "std")]
impl Debug for Reader<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Reader")
    }
}

/// Writes plaintext to send to the peer.
///
/// Before the handshake completes, writes are buffered (subject to the
/// buffer limit) and sent once it does.
#[cfg(feature = "std")]
pub struct Writer<'a> {
    common: &'a mut CommonState,
}

#[cfg(feature = "std")]
impl std::io::Write for Writer<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.common.encrypt_failed {
            return Err(std::io::Error::other("record encryption failed"));
        }
        Ok(self
            .common
            .send_plain(buf.into(), crate::common_state::Limit::Yes))
    }

    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        let slices: alloc::vec::Vec<&[u8]> = bufs.iter().map(|s| &**s).collect();
        let chunks = crate::msgs::message::OutboundChunks::new(&slices);
        Ok(self
            .common
            .send_plain(chunks, crate::common_state::Limit::Yes))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "std")]
impl Debug for Writer<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Writer")
    }
}

impl<Data> Debug for ConnectionCommon<Data> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConnectionCommon")
            .field("common", &self.core.common_state)
            .finish_non_exhaustive()
    }
}

/// A client or server connection.
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum Connection {
    /// A client connection.
    Client(crate::client::ClientConnection),
    /// A server connection.
    Server(crate::server::ServerConnection),
}

#[cfg(feature = "std")]
impl Connection {
    /// See [`ConnectionCommon::read_tls`].
    pub fn read_tls(&mut self, rd: &mut dyn std::io::Read) -> Result<usize, std::io::Error> {
        match self {
            Self::Client(conn) => conn.read_tls(rd),
            Self::Server(conn) => conn.read_tls(rd),
        }
    }

    /// See [`ConnectionCommon::write_tls`].
    pub fn write_tls(&mut self, wr: &mut dyn std::io::Write) -> Result<usize, std::io::Error> {
        match self {
            Self::Client(conn) => conn.write_tls(wr),
            Self::Server(conn) => conn.write_tls(wr),
        }
    }

    /// See [`ConnectionCommon::reader`].
    pub fn reader(&mut self) -> Reader<'_> {
        match self {
            Self::Client(conn) => conn.reader(),
            Self::Server(conn) => conn.reader(),
        }
    }

    /// See [`ConnectionCommon::writer`].
    pub fn writer(&mut self) -> Writer<'_> {
        match self {
            Self::Client(conn) => conn.writer(),
            Self::Server(conn) => conn.writer(),
        }
    }

    /// See [`ConnectionCommon::process_new_packets`].
    pub fn process_new_packets(&mut self) -> Result<IoState, Error> {
        match self {
            Self::Client(conn) => conn.process_new_packets(),
            Self::Server(conn) => conn.process_new_packets(),
        }
    }

    /// See [`ConnectionCommon::export_keying_material`].
    pub fn export_keying_material<T: AsMut<[u8]>>(&self, output: T, label: &[u8], context: Option<&[u8]>) -> Result<T, Error> {
        match self {
            Self::Client(conn) => conn.export_keying_material(output, label, context),
            Self::Server(conn) => conn.export_keying_material(output, label, context),
        }
    }

    /// See [`ConnectionCommon::complete_io`].
    pub fn complete_io<T>(&mut self, io: &mut T) -> Result<(usize, usize), std::io::Error>
    where
        T: std::io::Read + std::io::Write,
    {
        match self {
            Self::Client(conn) => conn.complete_io(io),
            Self::Server(conn) => conn.complete_io(io),
        }
    }

    /// See [`ConnectionCommon::dangerous_extract_secrets`].
    pub fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        match self {
            Self::Client(conn) => conn.dangerous_extract_secrets(),
            Self::Server(conn) => conn.dangerous_extract_secrets(),
        }
    }

    /// See [`ConnectionCommon::set_buffer_limit`].
    pub fn set_buffer_limit(&mut self, limit: Option<usize>) {
        match self {
            Self::Client(conn) => conn.set_buffer_limit(limit),
            Self::Server(conn) => conn.set_buffer_limit(limit),
        }
    }

    /// See [`ConnectionCommon::refresh_traffic_keys`].
    pub fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        match self {
            Self::Client(conn) => conn.refresh_traffic_keys(),
            Self::Server(conn) => conn.refresh_traffic_keys(),
        }
    }
}

#[cfg(feature = "std")]
impl Deref for Connection {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Client(conn) => conn,
            Self::Server(conn) => conn,
        }
    }
}

#[cfg(feature = "std")]
impl DerefMut for Connection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Client(conn) => conn,
            Self::Server(conn) => conn,
        }
    }
}

#[allow(dead_code)]
fn log_unused() {
    trace!("");
    debug!("");
    let _ = InvalidMessage::MessageTooShort;
}
