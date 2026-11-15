//! The unbuffered connection API: the caller owns every buffer.
//!
//! [`UnbufferedClientConnection`](crate::client::UnbufferedClientConnection)
//! and [`UnbufferedServerConnection`](crate::server::UnbufferedServerConnection)
//! drive the same handshake state machines as the buffered connections, but
//! never copy records into internal queues on the application-data path:
//!
//! * Received TLS bytes stay in the caller's buffer. Each call of
//!   [`UnbufferedConnectionCommon::process_tls_records`] parses records from
//!   the front of that buffer, decrypts them in place, and reports how many
//!   bytes the caller may then remove ([`UnbufferedStatus::discard`]).
//!   Application data is handed back as a slice of the caller's buffer
//!   ([`ReadTraffic`], [`ReadEarlyData`]), one record per call.
//! * Application data to send is encrypted straight into a caller-supplied
//!   output buffer ([`WriteTraffic::encrypt`]); a buffer that is too small is
//!   reported with the size needed ([`InsufficientSizeError`]) and nothing is
//!   consumed.
//! * Handshake messages, alerts and KeyUpdates that the state machine
//!   produces are queued internally, as encoded records, until the caller
//!   copies them out ([`EncodeTlsData`]). The handshake joiner keeps at most
//!   one handshake message being reassembled. Both are bounded by the
//!   protocol, not by the amount of application data.
//!
//! The record layer still allocates one temporary vector per record it
//! encrypts (the [`MessageEncrypter`](crate::crypto::cipher::MessageEncrypter)
//! interface returns an owned record); nothing is kept once the record has
//! been copied out.
//!
//! # Driving a connection
//!
//! Call `process_tls_records` with the bytes received so far (possibly
//! none), act on the returned [`ConnectionState`], remove `discard` bytes from
//! the front of the input buffer, and repeat:
//!
//! | State | What the caller does |
//! |---|---|
//! | [`ConnectionState::EncodeTlsData`] | [`EncodeTlsData::encode`] into the output buffer |
//! | [`ConnectionState::TransmitTlsData`] | sends the output buffer, then [`TransmitTlsData::done`] |
//! | [`ConnectionState::BlockedHandshake`] | receives more TLS bytes |
//! | [`ConnectionState::ReadTraffic`] / [`ConnectionState::ReadEarlyData`] | consumes the record |
//! | [`ConnectionState::WriteTraffic`] | encrypts data to send, or receives more TLS bytes |
//! | [`ConnectionState::PeerClosed`] | stops reading; may still write and close |
//! | [`ConnectionState::Closed`] | closes the transport |
//!
//! After a fatal error the alert, if one is due, is offered through
//! `EncodeTlsData`/`TransmitTlsData` first; then every call returns the
//! error.

use core::fmt;
use core::ops::{Deref, DerefMut, Range};

use crate::client::ClientConnectionData;
use crate::common_state::CommonState;
use crate::conn::{ConnectionCore, Processed, SideData};
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::deframer::DeframerSliceBuffer;
use crate::msgs::enums::KeyUpdateRequest;
use crate::msgs::message::HEADER_SIZE;
use crate::record_layer::PreEncryptAction;
use crate::suites::ExtractedSecrets;

/// The plaintext length of a KeyUpdate message (RFC 9846 §4.7.3): the
/// handshake header and the one-byte request.
const KEY_UPDATE_LEN: usize = 4 + 1;

/// The plaintext length of an alert (RFC 9846 §6): level and description.
const ALERT_LEN: usize = 2;

/// A connection driven by the unbuffered API; see the [module
/// documentation](self).
///
/// Dereferences to [`CommonState`] for the negotiated parameters.
pub struct UnbufferedConnectionCommon<Data> {
    pub(crate) core: ConnectionCore<Data>,
    /// Records were encoded for the caller and not yet reported sent.
    wants_write: bool,
    /// [`ConnectionState::PeerClosed`] has been reported.
    emitted_peer_closed: bool,
}

impl<Data: SideData> UnbufferedConnectionCommon<Data> {
    pub(crate) fn new(mut core: ConnectionCore<Data>) -> Self {
        core.common_state.unbuffered = true;
        Self {
            core,
            wants_write: false,
            emitted_peer_closed: false,
        }
    }

    /// Processes TLS records from the front of `incoming_tls` and reports
    /// what the connection needs next.
    ///
    /// `incoming_tls` holds the received bytes not yet discarded, oldest
    /// first; it may be empty, and may end in the middle of a record. Records
    /// are decrypted in place, so once the returned state has been handled,
    /// [`UnbufferedStatus::discard`] bytes must be removed from its front
    /// before the next call, and the rest kept as they are.
    pub fn process_tls_records<'c, 'i>(
        &'c mut self,
        incoming_tls: &'i mut [u8],
    ) -> UnbufferedStatus<'c, 'i, Data> {
        let mut buffer = DeframerSliceBuffer::new(incoming_tls);
        let step = self.advance(&mut buffer);
        let discard = buffer.discarded();
        let state = match step {
            Ok(Step::Encode) => Ok(ConnectionState::EncodeTlsData(EncodeTlsData { conn: self })),
            Ok(Step::Transmit) => Ok(ConnectionState::TransmitTlsData(TransmitTlsData {
                conn: self,
            })),
            Ok(Step::ReadTraffic(range)) => Ok(ConnectionState::ReadTraffic(ReadTraffic {
                payload: &mut buffer.into_inner()[range],
            })),
            Ok(Step::ReadEarlyData(range)) => Ok(ConnectionState::ReadEarlyData(ReadEarlyData {
                payload: &mut buffer.into_inner()[range],
            })),
            Ok(Step::BlockedHandshake) => Ok(ConnectionState::BlockedHandshake),
            Ok(Step::WriteTraffic) => {
                Ok(ConnectionState::WriteTraffic(WriteTraffic { conn: self }))
            }
            Ok(Step::PeerClosed) => Ok(ConnectionState::PeerClosed),
            Ok(Step::Closed) => Ok(ConnectionState::Closed),
            Err(err) => Err(err),
        };
        UnbufferedStatus { discard, state }
    }

    /// Runs the state machine until there is something to report.
    fn advance(&mut self, buffer: &mut DeframerSliceBuffer<'_>) -> Result<Step, Error> {
        loop {
            // Output goes first: queued records (an alert after a failure
            // too), then the caller's confirmation that they were sent.
            if !self.core.common_state.sendable_tls.is_empty() {
                return Ok(Step::Encode);
            }
            if self.wants_write {
                return Ok(Step::Transmit);
            }
            if let Err(err) = &self.core.state {
                return Err(err.clone());
            }
            if self.core.common_state.encrypt_failed {
                return Err(self.core.fail(Error::EncryptError));
            }

            let common = &self.core.common_state;
            if common.has_received_close_notify {
                // RFC 9846 §6.1: nothing after close_notify is processed.
                if !self.emitted_peer_closed {
                    self.emitted_peer_closed = true;
                    return Ok(Step::PeerClosed);
                }
                if common.has_sent_close_notify() || !common.may_send_application_data {
                    return Ok(Step::Closed);
                }
                return Ok(Step::WriteTraffic);
            }

            let state = self.core.take_state()?;
            let (state, processed) = match self.core.process_one(state, buffer) {
                Ok(result) => result,
                // The connection has failed; report its alert, then the error.
                Err(_) => continue,
            };
            self.core.state = Ok(state);

            match processed {
                Some(Processed::Message) => {}
                Some(Processed::AppData(range)) => {
                    return Ok(Step::ReadTraffic(range));
                }
                Some(Processed::EarlyData(range)) => {
                    return Ok(Step::ReadEarlyData(range));
                }
                None => {
                    // The received flight is processed: answer a KeyUpdate
                    // request now, before any further application data
                    // (RFC 9846 §4.7.3).
                    if let Err(err) = self.core.maybe_send_key_update() {
                        return Err(self.core.fail(err));
                    }
                    if !self.core.common_state.sendable_tls.is_empty() {
                        continue;
                    }
                    return Ok(if self.core.common_state.may_send_application_data {
                        Step::WriteTraffic
                    } else {
                        Step::BlockedHandshake
                    });
                }
            }
        }
    }

    /// Derives keying material bound to this session (RFC 5705, RFC 9846
    /// §7.5).
    pub fn export_keying_material<T: AsMut<[u8]>>(
        &self,
        mut output: T,
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<T, Error> {
        self.core
            .export_keying_material(output.as_mut(), label, context)?;
        Ok(output)
    }

    /// Extracts the traffic secrets for kernel TLS offload.
    ///
    /// Requires `enable_secret_extraction` in the configuration, a completed
    /// handshake, no queued records and no partly received handshake
    /// message.
    pub fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
        if !self.core.common_state.sendable_tls.is_empty()
            || self.core.deframer.has_buffered_handshake()
        {
            return Err(Error::general(
                "cannot extract secrets with unsent or unprocessed data",
            ));
        }
        self.core.dangerous_extract_secrets()
    }
}

impl<Data: SideData> ConnectionCore<Data> {
    /// Encrypts `payload` as application data (or 0-RTT data when `early`)
    /// straight into `outgoing`; returns the bytes written.
    ///
    /// Everything is checked before anything is written: on error nothing
    /// of `payload` was taken. A KeyUpdate that is due (an answer to the
    /// peer, or a refresh for the confidentiality limit, RFC 9846 §5.5) goes
    /// out first, in the same buffer; one that this write makes due follows
    /// it.
    fn encrypt_into(
        &mut self,
        payload: &[u8],
        outgoing: &mut [u8],
        early: bool,
    ) -> Result<usize, EncryptError> {
        let common = &self.common_state;
        if common.encrypt_failed {
            return Err(EncryptError::Failed);
        }
        if common.has_sent_close_notify() || common.sent_fatal_alert {
            return Err(EncryptError::AlreadyClosed);
        }
        if payload.is_empty() {
            return Ok(0);
        }

        let record_layer = &common.record_layer;
        let max_frag = common.max_fragment_len();
        let full = payload.len() / max_frag;
        let rest = payload.len() % max_frag;
        let records = full + usize::from(rest > 0);
        let data_len = full
            .saturating_mul(HEADER_SIZE + record_layer.encrypted_payload_len(max_frag))
            .saturating_add(match rest {
                0 => 0,
                n => HEADER_SIZE + record_layer.encrypted_payload_len(n),
            });

        // 0-RTT data cannot be rekeyed, and TLS 1.2 has no KeyUpdate: at the
        // limit those connections must close (RFC 9846 §5.5).
        let can_rekey = !early
            && common.is_tls13()
            && common
                .key_update_to_send(KeyUpdateRequest::UpdateNotRequested)
                .is_some();
        let due = !early && (common.key_update_owed || common.refresh_traffic_keys_pending);
        if due && !can_rekey && !early {
            // At the epoch limit: nothing more is sent, the flags just clear.
            self.maybe_send_key_update()
                .map_err(|_| EncryptError::Failed)?;
        }
        let common = &self.common_state;
        let record_layer = &common.record_layer;
        let action_now = record_layer.pre_encrypt_action(records as u64);
        let rekey_before = can_rekey && (due || action_now == PreEncryptAction::Refuse);
        let action = if rekey_before {
            record_layer.pre_encrypt_action_after_key_update(records as u64)
        } else {
            action_now
        };
        let mut rekey_after = match action {
            PreEncryptAction::Nothing => false,
            PreEncryptAction::RefreshOrClose if can_rekey => true,
            _ => return Err(EncryptError::EncryptExhausted),
        };

        let key_update_len = HEADER_SIZE + record_layer.encrypted_payload_len(KEY_UPDATE_LEN);
        let required = common
            .sendable_tls
            .len()
            .saturating_add(data_len)
            .saturating_add(key_update_len * usize::from(rekey_before))
            .saturating_add(key_update_len * usize::from(rekey_after));
        if outgoing.len() < required {
            return Err(EncryptError::InsufficientSize(InsufficientSizeError {
                required_size: required,
            }));
        }

        if rekey_before {
            let queued = self.common_state.sendable_tls.len();
            self.common_state.refresh_traffic_keys_pending = true;
            self.maybe_send_key_update()
                .map_err(|_| EncryptError::Failed)?;
            if self.common_state.sendable_tls.len() == queued {
                // The state cannot send a KeyUpdate yet (a server's half-RTT
                // data): the write is judged under the current key.
                rekey_after = match action_now {
                    PreEncryptAction::Nothing => false,
                    PreEncryptAction::RefreshOrClose => true,
                    PreEncryptAction::Refuse => return Err(EncryptError::EncryptExhausted),
                };
            }
        }
        // Anything queued (the KeyUpdate just made) precedes the data.
        let mut written = self.drain_queued_into(outgoing)?;

        let fragments = self.common_state.max_fragment_len();
        for chunk in payload.chunks(fragments) {
            let plain = crate::msgs::message::OutboundPlainMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload: chunk.into(),
            };
            let record = match self.common_state.record_layer.encrypt_outgoing(plain) {
                Ok(record) => record.encode(),
                Err(_) => {
                    self.common_state.encrypt_failed = true;
                    return Err(EncryptError::Failed);
                }
            };
            written += self.copy_record(&record, &mut outgoing[written..])?;
        }

        if rekey_after {
            // RFC 9846 §5.5: refresh before the next write passes the limit.
            self.common_state.refresh_traffic_keys_pending = true;
            self.maybe_send_key_update()
                .map_err(|_| EncryptError::Failed)?;
            written += self.drain_queued_into(&mut outgoing[written..])?;
        }
        Ok(written)
    }

    /// Queues a `close_notify` and copies it, after anything queued before
    /// it, into `outgoing`.
    fn close_notify_into(&mut self, outgoing: &mut [u8]) -> Result<usize, EncryptError> {
        let common = &self.common_state;
        if common.has_sent_close_notify() || common.sent_fatal_alert {
            return Ok(0);
        }
        let required = common.sendable_tls.len()
            + HEADER_SIZE
            + common.record_layer.encrypted_payload_len(ALERT_LEN);
        if outgoing.len() < required {
            return Err(EncryptError::InsufficientSize(InsufficientSizeError {
                required_size: required,
            }));
        }
        self.common_state.send_close_notify();
        if self.common_state.encrypt_failed {
            return Err(EncryptError::Failed);
        }
        self.drain_queued_into(outgoing)
    }

    /// Moves every queued record into `outgoing`, whose size the caller has
    /// checked against the expected record lengths.
    fn drain_queued_into(&mut self, outgoing: &mut [u8]) -> Result<usize, EncryptError> {
        let queued = self.common_state.sendable_tls.len();
        if queued > outgoing.len() {
            // A record came out longer than the provider's
            // `encrypted_payload_len` promised. It stays queued (and is
            // offered by `EncodeTlsData`), so nothing goes out of order.
            return Err(EncryptError::InsufficientSize(InsufficientSizeError {
                required_size: queued,
            }));
        }
        Ok(self.common_state.sendable_tls.read(outgoing))
    }

    /// Copies one encrypted record into `outgoing`.
    fn copy_record(&mut self, record: &[u8], outgoing: &mut [u8]) -> Result<usize, EncryptError> {
        match outgoing.get_mut(..record.len()) {
            Some(out) => {
                out.copy_from_slice(record);
                Ok(record.len())
            }
            None => {
                // The provider's `encrypted_payload_len` was wrong and the
                // record has used its sequence number: the stream cannot
                // continue consistently.
                self.common_state.encrypt_failed = true;
                Err(EncryptError::Failed)
            }
        }
    }
}

/// What [`UnbufferedConnectionCommon::advance`] found.
enum Step {
    Encode,
    Transmit,
    ReadTraffic(Range<usize>),
    ReadEarlyData(Range<usize>),
    BlockedHandshake,
    WriteTraffic,
    PeerClosed,
    Closed,
}

impl<Data> Deref for UnbufferedConnectionCommon<Data> {
    type Target = CommonState;

    fn deref(&self) -> &Self::Target {
        &self.core.common_state
    }
}

impl<Data> DerefMut for UnbufferedConnectionCommon<Data> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core.common_state
    }
}

impl<Data> fmt::Debug for UnbufferedConnectionCommon<Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnbufferedConnectionCommon")
            .field("common", &self.core.common_state)
            .field("wants_write", &self.wants_write)
            .finish_non_exhaustive()
    }
}

/// The result of [`UnbufferedConnectionCommon::process_tls_records`].
#[must_use]
#[derive(Debug)]
pub struct UnbufferedStatus<'c, 'i, Data> {
    /// How many bytes to remove from the front of the `incoming_tls` buffer
    /// once `state` has been handled, and before the next call.
    ///
    /// Bytes up to here may have been decrypted in place and must not be
    /// fed in again.
    pub discard: usize,

    /// What the connection needs next, or the error that ended it.
    pub state: Result<ConnectionState<'c, 'i, Data>, Error>,
}

/// What an unbuffered connection needs next.
#[non_exhaustive]
pub enum ConnectionState<'c, 'i, Data> {
    /// An application data record was received; its plaintext is in the
    /// caller's buffer, covered by [`UnbufferedStatus::discard`].
    ReadTraffic(ReadTraffic<'i>),

    /// A 0-RTT application data record was received (servers only). It is
    /// replayable by an attacker: see
    /// [`ServerConfig::max_early_data_size`](crate::ServerConfig::max_early_data_size).
    ReadEarlyData(ReadEarlyData<'i>),

    /// Records are queued for sending: copy them out with
    /// [`EncodeTlsData::encode`].
    EncodeTlsData(EncodeTlsData<'c, Data>),

    /// Everything queued was encoded: send it, then call
    /// [`TransmitTlsData::done`].
    TransmitTlsData(TransmitTlsData<'c, Data>),

    /// The handshake cannot progress without more TLS bytes from the peer.
    BlockedHandshake,

    /// Application data may be sent; receiving more TLS bytes is needed for
    /// anything else.
    ///
    /// Also reported after our own `close_notify` while the peer has not
    /// closed, to ask for more input; [`WriteTraffic::encrypt`] then fails
    /// with [`EncryptError::AlreadyClosed`].
    WriteTraffic(WriteTraffic<'c, Data>),

    /// The peer sent `close_notify`: no more data will be received.
    ///
    /// Reported once. Later calls report [`Self::WriteTraffic`] while the
    /// connection may still send (until our own `close_notify`), then
    /// [`Self::Closed`].
    PeerClosed,

    /// Both sides sent `close_notify` (or the peer closed before the
    /// handshake completed). Nothing more will happen.
    Closed,
}

impl<Data> fmt::Debug for ConnectionState<'_, '_, Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadTraffic(r) => f.debug_tuple("ReadTraffic").field(r).finish(),
            Self::ReadEarlyData(r) => f.debug_tuple("ReadEarlyData").field(r).finish(),
            Self::EncodeTlsData(_) => f.write_str("EncodeTlsData"),
            Self::TransmitTlsData(_) => f.write_str("TransmitTlsData"),
            Self::BlockedHandshake => f.write_str("BlockedHandshake"),
            Self::WriteTraffic(_) => f.write_str("WriteTraffic"),
            Self::PeerClosed => f.write_str("PeerClosed"),
            Self::Closed => f.write_str("Closed"),
        }
    }
}

/// One received application data record, decrypted in place.
pub struct ReadTraffic<'i> {
    payload: &'i mut [u8],
}

impl<'i> ReadTraffic<'i> {
    /// The plaintext.
    pub fn payload(&self) -> &[u8] {
        self.payload
    }

    /// The plaintext, writable (it is the caller's buffer).
    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.payload
    }

    /// The plaintext for the rest of the buffer borrow.
    pub fn into_payload(self) -> &'i mut [u8] {
        self.payload
    }
}

impl fmt::Debug for ReadTraffic<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadTraffic")
            .field("len", &self.payload.len())
            .finish()
    }
}

/// One received 0-RTT application data record, decrypted in place.
pub struct ReadEarlyData<'i> {
    payload: &'i mut [u8],
}

impl<'i> ReadEarlyData<'i> {
    /// The plaintext.
    pub fn payload(&self) -> &[u8] {
        self.payload
    }

    /// The plaintext, writable (it is the caller's buffer).
    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.payload
    }

    /// The plaintext for the rest of the buffer borrow.
    pub fn into_payload(self) -> &'i mut [u8] {
        self.payload
    }
}

impl fmt::Debug for ReadEarlyData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadEarlyData")
            .field("len", &self.payload.len())
            .finish()
    }
}

/// Queued records waiting to be copied into the caller's output buffer.
pub struct EncodeTlsData<'c, Data> {
    conn: &'c mut UnbufferedConnectionCommon<Data>,
}

impl<Data> EncodeTlsData<'_, Data> {
    /// Copies as many whole queued records as fit into `outgoing_tls` and
    /// returns the bytes written.
    ///
    /// Fails, writing nothing, when not even the first record fits; the
    /// error carries that record's length. May be called again to copy
    /// more, into the rest of the same buffer or another one.
    pub fn encode(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncodeError> {
        let queue = &mut self.conn.core.common_state.sendable_tls;
        let mut written = 0;
        while let Some(record) = queue.chunk() {
            let len = record.len();
            let Some(out) = outgoing_tls.get_mut(written..written + len) else {
                if written == 0 {
                    return Err(EncodeError::InsufficientSize(InsufficientSizeError {
                        required_size: len,
                    }));
                }
                break;
            };
            out.copy_from_slice(record);
            queue.consume(len);
            written += len;
        }
        if written > 0 {
            self.conn.wants_write = true;
        }
        Ok(written)
    }
}

impl<Data> fmt::Debug for EncodeTlsData<'_, Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncodeTlsData")
            .field("queued", &self.conn.core.common_state.sendable_tls.len())
            .finish()
    }
}

/// Encoded records waiting to be sent by the caller.
pub struct TransmitTlsData<'c, Data> {
    conn: &'c mut UnbufferedConnectionCommon<Data>,
}

impl<Data: SideData> TransmitTlsData<'_, Data> {
    /// Reports that the encoded records were sent (or handed to the
    /// transport).
    pub fn done(self) {
        self.conn.wants_write = false;
    }

    /// Application data may already be sent along with these records: the
    /// writer's output must be sent after them.
    pub fn may_encrypt_app_data(&mut self) -> Option<WriteTraffic<'_, Data>> {
        let common = &self.conn.core.common_state;
        (common.may_send_application_data && !common.has_sent_close_notify())
            .then_some(WriteTraffic { conn: self.conn })
    }
}

impl TransmitTlsData<'_, ClientConnectionData> {
    /// 0-RTT data may be sent after these records (which end with the
    /// ClientHello): the writer's output must be sent after them.
    ///
    /// Returns `None` unless the configuration enables early data, the
    /// resumed ticket allows it, and the server has not declined it yet.
    /// Early data is replayable by an attacker; see
    /// [`ClientConnection::early_data`](crate::ClientConnection::early_data)
    /// for the caveats.
    pub fn may_encrypt_early_data(&mut self) -> Option<MayEncryptEarlyData<'_>> {
        let core = &self.conn.core;
        (core.data.early_data_writable()
            && core.common_state.early_traffic
            && core.common_state.record_layer.is_encrypting()
            && !core.common_state.has_sent_close_notify())
        .then_some(MayEncryptEarlyData { conn: self.conn })
    }
}

impl<Data> fmt::Debug for TransmitTlsData<'_, Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TransmitTlsData")
    }
}

/// Sends application data, closes, or rekeys the connection.
pub struct WriteTraffic<'c, Data> {
    conn: &'c mut UnbufferedConnectionCommon<Data>,
}

impl<Data: SideData> WriteTraffic<'_, Data> {
    /// Encrypts all of `application_data` into `outgoing_tls`, split into
    /// records of at most the configured fragment size, and returns the
    /// bytes written.
    ///
    /// On error nothing of `application_data` was sent. A KeyUpdate that is
    /// due (RFC 9846 §4.7.3, §5.5) is written into the same buffer, before or
    /// after the data, and counted in the size required.
    pub fn encrypt(
        &mut self,
        application_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        self.conn
            .core
            .encrypt_into(application_data, outgoing_tls, false)
    }

    /// Writes a `close_notify` alert into `outgoing_tls` and returns the
    /// bytes written (zero if it was already sent). No application data can
    /// be sent afterwards (RFC 9846 §6.1).
    pub fn queue_close_notify(&mut self, outgoing_tls: &mut [u8]) -> Result<usize, EncryptError> {
        self.conn.core.close_notify_into(outgoing_tls)
    }

    /// Rotates our traffic key and asks the peer to rotate theirs (TLS 1.3
    /// only; RFC 9846 §4.7.3). The KeyUpdate is queued: the next
    /// `process_tls_records` offers it through [`EncodeTlsData`].
    pub fn refresh_traffic_keys(self) -> Result<(), Error> {
        self.conn.core.refresh_traffic_keys()
    }
}

impl<Data> fmt::Debug for WriteTraffic<'_, Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WriteTraffic")
    }
}

/// Sends 0-RTT data from a client; see
/// [`TransmitTlsData::may_encrypt_early_data`].
pub struct MayEncryptEarlyData<'c> {
    conn: &'c mut UnbufferedConnectionCommon<ClientConnectionData>,
}

impl MayEncryptEarlyData<'_> {
    /// How many more bytes of early data the server's ticket allows.
    pub fn bytes_left(&self) -> usize {
        self.conn.core.data.early_data_left()
    }

    /// Encrypts all of `early_data` under the early traffic key into
    /// `outgoing_tls` and returns the bytes written. Fails, sending nothing,
    /// when it exceeds [`Self::bytes_left`].
    pub fn encrypt(
        &mut self,
        early_data: &[u8],
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EarlyDataError> {
        let core = &mut self.conn.core;
        if early_data.len() > core.data.early_data_left() {
            return Err(EarlyDataError::ExceededAllowedEarlyData);
        }
        let written = core
            .encrypt_into(early_data, outgoing_tls, true)
            .map_err(EarlyDataError::Encrypt)?;
        core.data.charge_early_data(early_data.len());
        Ok(written)
    }
}

impl fmt::Debug for MayEncryptEarlyData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MayEncryptEarlyData")
            .field("bytes_left", &self.bytes_left())
            .finish()
    }
}

/// The caller's buffer is too small.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsufficientSizeError {
    /// The buffer size needed to make progress.
    pub required_size: usize,
}

impl fmt::Display for InsufficientSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "buffer too small: {} bytes required", self.required_size)
    }
}

impl core::error::Error for InsufficientSizeError {}

/// Why [`EncodeTlsData::encode`] failed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The output buffer cannot hold the next record.
    InsufficientSize(InsufficientSizeError),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSize(e) => e.fmt(f),
        }
    }
}

impl core::error::Error for EncodeError {}

/// Why encrypting into the caller's buffer failed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptError {
    /// The output buffer is too small; nothing was written.
    InsufficientSize(InsufficientSizeError),
    /// The write key has reached its confidentiality or sequence-number
    /// limit and cannot be refreshed (TLS 1.2, 0-RTT data, or the RFC 9846
    /// §4.7.3 key epoch limit): the connection must be closed.
    EncryptExhausted,
    /// Our `close_notify` (or a fatal alert) was already sent.
    AlreadyClosed,
    /// Record protection failed; the connection is unusable.
    Failed,
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSize(e) => e.fmt(f),
            Self::EncryptExhausted => f.write_str("encryption key exhausted"),
            Self::AlreadyClosed => f.write_str("connection already closed for writing"),
            Self::Failed => f.write_str("record encryption failed"),
        }
    }
}

impl core::error::Error for EncryptError {}

/// Why [`MayEncryptEarlyData::encrypt`] failed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EarlyDataError {
    /// The data exceeds what the server's ticket allows.
    ExceededAllowedEarlyData,
    /// Encryption failed.
    Encrypt(EncryptError),
}

impl fmt::Display for EarlyDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExceededAllowedEarlyData => f.write_str("too much early data"),
            Self::Encrypt(e) => e.fmt(f),
        }
    }
}

impl core::error::Error for EarlyDataError {}
