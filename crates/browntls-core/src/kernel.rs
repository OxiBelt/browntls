//! Kernel TLS offload: what stays in userspace once the kernel protects the
//! records of a connection.
//!
//! On Linux a TCP socket can protect application data itself (kernel TLS,
//! `setsockopt(TCP_ULP, "tls")` with `TLS_TX` and `TLS_RX` keys). The
//! handshake still happens here; afterwards a connection is turned into a
//! [`KernelConnection`] and its traffic secrets ([`ExtractedSecrets`]) are
//! given to the kernel. The kernel then encrypts and decrypts application
//! data on its own and hands everything else, decrypted, to the application
//! (Linux reports the record type in a `TLS_GET_RECORD_TYPE` control
//! message). Those records belong to [`KernelConnection::handle_record`]:
//! TLS 1.3 KeyUpdate and NewSessionTicket messages, post-handshake
//! authentication, alerts, and TLS 1.2 HelloRequest. In the other direction
//! the connection queues [`KernelOutput`]s: records the kernel must send
//! (a KeyUpdate, an alert, a post-handshake authentication answer, as a
//! `TLS_SET_RECORD_TYPE` control message) and new keys to install, in the
//! order they apply.
//!
//! Before the handover nothing of the connection may be left in flight: no
//! received application data waiting to be read, no buffered part of a
//! record, no records waiting to be written. A connection reports what
//! still stands in the way as a [`KernelHandoffBlocker`]; the handover fails
//! instead of dropping data.
//!
//! The kernel does not know the library's limits, so [`KernelConnection`]
//! keeps them: the caller reports the application data records the kernel
//! sent ([`KernelConnection::records_sent`]) and the connection refreshes
//! the TLS 1.3 keys, or closes a TLS 1.2 connection, at the cipher suite's
//! confidentiality limit (RFC 9846 §5.5), as it would in userspace. The
//! peer's KeyUpdate requests are bounded per application data received
//! ([`KernelConnection::application_data_received`]). Linux supports TLS 1.3
//! key updates from version 6.14; with an older kernel a KeyUpdate in either
//! direction ends the connection.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;

use crate::common_state::CommonState;
use crate::conn::{ConnectionCore, SideData};
use crate::enums::{AlertDescription, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::msgs::base::Payload;
use crate::msgs::codec::Reader as CodecReader;
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{InboundPlainMessage, Message, MessagePayload};
use crate::record_layer::PreEncryptAction;
use crate::suites::{ConnectionTrafficSecrets, ExtractedSecrets, SupportedCipherSuite};

/// What keeps a connection from being handed to the kernel now.
///
/// Transient blockers can be cleared by driving the connection on: read the
/// received data, write the queued records. Other blockers need a different
/// connection, configuration, or kernel.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelHandoffBlocker {
    /// `enable_secret_extraction` is off in the configuration.
    SecretExtractionDisabled,
    /// A QUIC connection: QUIC protects its packets itself.
    Quic,
    /// The handshake is not complete, or the connection failed.
    HandshakeIncomplete,
    /// The negotiated cipher suite has no kernel TLS form (TLS 1.2 AES-CBC,
    /// TLS 1.3 AES-128-CCM-8).
    UnsupportedCipherSuite,
    /// We sent `close_notify` or a fatal alert, or a record failed to
    /// encrypt.
    Closed,
    /// Received application data, or 0-RTT data a server accepted, has not
    /// been read yet.
    UnreadPlaintext,
    /// Received TLS bytes are buffered unprocessed: a part of a record, or
    /// records not yet processed. The kernel must receive whole records, so
    /// process the input and read the rest of the record first (buffered
    /// API only; the unbuffered API's buffer belongs to the caller, who must
    /// hand over only after processing it completely).
    UnprocessedInput,
    /// Records are queued for sending (`wants_write`).
    UnsentRecords,
    /// Application data written before the handshake completed is still
    /// queued.
    UnsentPlaintext,
    /// A KeyUpdate (an answer owed to the peer, or a key refresh) still has
    /// to be sent under the current key.
    KeyUpdatePending,
    /// Peer certificate authentication is waiting for revocation evidence.
    RevocationPending,
    /// The configured `max_fragment_size` is below the smallest record
    /// payload Linux accepts (64 bytes; 63 for TLS 1.3).
    FragmentTooSmall,
    /// The negotiated receive record size limit is below the protocol
    /// maximum, which Linux kernel TLS cannot enforce on received records.
    ReceiveRecordSizeLimit,
}

impl fmt::Display for KernelHandoffBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SecretExtractionDisabled => "secret extraction is disabled",
            Self::Quic => "QUIC connections cannot be offloaded",
            Self::HandshakeIncomplete => "the handshake is not complete",
            Self::UnsupportedCipherSuite => "the cipher suite has no kernel TLS form",
            Self::Closed => "the connection is closed",
            Self::UnreadPlaintext => "received data has not been read",
            Self::UnprocessedInput => "received TLS data has not been processed",
            Self::UnsentRecords => "records are waiting to be written",
            Self::UnsentPlaintext => "application data is waiting to be sent",
            Self::KeyUpdatePending => "a KeyUpdate is waiting to be sent",
            Self::RevocationPending => "certificate authentication is awaiting revocation evidence",
            Self::FragmentTooSmall => "the maximum fragment size is below what kernel TLS takes",
            Self::ReceiveRecordSizeLimit => {
                "the receive record size limit is below what kernel TLS can enforce"
            }
        })
    }
}

/// Something the kernel must do for a [`KernelConnection`], in order.
#[non_exhaustive]
pub enum KernelOutput {
    /// Send `payload` as one record of type `typ` under the current
    /// transmit key (Linux: `sendmsg` with a `TLS_SET_RECORD_TYPE` control
    /// message).
    Record {
        /// The record's content type.
        typ: ContentType,
        /// The record's plaintext, at most the negotiated maximum fragment
        /// length.
        payload: Vec<u8>,
    },
    /// Protect the records sent from now on with these keys, from sequence
    /// number zero (Linux: `TLS_TX`). Follows the KeyUpdate record that
    /// announced them (TLS 1.3 only).
    TxKeys(ConnectionTrafficSecrets),
    /// The records after the one just handled are protected with these
    /// keys, from sequence number zero (Linux: `TLS_RX`; the kernel stops
    /// reading after a KeyUpdate until they are installed). TLS 1.3 only.
    RxKeys(ConnectionTrafficSecrets),
}

impl fmt::Debug for KernelOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record { typ, payload } => f
                .debug_struct("Record")
                .field("typ", typ)
                .field("len", &payload.len())
                .finish(),
            Self::TxKeys(secrets) => f.debug_tuple("TxKeys").field(secrets).finish(),
            Self::RxKeys(secrets) => f.debug_tuple("RxKeys").field(secrets).finish(),
        }
    }
}

/// The queue of [`KernelOutput`]s; its presence on a [`CommonState`] puts
/// the connection in kernel mode, where every record it sends goes here as
/// plaintext instead of being encrypted.
#[derive(Default)]
pub(crate) struct KernelQueue {
    out: VecDeque<KernelOutput>,
}

impl KernelQueue {
    pub(crate) fn push(&mut self, output: KernelOutput) {
        self.out.push_back(output);
    }
}

/// A connection whose records the kernel protects; see the
/// [module documentation](self).
///
/// Obtained from a connection's `dangerous_into_kernel_connection` (buffered
/// or unbuffered, client or server) together with the secrets to install.
pub struct KernelConnection<Data> {
    pub(crate) core: ConnectionCore<Data>,
    version: ProtocolVersion,
    suite: SupportedCipherSuite,
}

impl<Data: SideData> ConnectionCore<Data> {
    /// What keeps this connection from being handed to the kernel, apart
    /// from input buffered outside the core (see
    /// [`KernelHandoffBlocker::UnprocessedInput`]).
    pub(crate) fn kernel_handoff_blocker(&self) -> Option<KernelHandoffBlocker> {
        let common = &self.common_state;
        if !common.enable_secret_extraction {
            return Some(KernelHandoffBlocker::SecretExtractionDisabled);
        }
        if common.is_quic() {
            return Some(KernelHandoffBlocker::Quic);
        }
        let Ok(state) = &self.state else {
            return Some(KernelHandoffBlocker::HandshakeIncomplete);
        };
        if common.pending_revocation.is_some() || common.revocation_auth_outstanding {
            return Some(KernelHandoffBlocker::RevocationPending);
        }
        if common.is_handshaking() || common.suite.is_none() {
            return Some(KernelHandoffBlocker::HandshakeIncomplete);
        }
        if common.sent_fatal_alert || common.has_sent_close_notify() || common.encrypt_failed {
            return Some(KernelHandoffBlocker::Closed);
        }
        match state.extract_secrets() {
            Ok(_) => {}
            Err(Error::HandshakeNotComplete) => {
                return Some(KernelHandoffBlocker::HandshakeIncomplete);
            }
            Err(_) => return Some(KernelHandoffBlocker::UnsupportedCipherSuite),
        }
        let max_rx_record_size = crate::common_state::max_record_size_limit(common.is_tls13());
        if common
            .negotiated_receive_record_size_limit()
            .is_some_and(|limit| limit < max_rx_record_size)
        {
            return Some(KernelHandoffBlocker::ReceiveRecordSizeLimit);
        }
        if let Some(blocker) = self.in_flight_blocker() {
            return Some(blocker);
        }
        // `TLS_MIN_RECORD_SIZE_LIM` of net/tls, less the TLS 1.3 content type.
        let floor = if common.is_tls13() { 63 } else { 64 };
        if common.max_tx_payload_len().is_some_and(|len| len < floor) {
            return Some(KernelHandoffBlocker::FragmentTooSmall);
        }
        None
    }

    /// Something in flight that extracted secrets could not account for,
    /// apart from input buffered outside the core: pending revocation
    /// evidence, unread plaintext, queued records or plaintext, or a KeyUpdate
    /// still to be sent. Unlike [`Self::kernel_handoff_blocker`], it is
    /// reported whatever else blocks the handover, so that
    /// `dangerous_extract_secrets` refuses it after `close_notify` or an
    /// encryption failure too.
    pub(crate) fn in_flight_blocker(&self) -> Option<KernelHandoffBlocker> {
        let common = &self.common_state;
        if common.pending_revocation.is_some() || common.revocation_auth_outstanding {
            return Some(KernelHandoffBlocker::RevocationPending);
        }
        if !common.received_plaintext.is_empty() || self.data.has_unread_early_data() {
            return Some(KernelHandoffBlocker::UnreadPlaintext);
        }
        if !common.sendable_tls.is_empty() {
            return Some(KernelHandoffBlocker::UnsentRecords);
        }
        if !common.sendable_plaintext.is_empty() {
            return Some(KernelHandoffBlocker::UnsentPlaintext);
        }
        if common.key_update_owed || common.refresh_traffic_keys_pending {
            return Some(KernelHandoffBlocker::KeyUpdatePending);
        }
        None
    }

    /// Hands the connection over: its secrets for the kernel, and the
    /// [`KernelConnection`] for the records the kernel passes back.
    ///
    /// A handshake message the peer has only partly sent stays buffered
    /// and is completed by the records the kernel delivers.
    pub(crate) fn into_kernel_connection(
        mut self,
    ) -> Result<(ExtractedSecrets, KernelConnection<Data>), Error> {
        if let Some(blocker) = self.kernel_handoff_blocker() {
            return Err(Error::General(alloc::format!(
                "cannot hand the connection to the kernel: {blocker}"
            )));
        }
        let secrets = self.extracted_secrets()?;
        let (Some(version), Some(suite)) = (
            self.common_state.negotiated_version,
            self.common_state.suite,
        ) else {
            return Err(Error::HandshakeNotComplete);
        };
        self.common_state.kernel = Some(Box::default());
        Ok((
            secrets,
            KernelConnection {
                core: self,
                version,
                suite,
            },
        ))
    }
}

impl CommonState {
    /// [`KernelConnection::max_tx_payload_len`], known once the handshake
    /// is complete: a driver can check before the handover that the kernel
    /// supports the limit.
    pub fn max_tx_payload_len(&self) -> Option<u16> {
        let len = self.max_fragment_len();
        match u16::try_from(len) {
            Ok(len) if usize::from(len) < crate::msgs::message::MAX_PLAINTEXT_LEN => Some(len),
            _ => None,
        }
    }
}

impl KernelConnection<crate::client::ClientConnectionData> {
    /// The reference identity authenticated in the userspace handshake.
    pub fn matched_service_identity(&self) -> Option<&browntls_pki::ReferenceIdentifier> {
        self.core.common_state.matched_service_identity()
    }
}

impl<Data: SideData> KernelConnection<Data> {
    /// The negotiated protocol version.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    /// The negotiated cipher suite.
    pub fn negotiated_cipher_suite(&self) -> SupportedCipherSuite {
        self.suite
    }

    /// The most plaintext one record may carry, when the peer's
    /// `record_size_limit` (RFC 8449) or the configured `max_fragment_size`
    /// asks for less than the protocol maximum of 16384 bytes; `None`
    /// otherwise.
    ///
    /// The kernel must then be told (Linux 6.19 and later:
    /// `TLS_TX_MAX_PAYLOAD_LEN`), or its full-size records overflow the
    /// peer's limit. The TLS 1.3 content type byte is not included.
    pub fn max_tx_payload_len(&self) -> Option<u16> {
        self.core.common_state.max_tx_payload_len()
    }

    /// Handles one record the kernel decrypted that is not application
    /// data: `typ` is the record's content type (Linux:
    /// `TLS_GET_RECORD_TYPE`), `payload` its whole plaintext.
    ///
    /// Afterwards [`Self::pop_output`] yields what the record calls for,
    /// for example new receive keys and a KeyUpdate in answer. On error the
    /// connection has failed for good; send the outputs still queued (the
    /// fatal alert) before closing the socket.
    ///
    /// Application data must not be passed here: the kernel gives it to
    /// the application directly. A record arriving after the peer's
    /// `close_notify` is ignored (RFC 9846 §6.1).
    pub fn handle_record(&mut self, typ: ContentType, payload: &[u8]) -> Result<(), Error> {
        if typ == ContentType::ApplicationData {
            return Err(Error::General(
                "application data is read from the kernel, not handled".into(),
            ));
        }
        let state = self.core.take_state()?;
        if self.core.common_state.has_received_close_notify {
            self.core.state = Ok(state);
            return Ok(());
        }
        if let Some((alert, err)) = self.refuse_record(typ, payload) {
            let err = self.core.common_state.send_fatal_alert(alert, err);
            return Err(self.core.fail(err));
        }
        let state = match typ {
            ContentType::Handshake => self.handle_handshake(state, payload)?,
            _ => {
                let result = match Message::try_from(InboundPlainMessage::new(
                    typ,
                    ProtocolVersion::TLSv1_2,
                    payload,
                )) {
                    Ok(msg) => ConnectionCore::process_msg(
                        &mut self.core.common_state,
                        &mut self.core.data,
                        state,
                        msg,
                    ),
                    Err(err) => Err(self
                        .core
                        .common_state
                        .send_fatal_alert(AlertDescription::from(err), Error::from(err))),
                };
                match result {
                    Ok(state) => state,
                    Err(err) => return Err(self.core.fail(err)),
                }
            }
        };
        self.core.state = Ok(state);
        self.send_due_key_update()
    }

    /// The checks the deframer makes in userspace that still apply to a
    /// whole record, and the one record shape kernel TLS cannot continue.
    fn refuse_record(&self, typ: ContentType, payload: &[u8]) -> Option<(AlertDescription, Error)> {
        let joining = !self.core.deframer.joiner.is_empty();
        if typ == ContentType::Handshake && payload.is_empty() {
            return Some((
                AlertDescription::DecodeError,
                InvalidMessage::InvalidEmptyPayload.into(),
            ));
        }
        if typ != ContentType::Handshake && joining {
            return Some((
                AlertDescription::UnexpectedMessage,
                PeerMisbehaved::MessageInterleavedWithHandshakeMessage.into(),
            ));
        }
        // Linux pauses reception after any handshake record whose first
        // byte is the KeyUpdate type, until new receive keys are set. Only
        // a record that is exactly one whole TLS 1.3 KeyUpdate brings them;
        // anything else (a fragment, a continuation that starts with that
        // byte) would leave the connection stalled for good.
        let whole_key_update = self.version == ProtocolVersion::TLSv1_3
            && !joining
            && payload.len() == 5
            && payload[1..4] == [0, 0, 1];
        if typ == ContentType::Handshake
            && payload.first() == Some(&u8::from(HandshakeType::KeyUpdate))
            && !whole_key_update
        {
            return Some((
                AlertDescription::UnexpectedMessage,
                Error::General(
                    "a handshake record starting with the KeyUpdate type that is not one \
                     whole KeyUpdate stalls kernel TLS"
                        .into(),
                ),
            ));
        }
        None
    }

    /// Joins `payload` onto any partial handshake message and processes
    /// every complete one.
    fn handle_handshake(
        &mut self,
        mut state: Box<dyn crate::conn::State<Data>>,
        mut data: &[u8],
    ) -> Result<Box<dyn crate::conn::State<Data>>, Error> {
        let version = self.version;
        let starts_with_key_update = data.first() == Some(&u8::from(HandshakeType::KeyUpdate));
        loop {
            let take = data.len().min(self.core.deframer.joiner.room());
            if take > 0 {
                if let Err(err) = self.core.deframer.joiner.push(&data[..take]) {
                    let err = match err {
                        Error::InvalidMessage(e) => self
                            .core
                            .common_state
                            .send_fatal_alert(AlertDescription::from(e), err),
                        other => other,
                    };
                    return Err(self.core.fail(err));
                }
                data = &data[take..];
            }

            let mut progressed = false;
            while let Some(len) = self.core.deframer.joiner.complete_message_len() {
                progressed = true;
                let bytes = &self.core.deframer.joiner.buffered()[..len];
                let mut key_update = false;
                let result = match HandshakeMessagePayload::read_version(
                    &mut CodecReader::init(bytes),
                    version,
                ) {
                    Ok(parsed) => {
                        key_update = matches!(parsed.0, HandshakePayload::KeyUpdate(_));
                        let msg = Message {
                            version: ProtocolVersion::TLSv1_2,
                            payload: MessagePayload::Handshake {
                                parsed,
                                encoded: Payload::Borrowed(bytes),
                            },
                        };
                        ConnectionCore::process_msg(
                            &mut self.core.common_state,
                            &mut self.core.data,
                            state,
                            msg,
                        )
                    }
                    Err(err) => Err(self
                        .core
                        .common_state
                        .send_fatal_alert(AlertDescription::from(err), Error::from(err))),
                };
                self.core.deframer.joiner.consume(len);
                state = match result {
                    Ok(next) => next,
                    Err(err) => return Err(self.core.fail(err)),
                };
                if key_update {
                    // RFC 8446 §5.1: a KeyUpdate ends its record; nothing
                    // may follow it under the old key.
                    if !self.core.deframer.joiner.is_empty() || !data.is_empty() {
                        let err = self.core.common_state.send_fatal_alert(
                            AlertDescription::UnexpectedMessage,
                            PeerMisbehaved::KeyEpochWithPendingFragment,
                        );
                        return Err(self.core.fail(err));
                    }
                    // Linux pauses reception only for a record that starts
                    // with the KeyUpdate. After other messages in the same
                    // record nothing stops a second reader of the socket
                    // (splice, another thread) from reading on under the old
                    // key before the new one is installed. Refusing costs
                    // interoperability with peers that coalesce a KeyUpdate
                    // with other messages, which is legal but rare.
                    if !starts_with_key_update {
                        let err = self.core.common_state.send_fatal_alert(
                            AlertDescription::UnexpectedMessage,
                            Error::General(
                                "a KeyUpdate after other messages in its record is not \
                                 supported by kernel TLS"
                                    .into(),
                            ),
                        );
                        return Err(self.core.fail(err));
                    }
                    match state.extract_secrets() {
                        Ok(secrets) => self.queue(KernelOutput::RxKeys(secrets.rx)),
                        Err(err) => return Err(self.core.fail(err)),
                    }
                }
            }

            if data.is_empty() {
                return Ok(state);
            }
            if take == 0 && !progressed {
                // Unreachable: the joiner rejects a declared length that
                // does not fit before it fills up.
                let err = self.core.common_state.send_fatal_alert(
                    AlertDescription::DecodeError,
                    InvalidMessage::HandshakePayloadTooLarge,
                );
                return Err(self.core.fail(err));
            }
        }
    }

    /// Takes the next thing the kernel must do, in order.
    pub fn pop_output(&mut self) -> Option<KernelOutput> {
        self.core.common_state.kernel.as_mut()?.out.pop_front()
    }

    /// Whether [`Self::pop_output`] has something.
    pub fn has_output(&self) -> bool {
        self.core
            .common_state
            .kernel
            .as_ref()
            .is_some_and(|k| !k.out.is_empty())
    }

    /// Records that the kernel sent `records` application data records
    /// under the current transmit key.
    ///
    /// When they reach the cipher suite's confidentiality limit (RFC 9846
    /// §5.5) a TLS 1.3 connection queues a key refresh (a KeyUpdate and new
    /// transmit keys) and a TLS 1.2 connection queues `close_notify`;
    /// [`Self::may_send_application_data`] tells whether more data may be
    /// sent. Fails once the limit has been passed and no refresh is possible.
    ///
    /// Report records before carrying out the outputs queued so far: once
    /// [`KernelOutput::TxKeys`] is installed the count starts again for the
    /// new key, so records sent under the old key but reported later would
    /// be counted against the new one.
    ///
    /// Callers that cannot count records exactly must overcount: Linux
    /// closes a record at the end of every `send` without `MSG_MORE`, so
    /// one write of `n` bytes makes at most `n.div_ceil(max)` records, `max`
    /// being [`Self::max_tx_payload_len`] or 16384.
    pub fn records_sent(&mut self, records: u64) -> Result<(), Error> {
        if let Err(err) = &self.core.state {
            return Err(err.clone());
        }
        let common = &mut self.core.common_state;
        let action = common.record_layer.pre_encrypt_action(records);
        common.record_layer.note_kernel_records(records);
        match action {
            PreEncryptAction::Nothing => Ok(()),
            PreEncryptAction::RefreshOrClose | PreEncryptAction::Refuse
                if self.version == ProtocolVersion::TLSv1_3
                    && common
                        .key_update_to_send(
                            crate::msgs::enums::KeyUpdateRequest::UpdateNotRequested,
                        )
                        .is_some() =>
            {
                common.refresh_traffic_keys_pending = true;
                self.send_due_key_update()
            }
            PreEncryptAction::RefreshOrClose => {
                common.send_close_notify();
                Ok(())
            }
            PreEncryptAction::Refuse => {
                common.send_close_notify();
                Err(Error::EncryptError)
            }
        }
    }

    /// Whether application data may be sent now: the connection has not
    /// failed or been closed by us, and the write key has room left.
    pub fn may_send_application_data(&self) -> bool {
        let common = &self.core.common_state;
        self.core.state.is_ok()
            && !common.sent_fatal_alert
            && !common.has_sent_close_notify()
            && common.record_layer.pre_encrypt_action(1) != PreEncryptAction::Refuse
    }

    /// Records that the kernel delivered application data (a non-empty
    /// read), which renews the budget of KeyUpdate and post-handshake
    /// authentication requests the peer may make without sending data.
    pub fn application_data_received(&mut self) {
        if let Ok(state) = &mut self.core.state {
            state.received_application_data(&mut self.core.common_state);
        }
    }

    /// Rotates the transmit keys and asks the peer to rotate theirs (TLS 1.3
    /// KeyUpdate with `update_requested`, unless an earlier request is still
    /// unanswered): queues the KeyUpdate record, then the new transmit keys.
    pub fn refresh_traffic_keys(&mut self) -> Result<(), Error> {
        if self.version != ProtocolVersion::TLSv1_3 {
            return Err(Error::General("TLS 1.2 has no key update".into()));
        }
        let before = self.core.common_state.sent_key_updates;
        self.core.refresh_traffic_keys()?;
        self.queue_tx_keys_if_rotated(before)
    }

    /// Queues `close_notify` (once); nothing is sent after it.
    pub fn send_close_notify(&mut self) {
        self.core.common_state.send_close_notify();
    }

    /// Whether the peer sent `close_notify`.
    pub fn peer_has_closed(&self) -> bool {
        self.core.common_state.has_received_close_notify
    }

    /// Sends the KeyUpdate that is due (an answer to the peer, or a refresh
    /// at the confidentiality limit), followed by the new transmit keys.
    fn send_due_key_update(&mut self) -> Result<(), Error> {
        let before = self.core.common_state.sent_key_updates;
        if let Err(err) = self.core.maybe_send_key_update() {
            return Err(self.core.fail(err));
        }
        self.queue_tx_keys_if_rotated(before)
    }

    fn queue_tx_keys_if_rotated(&mut self, before: u64) -> Result<(), Error> {
        if self.core.common_state.sent_key_updates == before {
            return Ok(());
        }
        let secrets = match &self.core.state {
            Ok(state) => state.extract_secrets(),
            Err(err) => Err(err.clone()),
        };
        match secrets {
            Ok(secrets) => {
                self.queue(KernelOutput::TxKeys(secrets.tx));
                Ok(())
            }
            Err(err) => Err(self.core.fail(err)),
        }
    }

    fn queue(&mut self, output: KernelOutput) {
        if let Some(kernel) = &mut self.core.common_state.kernel {
            kernel.push(output);
        }
    }

    /// The connection's common state (read only).
    pub fn common_state(&self) -> &CommonState {
        &self.core.common_state
    }
}

impl KernelConnection<crate::client::ClientConnectionData> {
    /// How many valid TLS 1.3 tickets this connection accepted for storage,
    /// before and after the handover.
    pub fn tls13_tickets_received(&self) -> u32 {
        self.core.data.tls13_tickets_received
    }
}

impl<Data> fmt::Debug for KernelConnection<Data> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KernelConnection")
            .field("version", &self.version)
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}
