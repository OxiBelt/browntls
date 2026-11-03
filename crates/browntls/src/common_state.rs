//! State shared by client and server connections.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::CertificateDer;

use crate::crypto::SupportedKxGroup;
use crate::enums::{AlertDescription, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{Error, PeerMisbehaved};
use crate::log::{debug, trace, warning};
use crate::msgs::alert::AlertMessagePayload;
use crate::msgs::base::Payload;
use crate::msgs::enums::{AlertLevel, KeyUpdateRequest};
use crate::msgs::fragmenter::MessageFragmenter;
use crate::msgs::handshake::CertificateChain;
use crate::msgs::message::{
    Message, MessagePayload, OutboundChunks, OutboundPlainMessage, PlainMessage,
};
use crate::record_layer::{PreEncryptAction, RecordLayer};
use crate::suites::SupportedCipherSuite;
use crate::vecbuf::ChunkVecBuffer;

/// Plaintext received from the peer is buffered up to this many bytes before
/// the application must read it.
pub(crate) const DEFAULT_RECEIVED_PLAINTEXT_LIMIT: usize = 16 * 1024;

/// The default limit on buffered outgoing data (TLS bytes plus unsent plaintext).
pub(crate) const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;

/// How many unprotected ChangeCipherSpec records a TLS 1.3 peer may send
/// during the handshake (RFC 8446 appendix D.4).
const MAX_MIDDLEBOX_CCS: u8 = 2;

/// How many consecutive warning alerts we tolerate.
const MAX_WARNING_ALERTS: u8 = 4;

/// Which side of the connection this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The client.
    Client,
    /// The server.
    Server,
}

impl Side {
    pub(crate) fn peer(&self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

/// How the handshake was completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeKind {
    /// A full handshake with certificate authentication.
    Full,
    /// A full handshake that needed a HelloRetryRequest (TLS 1.3 only).
    FullWithHelloRetryRequest,
    /// An abbreviated handshake using a previous session.
    Resumed,
}

/// The two hello randoms.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnectionRandoms {
    pub(crate) client: [u8; 32],
    pub(crate) server: [u8; 32],
}

impl ConnectionRandoms {
    pub(crate) fn new(
        client: crate::msgs::handshake::Random,
        server: crate::msgs::handshake::Random,
    ) -> Self {
        Self {
            client: client.0,
            server: server.0,
        }
    }
}

/// Which key exchange group is in use.
#[derive(Debug)]
pub(crate) enum KxState {
    Start,
    Started(&'static dyn SupportedKxGroup),
    Complete(&'static dyn SupportedKxGroup),
}

impl KxState {
    pub(crate) fn complete(&mut self) {
        if let Self::Started(group) = self {
            *self = Self::Complete(*group);
        }
    }
}

/// What a connection did during `process_new_packets`.
#[derive(Debug, Eq, PartialEq)]
pub struct IoState {
    tls_bytes_to_write: usize,
    plaintext_bytes_to_read: usize,
    peer_has_closed: bool,
}

impl IoState {
    /// TLS bytes waiting for `write_tls`.
    pub fn tls_bytes_to_write(&self) -> usize {
        self.tls_bytes_to_write
    }

    /// Plaintext bytes waiting for `reader()`.
    pub fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }

    /// Whether the peer sent `close_notify`.
    pub fn peer_has_closed(&self) -> bool {
        self.peer_has_closed
    }
}

/// Connection state that is independent of the handshake position.
pub struct CommonState {
    pub(crate) negotiated_version: Option<ProtocolVersion>,
    pub(crate) handshake_kind: Option<HandshakeKind>,
    pub(crate) side: Side,
    pub(crate) record_layer: RecordLayer,
    pub(crate) suite: Option<SupportedCipherSuite>,
    pub(crate) kx_state: KxState,
    pub(crate) alpn_protocol: Option<Vec<u8>>,
    pub(crate) peer_certificates: Option<CertificateChain<'static>>,
    message_fragmenter: MessageFragmenter,
    pub(crate) received_plaintext: ChunkVecBuffer,
    pub(crate) sendable_plaintext: ChunkVecBuffer,
    pub(crate) sendable_tls: ChunkVecBuffer,
    pub(crate) queued_key_update_message: Option<Vec<u8>>,
    pub(crate) may_send_application_data: bool,
    pub(crate) may_receive_application_data: bool,
    pub(crate) early_traffic: bool,
    pub(crate) sent_fatal_alert: bool,
    sent_close_notify: bool,
    pub(crate) has_received_close_notify: bool,
    pub(crate) has_seen_eof: bool,
    pub(crate) received_middlebox_ccs: u8,
    pub(crate) received_warning_alerts: u8,
    pub(crate) received_key_update_requests: u8,
    pub(crate) refresh_traffic_keys_pending: bool,
    pub(crate) enable_secret_extraction: bool,
    pub(crate) encrypt_failed: bool,
    pub(crate) fips: bool,
}

impl CommonState {
    pub(crate) fn new(side: Side) -> Self {
        Self {
            negotiated_version: None,
            handshake_kind: None,
            side,
            record_layer: RecordLayer::new(),
            suite: None,
            kx_state: KxState::Start,
            alpn_protocol: None,
            peer_certificates: None,
            message_fragmenter: MessageFragmenter::default(),
            received_plaintext: ChunkVecBuffer::new(Some(DEFAULT_RECEIVED_PLAINTEXT_LIMIT)),
            sendable_plaintext: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            sendable_tls: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            queued_key_update_message: None,
            may_send_application_data: false,
            may_receive_application_data: false,
            early_traffic: false,
            sent_fatal_alert: false,
            sent_close_notify: false,
            has_received_close_notify: false,
            has_seen_eof: false,
            received_middlebox_ccs: 0,
            received_warning_alerts: 0,
            received_key_update_requests: 0,
            refresh_traffic_keys_pending: false,
            enable_secret_extraction: false,
            encrypt_failed: false,
            fips: false,
        }
    }

    /// Whether there are TLS bytes waiting for `write_tls`.
    pub fn wants_write(&self) -> bool {
        !self.sendable_tls.is_empty()
    }

    /// Whether the handshake is still in progress.
    pub fn is_handshaking(&self) -> bool {
        !(self.may_send_application_data && self.may_receive_application_data)
    }

    /// The peer's certificate chain, end entity first, once received.
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.peer_certificates.as_ref().map(|c| c.0.as_slice())
    }

    /// The negotiated ALPN protocol, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_protocol.as_deref()
    }

    /// The negotiated cipher suite, once chosen.
    pub fn negotiated_cipher_suite(&self) -> Option<SupportedCipherSuite> {
        self.suite
    }

    /// The key exchange group used, once the exchange completed.
    pub fn negotiated_key_exchange_group(&self) -> Option<&'static dyn SupportedKxGroup> {
        match self.kx_state {
            KxState::Complete(group) => Some(group),
            _ => None,
        }
    }

    /// The negotiated protocol version, once agreed.
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.negotiated_version
    }

    /// How the handshake completed, once it has.
    pub fn handshake_kind(&self) -> Option<HandshakeKind> {
        self.handshake_kind
    }

    /// Whether every negotiated component claims FIPS validation.
    pub fn fips(&self) -> bool {
        self.fips
    }

    /// Whether the connection wants to read more TLS bytes: not when buffered
    /// plaintext is waiting for the application, not after the peer closed.
    pub fn wants_read(&self) -> bool {
        self.received_plaintext.is_empty()
            && !self.has_received_close_notify
            && (self.may_send_application_data || self.sendable_tls.is_empty())
    }

    /// Sets the limit on buffered outgoing data.
    pub fn set_buffer_limit(&mut self, limit: Option<usize>) {
        self.sendable_plaintext.set_limit(limit);
        self.sendable_tls.set_limit(limit);
    }

    /// Queues a `close_notify` alert (once).
    pub fn send_close_notify(&mut self) {
        if self.sent_fatal_alert || self.has_sent_close_notify() {
            return;
        }
        debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
        self.send_warning_alert_no_log(AlertDescription::CloseNotify);
        self.sent_close_notify = true;
    }

    fn has_sent_close_notify(&self) -> bool {
        self.sent_close_notify
    }

    pub(crate) fn set_max_fragment_size(&mut self, new: Option<usize>) -> Result<(), Error> {
        self.message_fragmenter.set_max_fragment_size(new)
    }

    pub(crate) fn current_io_state(&self) -> IoState {
        IoState {
            tls_bytes_to_write: self.sendable_tls.len(),
            plaintext_bytes_to_read: self.received_plaintext.len(),
            peer_has_closed: self.has_received_close_notify,
        }
    }

    pub(crate) fn is_tls13(&self) -> bool {
        self.negotiated_version == Some(ProtocolVersion::TLSv1_3)
    }

    /// Queues `m` for sending, encrypting it when `must_encrypt`.
    pub(crate) fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool) {
        if !must_encrypt {
            let msg = PlainMessage::from(m);
            for fragment in self.message_fragmenter.fragment_message(&msg) {
                self.queue_tls_message(fragment.to_unencrypted_opaque());
            }
        } else {
            self.send_msg_encrypt(m.into());
        }
    }

    /// Fragments and encrypts `m`; handshake and alert records never count
    /// towards the confidentiality limit check (they are few).
    pub(crate) fn send_msg_encrypt(&mut self, m: PlainMessage) {
        for fragment in self.message_fragmenter.fragment_message(&m) {
            self.send_single_fragment(fragment);
        }
    }

    /// Fragments and encrypts application data, honouring the confidentiality
    /// limit. Returns how much of `payload` was taken.
    pub(crate) fn send_appdata_encrypt(
        &mut self,
        payload: OutboundChunks<'_>,
        limit: Limit,
    ) -> usize {
        let len = match limit {
            Limit::Yes => self.sendable_tls.apply_limit(payload.len()),
            Limit::No => payload.len(),
        };
        let payload = payload.split_at(len).0;
        let fragments = len
            .div_ceil(self.message_fragmenter.max_fragment_len())
            .max(1);

        match self.record_layer.pre_encrypt_action(fragments as u64) {
            PreEncryptAction::Nothing => {}
            PreEncryptAction::RefreshOrClose => {
                if self.is_tls13() {
                    // RFC 8446 §5.5: refresh keys before the limit is reached.
                    self.refresh_traffic_keys_pending = true;
                } else {
                    // TLS 1.2 has no key update; the connection must end.
                    self.send_close_notify();
                    return 0;
                }
            }
            PreEncryptAction::Refuse => {
                self.send_close_notify();
                return 0;
            }
        }

        for fragment in self.message_fragmenter.fragment_payload(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ) {
            self.send_single_fragment(fragment);
        }
        len
    }

    fn send_single_fragment(&mut self, m: OutboundPlainMessage<'_>) {
        match self.record_layer.encrypt_outgoing(m) {
            Ok(em) => self.queue_tls_message(em),
            Err(err) => {
                debug!("record encryption failed: {:?}", err);
                self.encrypt_failed = true;
            }
        }
    }

    pub(crate) fn queue_tls_message(&mut self, m: crate::msgs::message::OutboundOpaqueMessage) {
        self.sendable_tls.append(m.encode());
    }

    /// Sends a fatal alert (once) and returns `err` for the caller to surface.
    pub(crate) fn send_fatal_alert(
        &mut self,
        desc: AlertDescription,
        err: impl Into<Error>,
    ) -> Error {
        if !self.sent_fatal_alert {
            debug!("Sending fatal alert {:?}", desc);
            self.send_alert(AlertLevel::Fatal, desc);
            self.sent_fatal_alert = true;
        }
        err.into()
    }

    pub(crate) fn send_warning_alert(&mut self, desc: AlertDescription) {
        debug!("Sending warning alert {:?}", desc);
        self.send_warning_alert_no_log(desc);
    }

    fn send_warning_alert_no_log(&mut self, desc: AlertDescription) {
        self.send_alert(AlertLevel::Warning, desc);
    }

    fn send_alert(&mut self, level: AlertLevel, desc: AlertDescription) {
        let m = Message::build_alert(level, desc);
        let encrypt = self.record_layer.is_encrypting();
        self.send_msg(m, encrypt);
    }

    /// Handles an incoming alert (RFC 8446 §6).
    pub(crate) fn process_alert(&mut self, alert: &AlertMessagePayload) -> Result<(), Error> {
        if alert.description == AlertDescription::CloseNotify {
            self.has_received_close_notify = true;
            return Ok(());
        }

        // TLS 1.3 removed warning alerts: every other alert is fatal
        // regardless of its level (RFC 8446 §6).
        if alert.level == AlertLevel::Warning && !self.is_tls13() {
            self.received_warning_alerts += 1;
            if self.received_warning_alerts > MAX_WARNING_ALERTS {
                return Err(self.send_fatal_alert(
                    AlertDescription::UnexpectedMessage,
                    PeerMisbehaved::TooManyWarningAlertsReceived,
                ));
            }
            warning!("TLS alert warning received: {:?}", alert);
            return Ok(());
        }

        if alert.level == AlertLevel::Warning && alert.description == AlertDescription::UserCanceled
        {
            // RFC 8446 §6.1: user_canceled is informational and followed by close_notify.
            return Ok(());
        }

        Err(Error::AlertReceived(alert.description))
    }

    /// Accepts an unprotected TLS 1.3 ChangeCipherSpec during the handshake.
    pub(crate) fn process_middlebox_ccs(&mut self) -> Result<(), Error> {
        if !self.is_handshaking() || self.received_middlebox_ccs >= MAX_MIDDLEBOX_CCS {
            return Err(self.send_fatal_alert(
                AlertDescription::UnexpectedMessage,
                PeerMisbehaved::IllegalMiddleboxChangeCipherSpec,
            ));
        }
        self.received_middlebox_ccs += 1;
        trace!("Dropping CCS");
        Ok(())
    }

    /// Buffers received application data for the application.
    pub(crate) fn take_received_plaintext(&mut self, bytes: Payload<'_>) {
        self.received_plaintext.append(bytes.into_vec());
    }

    /// TLS 1.2: installs the record ciphers derived from `secrets`. Encryption
    /// starts when we send ChangeCipherSpec; decryption when we receive it.
    #[cfg(feature = "tls12")]
    pub(crate) fn start_encryption_tls12(
        &mut self,
        secrets: &crate::tls12::ConnectionSecrets,
        side: Side,
    ) {
        let pair = secrets.make_cipher_pair(side);
        self.record_layer
            .prepare_message_encrypter(pair.enc, secrets.suite().common.confidentiality_limit);
        self.record_layer.prepare_message_decrypter(pair.dec);
    }

    /// Sends ChangeCipherSpec and starts encrypting (TLS 1.2).
    #[cfg(feature = "tls12")]
    pub(crate) fn send_change_cipher_spec(&mut self) {
        let m = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::ChangeCipherSpec(crate::msgs::ccs::ChangeCipherSpecPayload),
        };
        self.send_msg(m, false);
        self.record_layer.start_encrypting();
    }

    /// We may now send application data; flushes anything the application
    /// wrote before the handshake finished.
    pub(crate) fn start_outgoing_traffic(&mut self) {
        self.may_send_application_data = true;
        self.flush_plaintext();
    }

    /// Both directions may now carry application data.
    pub(crate) fn start_traffic(&mut self) {
        self.may_receive_application_data = true;
        self.start_outgoing_traffic();
    }

    fn flush_plaintext(&mut self) {
        if !self.may_send_application_data {
            return;
        }
        while let Some(buf) = self.sendable_plaintext.pop() {
            self.send_appdata_encrypt(buf.as_slice().into(), Limit::No);
        }
    }

    /// Buffers application data for after the handshake.
    pub(crate) fn buffer_plaintext(&mut self, payload: OutboundChunks<'_>) -> usize {
        self.sendable_plaintext
            .append_limited_copy(&payload.to_vec())
    }

    /// Sends application data now, or buffers it until the handshake finishes.
    pub(crate) fn send_plain(&mut self, payload: OutboundChunks<'_>, limit: Limit) -> usize {
        if !self.may_send_application_data {
            return match limit {
                Limit::Yes => self.buffer_plaintext(payload),
                Limit::No => self.sendable_plaintext.append(payload.to_vec()),
            };
        }
        self.send_appdata_encrypt(payload, limit)
    }

    /// Checks an incoming message is one of `expected` content types; for
    /// handshake messages checks the handshake type too.
    pub(crate) fn check_message_types(
        &mut self,
        m: &Message<'_>,
        content_types: &[ContentType],
        handshake_types: &[HandshakeType],
    ) -> Result<(), Error> {
        let got_type = m.payload.content_type();
        if !content_types.contains(&got_type) {
            return Err(self.send_fatal_alert(
                AlertDescription::UnexpectedMessage,
                Error::InappropriateMessage {
                    expect_types: content_types.to_vec(),
                    got_type,
                },
            ));
        }
        if let MessagePayload::Handshake { parsed, .. } = &m.payload
            && !handshake_types.is_empty()
            && !handshake_types.contains(&parsed.typ())
        {
            return Err(self.send_fatal_alert(
                AlertDescription::UnexpectedMessage,
                Error::InappropriateHandshakeMessage {
                    expect_types: handshake_types.to_vec(),
                    got_type: parsed.typ(),
                },
            ));
        }
        Ok(())
    }

    /// Queues a TLS 1.3 KeyUpdate message to be encrypted under the *current*
    /// key before the caller rotates to the next one.
    pub(crate) fn send_key_update(&mut self, request: KeyUpdateRequest) {
        let m = Message::build_key_update(request);
        self.send_msg_encrypt(m.into());
    }

    pub(crate) fn missing_extension(&mut self, why: PeerMisbehaved) -> Error {
        self.send_fatal_alert(AlertDescription::MissingExtension, why)
    }

    /// Notes that the transport reached EOF.
    pub(crate) fn mark_eof(&mut self) {
        self.has_seen_eof = true;
    }

    pub(crate) fn sent_close_notify(&self) -> bool {
        self.sent_close_notify
    }
}

/// Whether `send_plain` respects the outgoing buffer limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Limit {
    Yes,
    No,
}

impl fmt::Debug for CommonState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommonState")
            .field("side", &self.side)
            .field("negotiated_version", &self.negotiated_version)
            .field("suite", &self.suite)
            .field("handshake_kind", &self.handshake_kind)
            .finish_non_exhaustive()
    }
}
