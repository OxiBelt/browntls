//! State shared by client and server connections.

use alloc::vec::Vec;
use core::fmt;

use browntls_pki::CertificateDer;

use crate::crypto::SupportedKxGroup;
use crate::enums::{AlertDescription, ContentType, ProtocolVersion};
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
use crate::sync::Arc;
use crate::vecbuf::ChunkVecBuffer;

/// Plaintext received from the peer is buffered up to this many bytes before
/// the application must read it.
pub(crate) const DEFAULT_RECEIVED_PLAINTEXT_LIMIT: usize = 16 * 1024;

/// The default limit on buffered outgoing data (TLS bytes plus unsent
/// plaintext).
pub(crate) const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;

/// RFC 8449 §4: the smallest record size limit an endpoint may announce;
/// a smaller one is `illegal_parameter`.
pub(crate) const MIN_RECORD_SIZE_LIMIT: u16 = 64;

/// RFC 8449 §4: the largest record size limit worth announcing, the
/// protocol's own limit: 2^14 for TLS 1.2, 2^14 + 1 for TLS 1.3 (whose
/// limit counts the content type byte).
pub(crate) const fn max_record_size_limit(tls13: bool) -> u16 {
    if tls13 { 16_385 } else { 16_384 }
}

/// Checks a configured `record_size_limit` when a connection is created.
pub(crate) fn check_record_size_limit_config(limit: Option<u16>) -> Result<(), Error> {
    match limit {
        Some(limit) if limit < MIN_RECORD_SIZE_LIMIT => Err(Error::BadRecordSizeLimit),
        _ => Ok(()),
    }
}

/// How many unprotected ChangeCipherSpec records a TLS 1.3 peer may send
/// during the handshake (RFC 9846 appendix E.4).
const MAX_MIDDLEBOX_CCS: u8 = 2;

/// How many consecutive warning alerts we tolerate.
const MAX_WARNING_ALERTS: u8 = 4;

/// RFC 9846 §4.7.3: a sender MUST NOT let the number of key updates (the
/// key epoch) exceed 2^48-1. Receivers do not enforce this on the peer.
pub(crate) const MAX_KEY_UPDATES: u64 = (1 << 48) - 1;

/// How many HelloRequests a client ignores during its own handshake before
/// treating the server as misbehaving (RFC 5246 §7.4.1.1).
const MAX_IGNORED_HELLO_REQUESTS: u8 = 4;

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
    /// A full handshake: certificate authentication, or (TLS 1.3) an
    /// external PSK with (EC)DHE, see [`CommonState::external_psk_identity`].
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
    revocation_pending: bool,
    client_certificate_url_pending: bool,
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

    /// Whether progress requires resolving a pending certificate status
    /// request.
    pub fn revocation_pending(&self) -> bool {
        self.revocation_pending
    }

    /// Whether progress requires resolving a pending client certificate
    /// URL query (RFC 6066 §5, servers only).
    pub fn client_certificate_url_pending(&self) -> bool {
        self.client_certificate_url_pending
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
    pub(crate) pending_revocation: Option<alloc::boxed::Box<crate::revocation::PendingRevocation>>,
    pub(crate) peer_revocation_status: Option<crate::revocation::RevocationStatus>,
    pub(crate) revocation_auth_outstanding: bool,
    /// The client certificate URL query a TLS 1.2 server waits on.
    pub(crate) pending_certificate_url:
        Option<alloc::boxed::Box<crate::certificate_url::PendingCertificateUrl>>,
    message_fragmenter: MessageFragmenter,
    pub(crate) received_plaintext: ChunkVecBuffer,
    pub(crate) sendable_plaintext: ChunkVecBuffer,
    pub(crate) sendable_tls: ChunkVecBuffer,
    pub(crate) may_send_application_data: bool,
    pub(crate) may_receive_application_data: bool,
    pub(crate) early_traffic: bool,
    /// The early exporter (RFC 9846 §7.5), while 0-RTT is offered (client)
    /// or once it was accepted; dropped when 0-RTT is rejected.
    pub(crate) early_exporter: Option<crate::tls13::key_schedule::EarlyExporter>,
    pub(crate) sent_fatal_alert: bool,
    sent_close_notify: bool,
    pub(crate) has_received_close_notify: bool,
    pub(crate) has_seen_eof: bool,
    pub(crate) received_middlebox_ccs: u8,
    pub(crate) ignored_hello_requests: u8,
    pub(crate) received_warning_alerts: u8,
    pub(crate) received_key_update_requests: u8,
    pub(crate) refresh_traffic_keys_pending: bool,
    /// The peer sent `update_requested`; one KeyUpdate of ours is owed
    /// before our next application data record (RFC 9846 §4.7.3).
    pub(crate) key_update_owed: bool,
    /// We sent `update_requested` and have not received a KeyUpdate since,
    /// so we must not send another `update_requested` (RFC 9846 §4.7.3).
    pub(crate) key_update_request_outstanding: bool,
    /// How many KeyUpdates we have sent (our write key epoch past the
    /// initial application traffic secret).
    pub(crate) sent_key_updates: u64,
    pub(crate) enable_secret_extraction: bool,
    pub(crate) encrypt_failed: bool,
    pub(crate) fips: bool,
    /// Present on QUIC connections (RFC 9001): handshake messages and alerts
    /// go to the QUIC implementation instead of the record layer.
    pub(crate) quic: Option<alloc::boxed::Box<crate::quic::Quic>>,
    /// Present on DTLS connections (RFC 9147): handshake messages, alerts
    /// and application data go to the DTLS record layer and its flights
    /// instead of the TLS record layer.
    pub(crate) dtls: Option<alloc::boxed::Box<crate::dtls::Dtls>>,
    /// Driven by the unbuffered API: received application data stays in the
    /// caller's buffer instead of being copied into `received_plaintext`.
    pub(crate) unbuffered: bool,
    /// Unbuffered only: the record just processed was application data the
    /// state machine accepted, left in place for the caller.
    pub(crate) app_data_in_place: bool,
    /// The external PSK the handshake uses: the one selected, or the one a
    /// resumed session was established with.
    pub(crate) external_psk: Option<Arc<crate::psk::ExternalPsk>>,
    /// Whether the peer's Finished has verified, which authenticates the
    /// peer's knowledge of [`Self::external_psk`].
    pub(crate) external_psk_confirmed: bool,
    /// Present once the connection is handed to the kernel: records go to
    /// this queue as plaintext for the kernel to protect
    /// ([`crate::kernel::KernelConnection`]).
    pub(crate) kernel: Option<alloc::boxed::Box<crate::kernel::KernelQueue>>,
    /// The RFC 8844 values the peer sent, when a binding is configured
    /// ([`crate::external_binding`]).
    pub(crate) peer_external_binding:
        Option<alloc::boxed::Box<crate::external_binding::PeerExternalBinding>>,
    /// RFC 7924 state of this handshake ([`crate::cached_info`]).
    pub(crate) cached_info: crate::cached_info::CachedInfoState,
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
            pending_revocation: None,
            peer_revocation_status: None,
            revocation_auth_outstanding: false,
            pending_certificate_url: None,
            message_fragmenter: MessageFragmenter::default(),
            received_plaintext: ChunkVecBuffer::new(Some(DEFAULT_RECEIVED_PLAINTEXT_LIMIT)),
            sendable_plaintext: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            sendable_tls: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            may_send_application_data: false,
            may_receive_application_data: false,
            early_traffic: false,
            early_exporter: None,
            sent_fatal_alert: false,
            sent_close_notify: false,
            has_received_close_notify: false,
            has_seen_eof: false,
            received_middlebox_ccs: 0,
            ignored_hello_requests: 0,
            received_warning_alerts: 0,
            received_key_update_requests: 0,
            refresh_traffic_keys_pending: false,
            key_update_owed: false,
            key_update_request_outstanding: false,
            sent_key_updates: 0,
            enable_secret_extraction: false,
            encrypt_failed: false,
            fips: false,
            quic: None,
            dtls: None,
            unbuffered: false,
            app_data_in_place: false,
            external_psk: None,
            external_psk_confirmed: false,
            kernel: None,
            peer_external_binding: None,
            cached_info: Default::default(),
        }
    }

    /// Whether there are TLS bytes waiting for `write_tls`.
    pub fn wants_write(&self) -> bool {
        !self.sendable_tls.is_empty()
    }

    /// The OCSP request blocking certificate authentication, if any.
    pub fn pending_revocation(&self) -> Option<&crate::revocation::RevocationQuery> {
        self.pending_revocation
            .as_deref()
            .map(|pending| pending.query())
    }

    /// The revocation result of the most recently verified peer identity.
    pub fn peer_revocation_status(&self) -> Option<crate::revocation::RevocationStatus> {
        self.peer_revocation_status
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
        match self.negotiated_version {
            // The state machines run DTLS 1.3 as TLS 1.3.
            Some(ProtocolVersion::TLSv1_3) if self.is_dtls() => Some(ProtocolVersion::DTLSv1_3),
            version => version,
        }
    }

    /// How the handshake completed, once it has.
    pub fn handshake_kind(&self) -> Option<HandshakeKind> {
        self.handshake_kind
    }

    /// The identity of the external PSK (RFC 9846 §4.3.11) the handshake
    /// authenticated with; for an imported PSK (RFC 9258), its external
    /// identity. `None` until the peer's Finished message has verified (which
    /// proves the peer holds the key), and for a handshake that used no
    /// external PSK.
    ///
    /// Such a handshake is reported as [`HandshakeKind::Full`] (or
    /// [`HandshakeKind::FullWithHelloRetryRequest`]); unless certificate
    /// authentication was negotiated on top of it (RFC 8773), there are no
    /// peer certificates. A session resumed from a ticket issued on such a
    /// connection ([`HandshakeKind::Resumed`]) reports the same identity.
    ///
    /// A peer that offers or accepts external PSKs may still complete a
    /// handshake without one (with certificates, or by resuming a session
    /// that used none): unless `require_external_psk` is set in the
    /// [`ClientConfig`](crate::ClientConfig) or
    /// [`ServerConfig`](crate::ServerConfig), check this after the handshake.
    pub fn external_psk_identity(&self) -> Option<&[u8]> {
        self.external_psk
            .as_ref()
            .filter(|_| self.external_psk_confirmed)
            .map(|psk| psk.identity())
    }

    /// The external PSK to record in a ticket issued on this connection.
    pub(crate) fn external_psk_binding(
        &self,
        suites: &[SupportedCipherSuite],
        resumption_secret: &[u8],
    ) -> Result<Option<crate::psk::ExternalPskBinding>, Error> {
        let Some(psk) = self
            .external_psk
            .as_ref()
            .filter(|_| self.external_psk_confirmed)
        else {
            return Ok(None);
        };
        crate::psk::ExternalPskBinding::of(psk, suites, resumption_secret)
            .map(Some)
            .ok_or_else(|| Error::general("external PSK hash is unavailable in the provider"))
    }

    /// Whether every negotiated component claims FIPS validation.
    pub fn fips(&self) -> bool {
        self.fips
    }

    /// Whether the connection wants to read more TLS bytes: not when buffered
    /// plaintext is waiting for the application, not after the peer closed,
    /// and not while more control records (such as answers the peer's
    /// messages call for) wait to be written than the send buffer limit,
    /// capped at 64 KiB, allows.
    pub fn wants_read(&self) -> bool {
        self.received_plaintext.is_empty()
            && self.pending_revocation.is_none()
            && self.pending_certificate_url.is_none()
            && !self.has_received_close_notify
            && (self.may_send_application_data || self.sendable_tls.is_empty())
            && !self.control_backlog_full()
    }

    /// Whether more control records (anything but application data) wait to
    /// be written than the send buffer limit, capped at
    /// [`DEFAULT_BUFFER_LIMIT`], allows. They are queued whatever the limit,
    /// and the peer's requests call for some (KeyUpdate answers,
    /// post-handshake authentication responses): past this backlog the
    /// connection stops reading until the transport takes them.
    pub(crate) fn control_backlog_full(&self) -> bool {
        let bound = self
            .sendable_tls
            .limit()
            .map_or(DEFAULT_BUFFER_LIMIT, |limit| {
                limit.min(DEFAULT_BUFFER_LIMIT)
            });
        self.sendable_tls.control_len() > bound
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

    pub(crate) fn has_sent_close_notify(&self) -> bool {
        self.sent_close_notify
    }

    pub(crate) fn set_max_fragment_size(&mut self, new: Option<usize>) -> Result<(), Error> {
        self.message_fragmenter.set_max_fragment_size(new)
    }

    /// The largest plaintext fragment we put in one record.
    pub(crate) fn max_fragment_len(&self) -> usize {
        self.message_fragmenter.max_fragment_len()
    }

    /// Puts a negotiated `record_size_limit` (RFC 8449) into effect: `ours`
    /// is the value we announced, `peers` the value the peer announced.
    ///
    /// A peer value below 64 is `illegal_parameter` (RFC 8449 §4). A value
    /// above the protocol maximum is not an error (a server MUST NOT
    /// enforce that, and a client MAY abort but we do not): records never
    /// exceed the protocol maximum anyway. Our records then carry at most
    /// `peers` bytes of plaintext in TLS 1.2 and `peers - 1` in TLS 1.3,
    /// whose limit counts the content type (and any padding, of which we
    /// send none); the local `max_fragment_size` still applies when
    /// smaller. Protected records the peer sends from now on (except 0-RTT
    /// data) must respect `ours`, or the connection fails with
    /// `record_overflow`.
    pub(crate) fn apply_record_size_limits(
        &mut self,
        ours: u16,
        peers: u16,
        tls13: bool,
    ) -> Result<(), Error> {
        if peers < MIN_RECORD_SIZE_LIMIT {
            return Err(self.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::IllegalRecordSizeLimit,
            ));
        }
        let max = max_record_size_limit(tls13);
        let peers = usize::from(peers.min(max)) - usize::from(tls13);
        self.message_fragmenter.set_peer_record_size_limit(peers);
        self.record_layer
            .set_inbound_record_size_limit(ours.min(max), tls13);
        Ok(())
    }

    pub(crate) fn current_io_state(&self) -> IoState {
        IoState {
            tls_bytes_to_write: self.sendable_tls.len(),
            plaintext_bytes_to_read: self.received_plaintext.len(),
            peer_has_closed: self.has_received_close_notify,
            revocation_pending: self.pending_revocation.is_some(),
            client_certificate_url_pending: self.pending_certificate_url.is_some(),
        }
    }

    pub(crate) fn is_tls13(&self) -> bool {
        self.negotiated_version == Some(ProtocolVersion::TLSv1_3)
    }

    /// Whether this is a QUIC connection (RFC 9001).
    pub(crate) fn is_quic(&self) -> bool {
        self.quic.is_some()
    }

    /// Whether this is a DTLS connection (RFC 9147).
    pub(crate) fn is_dtls(&self) -> bool {
        self.dtls.is_some()
    }

    /// Queues `m` for sending, encrypting it when `must_encrypt`.
    ///
    /// On a QUIC connection nothing goes to the record layer: handshake
    /// messages are queued for CRYPTO frames at the current encryption level
    /// and a fatal alert is kept for the QUIC CONNECTION_CLOSE (RFC 9001
    /// §4.1.3, §4.8). Nothing else is ever sent over QUIC.
    ///
    /// On a DTLS connection handshake messages join the flight being
    /// prepared and alerts are sent once, both under the current sending
    /// epoch whatever `must_encrypt` says. There is no ChangeCipherSpec in
    /// DTLS 1.3 (RFC 9147 §5), and application data does not come this way.
    pub(crate) fn send_msg(&mut self, m: Message<'_>, must_encrypt: bool) {
        if let Some(dtls) = &mut self.dtls {
            match m.payload {
                MessagePayload::Handshake { encoded, .. } => {
                    dtls.queue_handshake(encoded.bytes());
                }
                MessagePayload::Alert(alert) => dtls.queue_alert(alert.level, alert.description),
                _ => {}
            }
            return;
        }
        if let Some(quic) = &mut self.quic {
            match m.payload {
                MessagePayload::Handshake { encoded, .. } => {
                    quic.queue_handshake(encoded.bytes().to_vec());
                }
                MessagePayload::Alert(alert) if alert.level == AlertLevel::Fatal => {
                    quic.record_alert(alert.description);
                }
                _ => {}
            }
            return;
        }
        if self.kernel.is_some() {
            self.send_to_kernel(&PlainMessage::from(m));
            return;
        }
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
        if let Some(dtls) = &mut self.dtls {
            // Only handshake messages (KeyUpdate) come this way.
            if m.typ == ContentType::Handshake {
                dtls.queue_handshake(m.payload.bytes());
            }
            return;
        }
        if self.send_to_kernel(&m) {
            return;
        }
        for fragment in self.message_fragmenter.fragment_message(&m) {
            self.send_single_fragment(fragment);
        }
    }

    /// Kernel offload: queues `m` as plaintext records for the kernel, one
    /// per fragment, each taking a sequence number of the current write
    /// key. Returns whether the connection is offloaded.
    pub(crate) fn send_to_kernel(&mut self, m: &PlainMessage) -> bool {
        let Some(queue) = self.kernel.as_mut() else {
            return false;
        };
        for fragment in self.message_fragmenter.fragment_message(m) {
            queue.push(crate::kernel::KernelOutput::Record {
                typ: fragment.typ,
                payload: fragment.payload.to_vec(),
            });
            self.record_layer.note_kernel_records(1);
        }
        true
    }

    /// Fragments and encrypts application data, honouring the confidentiality
    /// limit. Returns how much of `payload` was taken.
    pub(crate) fn send_appdata_encrypt(
        &mut self,
        payload: OutboundChunks<'_>,
        limit: Limit,
    ) -> usize {
        // The kernel sends the application data of an offloaded connection
        // (and the handover requires none to be queued).
        if self.kernel.is_some() {
            return 0;
        }
        let len = match limit {
            Limit::Yes => self.sendable_tls.apply_limit(payload.len()),
            Limit::No => payload.len(),
        };
        // Nothing to send (an empty write, or a full send buffer): the
        // fragmenter would still make one empty record of it, letting the
        // buffer grow past its limit with every retried write.
        if len == 0 {
            return 0;
        }
        let payload = payload.split_at(len).0;
        let fragments = len
            .div_ceil(self.message_fragmenter.max_fragment_len())
            .max(1);

        match self.record_layer.pre_encrypt_action(fragments as u64) {
            PreEncryptAction::Nothing => {}
            PreEncryptAction::RefreshOrClose => {
                if self.early_traffic {
                    // RFC 9846 §5.5: early data cannot be rekeyed, and MUST
                    // NOT exceed the limit; leave the rest for 1-RTT.
                    return 0;
                } else if self.is_tls13() {
                    // RFC 9846 §5.5: refresh keys before the limit is
                    // reached. The refresh happens as soon as this write
                    // returns; the configured limit sits well below the
                    // RFC's figure, leaving room for this write's records.
                    self.refresh_traffic_keys_pending = true;
                } else {
                    // TLS 1.2 has no key update; the connection must end.
                    self.send_close_notify();
                    return 0;
                }
            }
            PreEncryptAction::Refuse => {
                if self.early_traffic {
                    return 0;
                }
                // TLS 1.3 waits for the key refresh instead of closing,
                // unless no refresh is possible any more (RFC 9846 §4.7.3).
                if self.is_tls13() && self.sent_key_updates < MAX_KEY_UPDATES {
                    self.refresh_traffic_keys_pending = true;
                    return 0;
                }
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
        let application_data = m.typ == ContentType::ApplicationData;
        match self.record_layer.encrypt_outgoing(m) {
            Ok(em) if application_data => {
                self.sendable_tls.append(em.encode());
            }
            Ok(em) => self.queue_tls_message(em),
            Err(err) => {
                debug!("record encryption failed: {:?}", err);
                self.encrypt_failed = true;
            }
        }
    }

    /// Queues a control record (anything but application data). It is
    /// queued whatever the send buffer limit, and counts towards
    /// [`Self::control_backlog_full`] until it is written.
    pub(crate) fn queue_tls_message(&mut self, m: crate::msgs::message::OutboundOpaqueMessage) {
        self.sendable_tls.append_control(m.encode());
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

    /// Handles an incoming alert (RFC 9846 §6).
    pub(crate) fn process_alert(&mut self, alert: &AlertMessagePayload) -> Result<(), Error> {
        if alert.description == AlertDescription::CloseNotify {
            self.has_received_close_notify = true;
            return Ok(());
        }

        // TLS 1.3 removed warning alerts: every other alert is fatal
        // regardless of its level (RFC 9846 §6). In TLS 1.2 most alerts are
        // fatal by definition whatever level the peer wrote (RFC 5246
        // §7.2.2), and only the rest may be shrugged off as warnings.
        if alert.level == AlertLevel::Warning
            && !self.is_tls13()
            && !is_always_fatal(alert.description)
        {
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

        // RFC 9846 §6.1: user_canceled is a closure alert that MUST be
        // followed by close_notify, and receivers SHOULD keep reading until
        // that close_notify arrives. In TLS 1.3 the alert level carries no
        // meaning (§6), so the alert is ignored whatever level it arrived
        // with; in TLS 1.2 only a warning-level user_canceled is benign.
        if alert.description == AlertDescription::UserCanceled
            && (self.is_tls13() || alert.level == AlertLevel::Warning)
        {
            self.received_warning_alerts += 1;
            if self.received_warning_alerts > MAX_WARNING_ALERTS {
                return Err(self.send_fatal_alert(
                    AlertDescription::UnexpectedMessage,
                    PeerMisbehaved::TooManyWarningAlertsReceived,
                ));
            }
            return Ok(());
        }

        Err(Error::AlertReceived(alert.description))
    }

    /// Ignores a HelloRequest that arrives while the client is already
    /// handshaking (RFC 5246 §7.4.1.1), within reason.
    pub(crate) fn process_hello_request_during_handshake(&mut self) -> Result<(), Error> {
        if self.ignored_hello_requests >= MAX_IGNORED_HELLO_REQUESTS {
            return Err(self.send_fatal_alert(
                AlertDescription::UnexpectedMessage,
                PeerMisbehaved::TooManyRenegotiationRequests,
            ));
        }
        self.ignored_hello_requests += 1;
        trace!("Ignoring HelloRequest during handshake");
        Ok(())
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

    /// Buffers received application data for the application, or, for an
    /// unbuffered connection, notes that the record's plaintext is to be
    /// handed to the caller where it was decrypted.
    pub(crate) fn take_received_plaintext(&mut self, bytes: Payload<'_>) {
        if self.unbuffered {
            self.app_data_in_place = true;
            return;
        }
        self.received_plaintext.append(bytes.into_vec());
    }

    /// TLS 1.2: installs the record ciphers derived from `secrets`. Encryption
    /// starts when we send ChangeCipherSpec; decryption when we receive it.
    #[cfg(feature = "tls12")]
    pub(crate) fn start_encryption_tls12(
        &mut self,
        secrets: &crate::tls12::ConnectionSecrets,
        side: Side,
        order: crate::crypto::cipher::Tls12MacOrder,
    ) {
        let pair = secrets.make_cipher_pair(side, order);
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

    /// Sends plaintext buffered before application data could flow. What
    /// the record layer does not take (a key refresh is due first) stays
    /// buffered and goes out after the refresh.
    pub(crate) fn flush_plaintext(&mut self) {
        if !self.may_send_application_data {
            return;
        }
        while let Some(buf) = self.sendable_plaintext.pop() {
            let sent = self.send_appdata_encrypt(buf.as_slice().into(), Limit::No);
            if sent < buf.len() {
                self.sendable_plaintext.prepend(buf[sent..].to_vec());
                break;
            }
        }
    }

    /// Buffers application data for after the handshake.
    pub(crate) fn buffer_plaintext(&mut self, payload: OutboundChunks<'_>) -> usize {
        self.sendable_plaintext.append_limited_copy(payload)
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

    /// Encrypts and sends 0-RTT data under the early traffic key.
    pub(crate) fn send_early_plaintext(&mut self, data: &[u8]) -> usize {
        debug_assert!(self.early_traffic);
        debug_assert!(self.record_layer.is_encrypting());
        if data.is_empty() {
            return 0;
        }
        self.send_appdata_encrypt(data.into(), Limit::Yes)
    }

    /// Queues a TLS 1.3 KeyUpdate message to be encrypted under the *current*
    /// key before the caller rotates to the next one, and records it.
    ///
    /// Callers go through [`Self::key_update_to_send`] first, which applies
    /// the RFC 9846 §4.7.3 sending rules.
    pub(crate) fn send_key_update(&mut self, request: KeyUpdateRequest) {
        let m = Message::build_key_update(request);
        self.send_msg_encrypt(m.into());
        self.sent_key_updates += 1;
        // Any KeyUpdate of ours moves our write key on, which is what an
        // owed response would have done.
        self.key_update_owed = false;
        if request == KeyUpdateRequest::UpdateRequested {
            self.key_update_request_outstanding = true;
        }
    }

    /// Applies the RFC 9846 §4.7.3 sending rules to a wanted KeyUpdate.
    ///
    /// Returns `None` when no further KeyUpdate may be sent because the
    /// epoch limit (2^48-1 key updates) was reached. `update_requested` is
    /// downgraded to `update_not_requested` while an earlier request of ours
    /// has not been answered by any KeyUpdate from the peer.
    pub(crate) fn key_update_to_send(&self, wanted: KeyUpdateRequest) -> Option<KeyUpdateRequest> {
        if self.sent_key_updates >= MAX_KEY_UPDATES {
            return None;
        }
        match wanted {
            KeyUpdateRequest::UpdateRequested if self.key_update_request_outstanding => {
                Some(KeyUpdateRequest::UpdateNotRequested)
            }
            other => Some(other),
        }
    }

    /// Records a KeyUpdate received from the peer (after its validation).
    ///
    /// Returns an error when the peer keeps requesting updates without
    /// sending application data in between: a local resource bound, not an
    /// RFC 9846 rule.
    pub(crate) fn received_key_update(
        &mut self,
        request: KeyUpdateRequest,
        max_requests: u8,
    ) -> Result<(), Error> {
        // Any KeyUpdate from the peer lifts the ban on sending another
        // `update_requested` of ours.
        self.key_update_request_outstanding = false;
        if request == KeyUpdateRequest::UpdateRequested {
            self.received_key_update_requests = self.received_key_update_requests.saturating_add(1);
            if self.received_key_update_requests > max_requests {
                return Err(self.send_fatal_alert(
                    AlertDescription::UnexpectedMessage,
                    PeerMisbehaved::TooManyKeyUpdateRequests,
                ));
            }
            // Answered once, after this flight is processed and before any
            // further application data: several requests received while we
            // were silent get a single response (RFC 9846 §4.7.3).
            self.key_update_owed = true;
        }
        Ok(())
    }

    pub(crate) fn missing_extension(&mut self, why: PeerMisbehaved) -> Error {
        self.send_fatal_alert(AlertDescription::MissingExtension, why)
    }

    /// Notes that the transport reached EOF.
    pub(crate) fn mark_eof(&mut self) {
        self.has_seen_eof = true;
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

/// Whether RFC 5246 §7.2.2 defines `desc` as always fatal, so a warning
/// level on it is the peer's mistake, not a reason to carry on.
fn is_always_fatal(desc: AlertDescription) -> bool {
    matches!(
        desc,
        AlertDescription::UnexpectedMessage
            | AlertDescription::BadRecordMac
            | AlertDescription::DecryptionFailed
            | AlertDescription::RecordOverflow
            | AlertDescription::DecompressionFailure
            | AlertDescription::HandshakeFailure
            | AlertDescription::IllegalParameter
            | AlertDescription::UnknownCA
            | AlertDescription::AccessDenied
            | AlertDescription::DecodeError
            | AlertDescription::DecryptError
            | AlertDescription::ExportRestriction
            | AlertDescription::ProtocolVersion
            | AlertDescription::InsufficientSecurity
            | AlertDescription::InternalError
            | AlertDescription::InappropriateFallback
            | AlertDescription::UnsupportedExtension
            // RFC 6066 §5: "This alert is always fatal."
            | AlertDescription::BadCertificateHashValue
    )
}

#[cfg(test)]
mod tests;
