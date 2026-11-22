//! The client handshake up to version negotiation: ClientHello, ServerHello
//! and HelloRetryRequest.

use alloc::boxed::Box;
use alloc::vec::Vec;

use browntls_pki::ServerName;

use super::client_conn::ClientConnectionData;
use super::common::ClientHelloDetails;
#[cfg(feature = "tls12")]
use super::tls12;
use super::{ClientConfig, tls13};
use crate::common_state::ConnectionRandoms;
use crate::common_state::{CommonState, HandshakeKind, KxState};
use crate::conn::{Context, State};
use crate::crypto::{ActiveKeyExchange, SharedSecret};
use crate::ech::client::{ClientEch, EchOffer};
use crate::ech::{self, EchStatus};
use crate::enums::{AlertDescription, CertificateType, ProtocolVersion};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHashBuffer;
use crate::log::{debug, trace};
use crate::msgs::enums::{Compression, ExtensionType, NamedGroup};
use crate::msgs::grease::GreaseValues;
use crate::msgs::handshake::{
    HandshakeMessagePayload, HandshakePayload, ProtocolName, Random, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist::{self, Retrieved};
use crate::psk::OfferedPsk;
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;
use crate::tls13::extensions::{Tls13Message, first_disallowed};

mod client_hello;

use client_hello::emit_client_hello_for_retry;
pub(super) use client_hello::start_handshake;

pub(super) type NextState = Box<dyn State<ClientConnectionData>>;
pub(super) type NextStateOrError = Result<NextState, Error>;
pub(super) type ClientContext<'a> = Context<'a, ClientConnectionData>;

/// A stored session that may be offered for resumption.
pub(super) enum ClientSessionValue {
    Tls13(persist::Tls13ClientSessionValue),
    #[cfg(feature = "tls12")]
    Tls12(persist::Tls12ClientSessionValue),
}

impl core::ops::Deref for ClientSessionValue {
    type Target = persist::ClientSessionCommon;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Tls13(v) => &v.common,
            #[cfg(feature = "tls12")]
            Self::Tls12(v) => &v.common,
        }
    }
}

/// Our key share for the ClientHello, possibly reusing part of a hybrid
/// share after a HelloRetryRequest (RFC 8446 §4.2.8 and the hybrid draft).
pub(super) enum OfferedKeyShare {
    Full(Box<dyn ActiveKeyExchange>),
    HybridComponent(Box<dyn ActiveKeyExchange>),
}

impl OfferedKeyShare {
    pub(super) fn group(&self) -> NamedGroup {
        match self {
            Self::Full(kx) => kx.group(),
            Self::HybridComponent(kx) => kx
                .hybrid_component()
                .map(|(g, _)| g)
                .unwrap_or_else(|| kx.group()),
        }
    }

    pub(super) fn pub_key(&self) -> &[u8] {
        match self {
            Self::Full(kx) => kx.pub_key(),
            Self::HybridComponent(kx) => kx
                .hybrid_component()
                .map(|(_, pk)| pk)
                .unwrap_or_else(|| kx.pub_key()),
        }
    }

    /// The classical half of a hybrid share, offered alongside it.
    pub(super) fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        match self {
            Self::Full(kx) => kx.hybrid_component(),
            Self::HybridComponent(_) => None,
        }
    }

    pub(super) fn complete(self, peer: &[u8]) -> Result<SharedSecret, Error> {
        match self {
            Self::Full(kx) => kx.complete(peer),
            Self::HybridComponent(kx) => kx.complete_hybrid_component(peer),
        }
    }
}

/// Everything needed to build (and, after a retry, rebuild) the ClientHello.
pub(super) struct ClientHelloInput {
    pub(super) config: Arc<ClientConfig>,
    pub(super) resuming: Option<Retrieved<ClientSessionValue>>,
    pub(super) random: Random,
    pub(super) sent_tls13_fake_ccs: bool,
    pub(super) hello: ClientHelloDetails,
    pub(super) session_id: SessionId,
    pub(super) server_name: ServerName<'static>,
    pub(super) alpn_protocols: Vec<Vec<u8>>,
    /// Encrypted Client Hello, while the server has not decided. With a
    /// real offer, the hello this input builds is the inner one.
    pub(super) ech: Option<ClientEch>,
    /// The GREASE values (RFC 8701) of this connection, when enabled; the
    /// same ones go into a second ClientHello.
    pub(super) grease: Option<GreaseValues>,
}

impl ClientHelloInput {
    /// RFC 9846 §4.2.2: carry the original offer across a retry.
    fn offers_transparency_info(&self, retry: bool) -> bool {
        if retry {
            self.hello
                .sent_extensions
                .contains(&ExtensionType::TransparencyInfo)
        } else {
            self.config.offers_transparency_info()
        }
    }

    /// RFC 9973 §5: repeat the offer on retry or abort. ECH rejection has
    /// already switched the comparison to the original outer ClientHello.
    fn check_cert_with_extern_psk_retry(
        &self,
        common: &mut CommonState,
        offered: bool,
    ) -> Result<(), Error> {
        if self
            .hello
            .sent_extensions
            .contains(&ExtensionType::TlsCertWithExternPsk)
            != offered
        {
            return Err(common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::CertWithExternPskChangedOnRetry,
            ));
        }
        Ok(())
    }

    /// Continues with the outer ClientHello after the server rejected ECH
    /// (RFC 9849 §6.1.6): its random, the public name (which the server
    /// certificate is checked against), its extensions, no ALPN and no
    /// resumption.
    fn switch_to_outer(&mut self, offer: &EchOffer) {
        self.random = offer.outer_random;
        self.server_name = ServerName::DnsName(offer.config.public_name().clone());
        self.hello.sent_extensions = offer.outer_sent_extensions.clone();
        self.alpn_protocols = Vec::new();
        self.resuming = None;
    }
}

/// Puts a `record_size_limit` the server announced (RFC 8449) into
/// effect. The server can only have sent one when we did (the
/// unsolicited-extension check runs first).
pub(super) fn process_record_size_limit(
    common: &mut CommonState,
    hello: &ClientHelloDetails,
    servers: Option<u16>,
    tls13: bool,
) -> Result<(), Error> {
    match (hello.sent_record_size_limit, servers) {
        (Some(ours), Some(servers)) => common.apply_record_size_limits(ours, servers, tls13),
        _ => {
            if let Some(dtls) = &mut common.dtls {
                dtls.clear_record_size_limit_observation();
            } else {
                common.record_layer.clear_record_size_limit_observation();
            }
            Ok(())
        }
    }
}

/// Checks the server's answers to our RFC 7250 certificate type offers: a
/// side we required raw public keys for must have been granted them.
///
/// An answer we never asked for is caught earlier as an unsolicited extension.
pub(super) fn process_cert_type_extensions(
    common: &mut CommonState,
    config: &ClientConfig,
    client_negotiated: Option<CertificateType>,
    server_negotiated: Option<CertificateType>,
) -> Result<(), Error> {
    for (required, negotiated) in [
        (
            config.client_auth_cert_resolver.only_raw_public_keys(),
            client_negotiated,
        ),
        (
            config.verifier.requires_raw_public_keys(),
            server_negotiated,
        ),
    ] {
        if required && negotiated != Some(CertificateType::RawPublicKey) {
            return Err(common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::IncorrectCertificateTypeExtension,
            ));
        }
    }
    Ok(())
}

/// Checks the server's ALPN choice against what we offered and records it.
pub(super) fn process_alpn_protocol(
    common: &mut CommonState,
    offered: &[Vec<u8>],
    proto: Option<&[u8]>,
) -> Result<(), Error> {
    common.alpn_protocol = proto.map(|p| p.to_vec());
    if let Some(alpn_protocol) = &common.alpn_protocol
        && !offered.contains(alpn_protocol)
    {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::SelectedUnofferedApplicationProtocol,
        ));
    }
    // RFC 7301 §3.2: the server may only select a protocol we offered, or
    // omit the extension; selecting when we offered nothing is an error.
    if common.alpn_protocol.is_some() && offered.is_empty() {
        return Err(common.send_fatal_alert(
            AlertDescription::UnsupportedExtension,
            PeerMisbehaved::UnsolicitedServerHelloExtension,
        ));
    }
    debug!(
        "ALPN protocol is {:?}",
        common
            .alpn_protocol
            .as_deref()
            .map(ProtocolName::from_bytes)
    );
    Ok(())
}

struct ExpectServerHello {
    input: ClientHelloInput,
    transcript_buffer: HandshakeHashBuffer,
    /// The PSKs our ClientHello offered, in order.
    offered_psks: Vec<OfferedPsk>,
    offered_key_share: Option<OfferedKeyShare>,
    /// The suite the HelloRetryRequest committed us to, if any.
    suite: Option<SupportedCipherSuite>,
}

impl State<ClientConnectionData> for ExpectServerHello {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        let server_hello = require_handshake_msg!(
            m,
            crate::enums::HandshakeType::ServerHello,
            HandshakePayload::ServerHello
        )?;
        trace!("We got ServerHello {:#?}", server_hello);

        let config = &self.input.config;
        let tls13_supported = config.supports_version(ProtocolVersion::TLSv1_3)
            && cx
                .common
                .dtls
                .as_ref()
                .is_none_or(|d| d.allows(ProtocolVersion::TLSv1_3));

        // RFC 9846 §4.3.1: version negotiation. A supported_versions value
        // we did not offer, or one below TLS 1.3, is illegal_parameter.
        let version = match server_hello.extensions.supported_versions {
            Some(ProtocolVersion::TLSv1_3) if tls13_supported => ProtocolVersion::TLSv1_3,
            Some(ProtocolVersion::TLSv1_2) => {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SelectedTls12UsingTls13VersionExtension,
                ));
            }
            Some(_) => {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SelectedUnofferedVersion,
                ));
            }
            None => match server_hello.legacy_version {
                ProtocolVersion::TLSv1_2 if config.supports_version(ProtocolVersion::TLSv1_2) => {
                    ProtocolVersion::TLSv1_2
                }
                ProtocolVersion::TLSv1_2 => {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::ProtocolVersion,
                        PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig,
                    ));
                }
                _ => {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::ProtocolVersion,
                        PeerIncompatible::ServerDoesNotSupportTls12Or13,
                    ));
                }
            },
        };

        // RFC 9001 §4.2: QUIC requires TLS 1.3; we offered nothing else.
        crate::quic::tls::require_tls13(cx.common, version)?;
        crate::tls13::dtls::require_enabled_version(cx.common, version)?;

        // RFC 8446 §4.2.10: a server that answers a 0-RTT offer with TLS 1.2
        // cannot have read the early data; fail rather than fall back.
        if version == ProtocolVersion::TLSv1_2
            && cx.data.early_data.is_enabled()
            && cx.common.early_traffic
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::OfferedEarlyDataWithOldProtocolVersion,
            ));
        }

        // RFC 9849 §6.1: an ECH offer (and what follows its rejection at a
        // HelloRetryRequest) offers TLS 1.3 only.
        if version == ProtocolVersion::TLSv1_2
            && self
                .input
                .ech
                .as_ref()
                .is_some_and(ClientEch::restricts_to_tls13)
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::ProtocolVersion,
                PeerMisbehaved::SelectedUnofferedVersion,
            ));
        }

        // RFC 9846 §4.2.3: a TLS 1.3 ServerHello carries legacy_version
        // 0x0303; anything else is a version error (§E.5).
        if version == ProtocolVersion::TLSv1_3
            && server_hello.legacy_version != ProtocolVersion::TLSv1_2
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::ProtocolVersion,
                PeerMisbehaved::IllegalServerHelloLegacyVersion,
            ));
        }

        // RFC 8446 §4.1.3: downgrade protection.
        if tls13_supported
            && version == ProtocolVersion::TLSv1_2
            && server_hello.has_downgrade_sentinel()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::AttemptedDowngradeToTls12WhenTls13IsSupported,
            ));
        }

        if server_hello.compression_method != Compression::Null {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SelectedUnofferedCompression,
            ));
        }

        // RFC 9846 §4.3: in TLS 1.3, a recognised extension that may not
        // appear in a ServerHello is illegal_parameter, whether or not we
        // offered it in the ClientHello.
        if version == ProtocolVersion::TLSv1_3 {
            tls13::validate_server_hello(cx.common, server_hello)?;
        }

        let received_exts = server_hello.extensions.present_types();
        if self
            .input
            .hello
            .server_sent_unsolicited_extensions(&received_exts, &[ExtensionType::RenegotiationInfo])
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerMisbehaved::UnsolicitedServerHelloExtension,
            ));
        }

        crate::dtls::cid::select_server_hello(
            cx.common,
            server_hello.extensions.connection_id.as_ref(),
        )?;

        crate::dtls::rrc_engine::select_server_hello(
            cx.common,
            server_hello.extensions.return_routability_check.is_some(),
        )?;

        let suite = config
            .find_cipher_suite(server_hello.cipher_suite)
            .ok_or_else(|| {
                // RFC 9846 §4.2.3: a cipher suite we did not offer.
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SelectedUnofferedCipherSuite,
                )
            })?;
        // RFC 9001 §5.3: on QUIC only the suites we offered, those with a
        // header protection scheme, may be selected; on DTLS only those
        // usable there (RFC 9147 §4.5.3), which we offered.
        if (cx.common.is_quic() && !suite.usable_for_quic())
            || (cx.common.is_dtls() && !suite.usable_for_dtls())
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SelectedUnofferedCipherSuite,
            ));
        }
        if suite.version().version != version {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SelectedUnusableCipherSuiteForVersion,
            ));
        }
        if let Some(prev) = self.suite
            && prev != suite
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SelectedDifferentCipherSuiteAfterRetry,
            ));
        }

        // External PSKs exist only in TLS 1.3.
        if config.require_external_psk && version != ProtocolVersion::TLSv1_3 {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::ExternalPskRequired,
            ));
        }

        debug!("Using ciphersuite {:?}", suite.suite());
        cx.common.negotiated_version = Some(version);
        cx.common.suite = Some(suite);
        if cx.common.handshake_kind.is_none() {
            cx.common.handshake_kind = Some(HandshakeKind::Full);
        }

        // RFC 9849 §6.1.4: the ServerHello's random says whether the server
        // took the inner hello; if not, the handshake continues with the
        // outer one.
        match self.input.ech.take() {
            Some(ClientEch::Offer(offer)) => {
                let accepted = match suite {
                    SupportedCipherSuite::Tls13(suite) => ech::client::server_hello_accepts(
                        &self.transcript_buffer,
                        suite,
                        &self.input.random,
                        handshake_bytes(&m),
                    ),
                    #[cfg(feature = "tls12")]
                    SupportedCipherSuite::Tls12(_) => false,
                };
                if accepted {
                    cx.data.ech_status = EchStatus::Accepted;
                } else if offer.accepted_at_retry {
                    // §6.1.5: the HelloRetryRequest confirmed acceptance.
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::EchAcceptanceVariedAfterRetry,
                    ));
                } else {
                    debug!("Server rejected ECH");
                    cx.data.ech_status = EchStatus::Rejected;
                    self.input.switch_to_outer(&offer);
                    self.transcript_buffer = offer.outer_transcript;
                    self.offered_psks.clear();
                }
            }
            other => self.input.ech = other,
        }

        #[cfg(feature = "tls12")]
        if version == ProtocolVersion::TLSv1_2
            && let Some(dtls) = &mut cx.common.dtls
        {
            dtls.select_version(version);
            self.transcript_buffer = self.transcript_buffer.for_dtls12(dtls.outgoing_hello_seq());
        }
        let mut transcript = self.transcript_buffer.start_hash(suite.hash_provider());
        #[cfg(feature = "tls12")]
        if version == ProtocolVersion::TLSv1_2 && cx.common.is_dtls() {
            let seq = cx.common.dtls.as_ref().map_or(0, |d| d.received_seq);
            transcript.add(&crate::dtls::canonical12(handshake_bytes(&m), seq));
        } else {
            transcript.add_message(&m);
        }
        #[cfg(not(feature = "tls12"))]
        transcript.add_message(&m);

        let randoms = ConnectionRandoms::new(self.input.random, server_hello.random);

        match suite {
            SupportedCipherSuite::Tls13(suite) => {
                // RFC 9147 section 5: DTLS 1.3 never echoes an old ID.
                let expected_id = if cx.common.is_dtls() {
                    SessionId::empty()
                } else {
                    self.input.session_id
                };
                if server_hello.session_id != expected_id {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::ServerEchoedCompatibilitySessionId,
                    ));
                }
                let resuming = match self.input.resuming.take().map(|r| r.value) {
                    Some(ClientSessionValue::Tls13(inner)) => Some(inner),
                    _ => None,
                };
                let our_key_share = self.offered_key_share.take().ok_or_else(|| {
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::MissingKeyShare,
                    )
                })?;
                tls13::handle_server_hello(
                    self.input.config.clone(),
                    cx,
                    server_hello,
                    resuming,
                    self.input.server_name,
                    randoms,
                    suite,
                    transcript,
                    self.offered_psks,
                    self.input.hello,
                    our_key_share,
                    self.input.sent_tls13_fake_ccs,
                    self.input.alpn_protocols,
                )
            }
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(suite) => {
                let resuming = self.input.resuming.take().and_then(|r| match r.value {
                    ClientSessionValue::Tls12(inner) => Some(inner),
                    ClientSessionValue::Tls13(_) => None,
                });
                tls12::CompleteServerHelloHandling {
                    config: self.input.config.clone(),
                    resuming_session: resuming,
                    server_name: self.input.server_name,
                    randoms,
                    using_ems: server_hello.extensions.extended_master_secret.is_some(),
                    using_etm: server_hello.extensions.encrypt_then_mac.is_some(),
                    transcript,
                    hello: self.input.hello,
                    alpn_protocols: self.input.alpn_protocols,
                }
                .handle_server_hello(cx, suite, server_hello, tls13_supported)
            }
        }
    }
}

struct ExpectServerHelloOrHelloRetryRequest {
    next: ExpectServerHello,
}

impl ExpectServerHelloOrHelloRetryRequest {
    fn handle_hello_retry_request(
        mut self,
        cx: &mut ClientContext<'_>,
        m: Message<'_>,
    ) -> NextStateOrError {
        let hrr = require_handshake_msg!(
            m,
            crate::enums::HandshakeType::HelloRetryRequest,
            HandshakePayload::HelloRetryRequest
        )?;
        trace!("Got HRR {:?}", hrr);

        let config = &self.next.input.config;

        // RFC 9846 §4.3: a recognised extension that may not appear in a
        // HelloRetryRequest is illegal_parameter; any other extension we
        // did not offer is unsupported_extension (§4.2.4).
        if first_disallowed(
            hrr.extensions.unknown.iter().copied(),
            Tls13Message::HelloRetryRequest,
        )
        .is_some()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::DisallowedHelloRetryRequestExtension,
            ));
        }
        if !hrr.extensions.unknown.is_empty() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerIncompatible::ServerSentHelloRetryRequestWithUnknownExtension,
            ));
        }
        if hrr.extensions.key_share.is_none() && hrr.extensions.cookie.is_none() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::IllegalHelloRetryRequestWithNoChanges,
            ));
        }
        // RFC 9846 §4.2.4: a HelloRetryRequest selects TLS 1.3 through
        // supported_versions (illegal_parameter otherwise, §4.3.1) and
        // carries legacy_version 0x0303 (protocol_version otherwise, §E.5).
        if hrr.extensions.supported_versions != Some(ProtocolVersion::TLSv1_3) {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::IllegalHelloRetryRequestWithUnsupportedVersion,
            ));
        }
        if hrr.legacy_version != ProtocolVersion::TLSv1_2 {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::ProtocolVersion,
                PeerMisbehaved::IllegalServerHelloLegacyVersion,
            ));
        }
        let expected_id = if cx.common.is_dtls() {
            SessionId::empty()
        } else {
            self.next.input.session_id
        };
        if hrr.session_id != expected_id {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::IllegalHelloRetryRequestWithWrongSessionId,
            ));
        }
        if hrr.compression_method != Compression::Null {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SelectedUnofferedCompression,
            ));
        }

        let suite = match config.find_cipher_suite(hrr.cipher_suite) {
            Some(suite @ SupportedCipherSuite::Tls13(_))
                if !cx.common.is_dtls() || suite.usable_for_dtls() =>
            {
                suite
            }
            _ => {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedCipherSuite,
                ));
            }
        };

        let key_share = match hrr.extensions.key_share {
            Some(group) => {
                let Some(kx_group) = config.find_kx_group(group, ProtocolVersion::TLSv1_3) else {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedNamedGroup,
                    ));
                };
                // RFC 8446 §4.1.4: the server must not ask for a group we
                // already offered a share for, including the classical half
                // of a hybrid share that went out alongside it.
                if let Some(offered) = self.next.offered_key_share.take() {
                    let offered_component = offered
                        .hybrid_component()
                        .map(|(g, _)| g)
                        .filter(|g| config.find_kx_group(*g, ProtocolVersion::TLSv1_3).is_some());
                    if offered.group() == group || offered_component == Some(group) {
                        return Err(cx.common.send_fatal_alert(
                            AlertDescription::IllegalParameter,
                            PeerMisbehaved::IllegalHelloRetryRequestWithOfferedGroup,
                        ));
                    }
                }
                cx.common.kx_state = KxState::Started(kx_group);
                OfferedKeyShare::Full(kx_group.start()?)
            }
            None => self.next.offered_key_share.take().ok_or_else(|| {
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::MissingKeyShare,
                )
            })?,
        };

        cx.common.handshake_kind = Some(HandshakeKind::FullWithHelloRetryRequest);

        // RFC 8446 §4.4.1: the first ClientHello is replaced in the
        // transcript by a message_hash, then the HelloRetryRequest follows.
        let transcript = self
            .next
            .transcript_buffer
            .start_hash(suite.hash_provider());
        let mut transcript_buffer = transcript.into_hrr_buffer();

        // RFC 9849 §6.1.4: an ECH extension in the HelloRetryRequest
        // confirms (or, not matching, rejects) our offer. A GREASE offer
        // ignores it; without an offer it is unsolicited.
        match self.next.input.ech.take() {
            Some(ClientEch::Offer(mut offer)) => {
                let accepted = match suite {
                    SupportedCipherSuite::Tls13(suite) => {
                        hrr.extensions.encrypted_client_hello.is_some()
                            && ech::client::retry_request_accepts(
                                &transcript_buffer,
                                suite,
                                &self.next.input.random,
                                handshake_bytes(&m),
                            )
                    }
                    #[cfg(feature = "tls12")]
                    SupportedCipherSuite::Tls12(_) => false,
                };
                if accepted {
                    offer.accepted_at_retry = true;
                    self.next.input.ech = Some(ClientEch::Offer(offer));
                } else {
                    debug!("Server rejected ECH in HelloRetryRequest");
                    cx.data.ech_status = EchStatus::Rejected;
                    self.next.input.switch_to_outer(&offer);
                    transcript_buffer = offer
                        .outer_transcript
                        .start_hash(suite.hash_provider())
                        .into_hrr_buffer();
                    self.next.input.ech = Some(ClientEch::RejectedAtRetry {
                        outer_ext: offer.first_outer_ext.clone(),
                        public_name: offer.config.public_name().clone(),
                    });
                }
            }
            None if hrr.extensions.encrypted_client_hello.is_some() => {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::UnsupportedExtension,
                    PeerMisbehaved::UnsolicitedEchExtension,
                ));
            }
            other => self.next.input.ech = other,
        }
        transcript_buffer.add_message(&m);

        // RFC 8446 §4.2.10: early data is not possible after a
        // HelloRetryRequest.
        if cx.data.early_data.is_enabled() {
            cx.data.early_data.rejected();
        }
        cx.common.early_traffic = false;
        if let Some(quic) = cx.common.quic.as_mut() {
            quic.clear_early_secret();
        }
        cx.common.early_exporter = None;

        // The retry must repeat the PSK offer (with a new binder) or drop it;
        // our session is still held in `input.resuming` for that.
        emit_client_hello_for_retry(
            transcript_buffer,
            Some(hrr),
            Some(key_share),
            Some(suite),
            self.next.input,
            cx,
        )
    }
}

impl State<ClientConnectionData> for ExpectServerHelloOrHelloRetryRequest {
    #[cfg_attr(not(feature = "tls12"), allow(unused_mut))]
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        #[cfg(feature = "tls12")]
        if let MessagePayload::Handshake {
            parsed:
                HandshakeMessagePayload(HandshakePayload::Unknown((
                    crate::enums::HandshakeType::HelloVerifyRequest,
                    body,
                ))),
            ..
        } = &m.payload
        {
            self.next.transcript_buffer = crate::dtls::retry_client_hello(cx.common, body.bytes())?;
            // The repeated hello still offers its DTLS 1.2 session.
            // TLS 1.3 binders, however, do not survive a legacy retry.
            if matches!(
                self.next.input.resuming.as_ref().map(|r| &r.value),
                Some(ClientSessionValue::Tls13(_))
            ) {
                self.next.input.resuming = None;
            }
            self.next.offered_psks.clear();
            return Ok(Box::new(self.next));
        }
        match &m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ServerHello(..)),
                ..
            } => Box::new(self.next).handle(cx, m),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::HelloRetryRequest(..)),
                ..
            } => self.handle_hello_retry_request(cx, m),
            payload => Err(crate::check::inappropriate_handshake_message(
                payload,
                &[crate::enums::ContentType::Handshake],
                &[
                    crate::enums::HandshakeType::ServerHello,
                    crate::enums::HandshakeType::HelloRetryRequest,
                ],
            )),
        }
    }
}

/// The encoding of a handshake message, header included.
fn handshake_bytes<'a>(m: &'a Message<'_>) -> &'a [u8] {
    match &m.payload {
        MessagePayload::Handshake { encoded, .. } => encoded.bytes(),
        _ => &[],
    }
}

impl ProtocolName {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        Self::from(bytes.to_vec())
    }
}
