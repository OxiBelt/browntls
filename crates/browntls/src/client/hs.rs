//! The client handshake up to version negotiation: ClientHello, ServerHello
//! and HelloRetryRequest.

use alloc::boxed::Box;
use alloc::vec;
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
use crate::enums::{AlertDescription, CipherSuite, ProtocolVersion};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHashBuffer;
use crate::log::{debug, trace};
use crate::msgs::enums::{
    Compression, ECPointFormat, ExtensionType, NamedGroup, PskKeyExchangeMode,
};
#[cfg(feature = "tls12")]
use crate::msgs::handshake::ClientSessionTicket;
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientExtensions, ClientHelloPayload, HandshakeMessagePayload,
    HandshakePayload, HelloRetryRequest, KeyShareEntry, PresharedKeyIdentity, PresharedKeyOffer,
    ProtocolName, Random, ServerNamePayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist::{self, Retrieved};
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;
use crate::tls13::key_schedule::KeyScheduleEarly;

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

/// Looks up and validates a session to offer for `server_name`.
fn find_session(
    server_name: &ServerName<'static>,
    config: &ClientConfig,
    cx: &mut ClientContext<'_>,
) -> Option<Retrieved<ClientSessionValue>> {
    let now = config.current_time().ok()?;
    let _ = &cx;

    let found = config
        .resumption
        .store
        .take_tls13_ticket(server_name)
        .map(ClientSessionValue::Tls13)
        .or_else(|| {
            #[cfg(feature = "tls12")]
            {
                if config.resumption.tls12_resumption == super::Tls12Resumption::Disabled {
                    return None;
                }
                config
                    .resumption
                    .store
                    .tls12_session(server_name)
                    .map(ClientSessionValue::Tls12)
            }
            #[cfg(not(feature = "tls12"))]
            {
                None
            }
        })
        .map(|value| Retrieved::new(value, now))?;

    if found.has_expired() {
        debug!("Not resuming expired session");
        return None;
    }

    let usable = match &found.value {
        ClientSessionValue::Tls13(inner) => {
            config.supports_version(ProtocolVersion::TLSv1_3)
                && config
                    .find_cipher_suite(inner.suite().common.suite)
                    .is_some()
        }
        #[cfg(feature = "tls12")]
        ClientSessionValue::Tls12(inner) => {
            config.supports_version(ProtocolVersion::TLSv1_2)
                && config
                    .find_cipher_suite(inner.suite().common.suite)
                    .is_some()
                && (!config.require_ems || inner.extended_ms())
        }
    };
    if !usable {
        debug!("Not resuming session: incompatible with configuration");
        return None;
    }
    Some(found)
}

/// Picks the group for the initial key share: the one the server accepted
/// last time, or the provider's first TLS 1.3-capable group.
fn initial_key_share(
    config: &ClientConfig,
    server_name: &ServerName<'static>,
    kx_state: &mut KxState,
) -> Result<Box<dyn ActiveKeyExchange>, Error> {
    let group = config
        .resumption
        .store
        .kx_hint(server_name)
        .and_then(|hint| config.find_kx_group(hint, ProtocolVersion::TLSv1_3))
        .or_else(|| {
            config
                .provider
                .kx_groups
                .iter()
                .copied()
                .find(|g| g.usable_for_version(ProtocolVersion::TLSv1_3))
        })
        .ok_or_else(|| Error::general("no key exchange group is usable for TLS 1.3"))?;
    *kx_state = KxState::Started(group);
    group.start()
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
}

/// Builds and sends the first ClientHello.
pub(super) fn start_handshake(
    server_name: ServerName<'static>,
    alpn_protocols: Vec<Vec<u8>>,
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
) -> NextStateOrError {
    let mut transcript_buffer = HandshakeHashBuffer::new();
    if config.client_auth_cert_resolver.has_certs() {
        transcript_buffer.set_client_auth_enabled();
    }

    let supports_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);
    #[cfg_attr(not(feature = "tls12"), allow(unused_mut))]
    let mut resuming = find_session(&server_name, &config, cx);

    let key_share = if supports_tls13 {
        Some(initial_key_share(
            &config,
            &server_name,
            &mut cx.common.kx_state,
        )?)
    } else {
        None
    };

    let session_id = match &resuming {
        #[cfg(feature = "tls12")]
        Some(Retrieved {
            value: ClientSessionValue::Tls12(inner),
            ..
        }) if !inner.session_id.is_empty() => inner.session_id,
        // RFC 8446 §4.1.2: a non-empty legacy_session_id helps middleboxes;
        // for TLS 1.2 ticket resumption a random ID lets us detect acceptance.
        _ if supports_tls13 || resuming.is_some() => {
            SessionId::random(config.provider.secure_random)?
        }
        _ => SessionId::empty(),
    };

    // For TLS 1.2 ticket resumption the stored session has no ID of its own:
    // remember the random one we send, so the server echoing it back tells us
    // the ticket was accepted (RFC 5077 §3.4).
    #[cfg(feature = "tls12")]
    if let Some(Retrieved {
        value: ClientSessionValue::Tls12(inner),
        ..
    }) = &mut resuming
        && inner.session_id.is_empty()
    {
        inner.session_id = session_id;
    }

    let random = Random::new(config.provider.secure_random)?;
    let input = ClientHelloInput {
        config,
        resuming,
        random,
        sent_tls13_fake_ccs: false,
        hello: ClientHelloDetails::new(),
        session_id,
        server_name,
        alpn_protocols,
    };
    emit_client_hello_for_retry(
        transcript_buffer,
        None,
        key_share.map(OfferedKeyShare::Full),
        None,
        input,
        cx,
    )
}

/// Builds and sends a ClientHello (the first, or the answer to a HelloRetryRequest).
///
/// `committed_suite` is the suite a HelloRetryRequest fixed, which the
/// ServerHello must then repeat.
fn emit_client_hello_for_retry(
    mut transcript_buffer: HandshakeHashBuffer,
    retryreq: Option<&HelloRetryRequest>,
    key_share: Option<OfferedKeyShare>,
    committed_suite: Option<SupportedCipherSuite>,
    mut input: ClientHelloInput,
    cx: &mut ClientContext<'_>,
) -> NextStateOrError {
    let config = &input.config;
    let supports_tls13 = config.supports_version(ProtocolVersion::TLSv1_3);
    let supports_tls12 = config.supports_version(ProtocolVersion::TLSv1_2);

    let supported_versions: Vec<ProtocolVersion> =
        [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2]
            .into_iter()
            .filter(|v| config.supports_version(*v))
            .collect();

    let server_name = match (&input.server_name, config.enable_sni) {
        (ServerName::DnsName(dns), true) => Some(ServerNamePayload::SingleDnsName(dns.to_owned())),
        _ => None,
    };

    let offered_sigschemes = config.verifier().supported_verify_schemes();

    let mut exts = ClientExtensions {
        server_name,
        named_groups: Some(config.provider.kx_groups.iter().map(|g| g.name()).collect()),
        ec_point_formats: supports_tls12.then(|| vec![ECPointFormat::Uncompressed]),
        signature_schemes: Some(offered_sigschemes.clone()),
        protocols: (!input.alpn_protocols.is_empty()).then(|| {
            input
                .alpn_protocols
                .iter()
                .cloned()
                .map(ProtocolName::from)
                .collect()
        }),
        certificate_status_request: Some(CertificateStatusRequest::build_ocsp()),
        extended_master_secret: supports_tls12.then_some(()),
        supported_versions: Some(supported_versions),
        psk_modes: supports_tls13.then(|| vec![PskKeyExchangeMode::PSK_DHE_KE]),
        key_shares: key_share.as_ref().map(|ks| {
            let mut shares = vec![KeyShareEntry::new(ks.group(), ks.pub_key())];
            // For the first ClientHello (or a HelloRetryRequest that names no
            // group) a hybrid share's classical half is offered too, for
            // free, when the provider also supports that group on its own.
            let hrr_named_group = retryreq.is_some_and(|rr| rr.extensions.key_share.is_some());
            if !hrr_named_group
                && let Some((component_group, component_share)) = ks.hybrid_component()
                && config
                    .find_kx_group(component_group, ProtocolVersion::TLSv1_3)
                    .is_some()
            {
                shares.push(KeyShareEntry::new(component_group, component_share));
            }
            shares
        }),
        cookie: retryreq.and_then(|r| r.extensions.cookie.clone()),
        certificate_compression: (supports_tls13 && !config.cert_decompressors.is_empty()).then(
            || {
                config
                    .cert_decompressors
                    .iter()
                    .map(|d| d.algorithm())
                    .collect()
            },
        ),
        ..Default::default()
    };

    #[cfg(feature = "tls12")]
    if supports_tls12
        && config.resumption.tls12_resumption == super::Tls12Resumption::SessionIdOrTickets
    {
        exts.session_ticket = Some(match &input.resuming {
            Some(Retrieved {
                value: ClientSessionValue::Tls12(inner),
                ..
            }) if !inner.ticket().is_empty() => {
                ClientSessionTicket::Offer(crate::msgs::base::Payload::new(inner.ticket().to_vec()))
            }
            _ => ClientSessionTicket::Request,
        });
    }

    // RFC 8446 §4.2.11: offer the TLS 1.3 session as a PSK, binder filled in below.
    let tls13_session = match &input.resuming {
        Some(retrieved) if supports_tls13 => retrieved.map(|v| match v {
            ClientSessionValue::Tls13(inner) => Some(inner),
            #[cfg(feature = "tls12")]
            _ => None,
        }),
        _ => None,
    };
    if let Some(resuming) = &tls13_session {
        // RFC 8446 §4.2.10: offer 0-RTT when the ticket and configuration
        // allow it, but never in the second ClientHello of a retry.
        let max_early_data_size = resuming.max_early_data_size();
        if config.enable_early_data && max_early_data_size > 0 && retryreq.is_none() {
            cx.data.early_data.enable(max_early_data_size as usize);
            exts.early_data = Some(());
        }

        let obfuscated_ticket_age = resuming.obfuscated_ticket_age();
        let binder_len = resuming.suite().common.hash_provider.output_len();
        exts.preshared_key = Some(PresharedKeyOffer::new(
            PresharedKeyIdentity::new(resuming.ticket().to_vec(), obfuscated_ticket_age),
            vec![0u8; binder_len],
        ));
    }

    let mut cipher_suites: Vec<CipherSuite> = config
        .provider
        .cipher_suites
        .iter()
        .filter(|cs| config.supports_version(cs.version().version))
        .map(|cs| cs.suite())
        .collect();
    // RFC 5746 §3.3: signal secure renegotiation support (we never renegotiate).
    cipher_suites.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);

    input.hello.sent_extensions = exts.present_types();
    input.hello.offered_sigschemes = offered_sigschemes;

    let chp = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: input.random,
        session_id: input.session_id,
        cipher_suites,
        compression_methods: vec![Compression::Null],
        extensions: exts,
    };
    let mut hmp = HandshakeMessagePayload(HandshakePayload::ClientHello(chp));

    let resuming_hash_provider = tls13_session
        .as_ref()
        .map(|resuming| resuming.suite().common.hash_provider);
    let early_key_schedule = tls13_session
        .map(|resuming| tls13::fill_in_psk_binder(&resuming, &transcript_buffer, &mut hmp));

    let ch = Message {
        // RFC 8446 §5.1: the first ClientHello's record may use the lowest
        // legacy version for compatibility; later records use TLS 1.2.
        version: if retryreq.is_some() {
            ProtocolVersion::TLSv1_2
        } else {
            ProtocolVersion::TLSv1_0
        },
        payload: MessagePayload::handshake(hmp),
    };

    trace!("Sending ClientHello {:#?}", ch);
    transcript_buffer.add_message(&ch);
    cx.common.send_msg(ch, false);

    // With 0-RTT offered, the early traffic key derives from the ClientHello
    // alone, so early data can go out right behind it.
    if let (Some(schedule), Some(hash_provider)) = (&early_key_schedule, resuming_hash_provider)
        && cx.data.early_data.is_enabled()
    {
        tls13::derive_early_traffic_secret(
            &*config.key_log,
            cx,
            hash_provider,
            schedule,
            &mut input.sent_tls13_fake_ccs,
            &transcript_buffer,
            &input.random.0,
        );
    }

    let next = ExpectServerHello {
        input,
        transcript_buffer,
        early_key_schedule,
        offered_key_share: key_share,
        suite: committed_suite,
    };

    Ok(if retryreq.is_some() {
        Box::new(next)
    } else {
        Box::new(ExpectServerHelloOrHelloRetryRequest { next })
    })
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
    early_key_schedule: Option<KeyScheduleEarly>,
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
        let tls13_supported = config.supports_version(ProtocolVersion::TLSv1_3);

        // RFC 8446 §4.2.1: version negotiation.
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
                    AlertDescription::ProtocolVersion,
                    PeerIncompatible::ServerDoesNotSupportTls12Or13,
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

        if version == ProtocolVersion::TLSv1_3
            && server_hello.legacy_version != ProtocolVersion::TLSv1_2
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::IllegalHelloRetryRequestWithUnsupportedVersion,
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

        let suite = config
            .find_cipher_suite(server_hello.cipher_suite)
            .ok_or_else(|| {
                cx.common.send_fatal_alert(
                    AlertDescription::HandshakeFailure,
                    PeerMisbehaved::SelectedUnofferedCipherSuite,
                )
            })?;
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

        debug!("Using ciphersuite {:?}", suite.suite());
        cx.common.negotiated_version = Some(version);
        cx.common.suite = Some(suite);
        if cx.common.handshake_kind.is_none() {
            cx.common.handshake_kind = Some(HandshakeKind::Full);
        }

        let mut transcript = self.transcript_buffer.start_hash(suite.hash_provider());
        transcript.add_message(&m);

        let randoms = ConnectionRandoms::new(self.input.random, server_hello.random);

        match suite {
            SupportedCipherSuite::Tls13(suite) => {
                // RFC 8446 §4.1.3: the session ID must be echoed exactly.
                if server_hello.session_id != self.input.session_id {
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
                    self.early_key_schedule,
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

        // RFC 8446 §4.1.4: a HelloRetryRequest may only carry extensions we
        // would understand in a ServerHello.
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
        if hrr.extensions.supported_versions != Some(ProtocolVersion::TLSv1_3)
            || hrr.legacy_version != ProtocolVersion::TLSv1_2
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::IllegalHelloRetryRequestWithUnsupportedVersion,
            ));
        }
        if hrr.session_id != self.next.input.session_id {
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
            Some(suite @ SupportedCipherSuite::Tls13(_)) => suite,
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
        transcript_buffer.add_message(&m);

        // RFC 8446 §4.2.10: early data is not possible after a HelloRetryRequest.
        if cx.data.early_data.is_enabled() {
            cx.data.early_data.rejected();
        }
        cx.common.early_traffic = false;

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
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
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

impl ProtocolName {
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        Self::from(bytes.to_vec())
    }
}
