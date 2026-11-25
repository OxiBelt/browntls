//! Building and sending the ClientHello: the first one, and the answer to a
//! HelloRetryRequest.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use browntls_pki::ServerName;

use super::super::common::ClientHelloDetails;
use super::super::{ClientConfig, ClientHelloPadding, ClientSessionStore, tls13};
use super::{
    ClientContext, ClientHelloInput, ClientSessionValue, ExpectServerHello,
    ExpectServerHelloOrHelloRetryRequest, NextStateOrError, OfferedKeyShare,
};
use crate::common_state::KxState;
use crate::crypto::ActiveKeyExchange;
use crate::ech::client::{ClientEch, OfferKeyLogRecords};
use crate::enums::{CertificateType, CipherSuite, ProtocolVersion, SignatureScheme};
use crate::error::Error;
use crate::hash_hs::HandshakeHashBuffer;
use crate::log::{debug, trace};
use crate::msgs::base::PayloadU8;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{Compression, ECPointFormat, NamedGroup, PskKeyExchangeMode};
use crate::msgs::grease::GreaseValues;
#[cfg(feature = "tls12")]
use crate::msgs::handshake::ClientSessionTicket;
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientExtensions, ClientHelloPayload, ClientTicketRequest,
    HandshakeMessagePayload, HandshakePayload, HelloRetryRequest, KeyShareEntry,
    MAX_HANDSHAKE_SIZE, PresharedKeyBinder, PresharedKeyIdentity, PresharedKeyOffer, ProtocolName,
    Random, ServerNamePayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist::{Retrieved, Tls13ClientSessionValue};
use crate::psk::{OfferedPsk, PskSecret};
use crate::suites::SupportedCipherSuite;
use crate::sync::Arc;
use crate::tls13::key_schedule::{BinderLabel, Protocol};

/// Looks up and validates a session to offer for `server_name`.
fn find_session(
    server_name: &ServerName<'static>,
    config: &ClientConfig,
    cx: &mut ClientContext<'_>,
) -> Option<Retrieved<ClientSessionValue>> {
    // RFC 8844 §5: a bound connection uses nothing from another one.
    if config.external_binding.is_some() {
        return None;
    }
    let now = config.current_time().ok()?;
    // RFC 9001 §4.2: QUIC uses TLS 1.3 only, so only its tickets resume;
    // so does DTLS 1.3, with its own tickets.
    let tls13_only = cx.common.is_quic()
        || cx
            .common
            .dtls
            .as_ref()
            .is_some_and(|d| !d.allows(ProtocolVersion::TLSv1_2));
    // RFC 9849 §6.1: an ECH offer is TLS 1.3 only and may not resume a
    // TLS 1.2 session. Such a session is not even looked up: its session
    // ID went out in the clear next to the hidden server name, so any use
    // of it in the outer ClientHello would link the two connections.
    #[cfg(feature = "tls12")]
    let ech_offer = matches!(config.ech_mode, Some(crate::ech::EchMode::Enable(_)));

    let found = (if cx
        .common
        .dtls
        .as_ref()
        .is_none_or(|d| d.allows(ProtocolVersion::TLSv1_3))
    {
        take_tls13_ticket(
            &*config.resumption.store,
            server_name,
            Protocol::of(cx.common),
        )
    } else {
        None
    })
    .filter(|ticket| {
        !config.revocation_enabled()
            || (ticket.server_cert_chain().0.is_empty() && ticket.external_psk().is_some())
    })
    .map(ClientSessionValue::Tls13)
    .or_else(|| {
        #[cfg(feature = "tls12")]
        {
            if tls13_only
                || ech_offer
                || config.revocation_enabled()
                || config.resumption.tls12_resumption == super::super::Tls12Resumption::Disabled
            {
                return None;
            }
            let store = &config.resumption.store;
            let (session, version) = if cx.common.is_dtls() {
                (store.dtls12_session(server_name), ProtocolVersion::DTLSv1_2)
            } else {
                (store.tls12_session(server_name), ProtocolVersion::TLSv1_2)
            };
            session
                .filter(|s| s.protocol_version() == version)
                .map(ClientSessionValue::Tls12)
        }
        #[cfg(not(feature = "tls12"))]
        {
            let _ = tls13_only;
            None
        }
    })
    .map(|value| Retrieved::new(value, now))?;

    if found.has_expired() {
        debug!("Not resuming expired session");
        return None;
    }

    let session = match &found.value {
        ClientSessionValue::Tls13(inner) => &inner.common,
        #[cfg(feature = "tls12")]
        ClientSessionValue::Tls12(inner) => &inner.common,
    };
    if !session.compatible_config(&config.session_binding())
        || !session.compatible_server_identity(server_name, cx.data.service_identity.as_deref())
    {
        debug!("Not resuming session: authentication policy differs");
        return None;
    }

    // A session authenticated with a delegated credential (RFC 9345) keeps
    // that authentication; only a configuration that accepts delegated
    // credentials may resume it.
    if matches!(
        &found.value,
        ClientSessionValue::Tls13(inner)
            if inner.delegated_credential_expiry().is_some() && !config.enable_delegated_credentials
    ) {
        debug!("Not resuming delegated-credential session: delegated credentials are disabled");
        return None;
    }

    if matches!(
        &found.value,
        ClientSessionValue::Tls13(inner) if inner.delegated_credential_expired_at(now)
    ) {
        debug!("Not resuming session authenticated by an expired delegated credential");
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
                && (!(config.require_ems || cx.common.is_dtls()) || inner.extended_ms())
                && (!cx.common.is_dtls()
                    || SupportedCipherSuite::from(inner.suite()).usable_for_dtls())
        }
    };
    if !usable {
        debug!("Not resuming session: incompatible with configuration");
        return None;
    }
    Some(found)
}

/// How many tickets of the other protocol [`take_tls13_ticket`] passes
/// over before giving up.
const MAX_SKIPPED_TICKETS: usize = 8;

/// Takes the newest TLS 1.3 ticket for `server_name` that was issued over
/// `protocol`.
///
/// TLS and DTLS connections may share a store, but a ticket is only offered
/// over the protocol it came from: its binder would take the other label
/// prefix (RFC 9147 §5.9) and fail the handshake. Tickets of the other
/// protocol taken on the way, up to [`MAX_SKIPPED_TICKETS`], are put back
/// in their order for later connections of their own.
fn take_tls13_ticket(
    store: &dyn ClientSessionStore,
    server_name: &ServerName<'static>,
    protocol: Protocol,
) -> Option<Tls13ClientSessionValue> {
    let mut skipped = Vec::new();
    let mut found = None;
    while skipped.len() < MAX_SKIPPED_TICKETS {
        let Some(ticket) = store.take_tls13_ticket(server_name) else {
            break;
        };
        if ticket.protocol() == protocol {
            found = Some(ticket);
            break;
        }
        skipped.push(ticket);
    }
    // The newest was taken first, so it goes back last.
    for ticket in skipped.into_iter().rev() {
        store.insert_tls13_ticket(server_name.clone(), ticket);
    }
    found
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

/// Builds and sends the first ClientHello.
pub(in crate::client) fn start_handshake(
    server_name: ServerName<'static>,
    alpn_protocols: Vec<Vec<u8>>,
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
) -> NextStateOrError {
    let mut transcript_buffer = HandshakeHashBuffer::new();
    if config.client_auth_cert_resolver.has_certs() {
        transcript_buffer.set_client_auth_enabled();
    }

    let supports_tls13 = config.supports_version(ProtocolVersion::TLSv1_3)
        && cx
            .common
            .dtls
            .as_ref()
            .is_none_or(|d| d.allows(ProtocolVersion::TLSv1_3));
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
        // RFC 9001 §8.4: a QUIC client MUST NOT request the middlebox
        // compatibility mode, so its legacy_session_id is empty. Nor has
        // DTLS 1.3 that mode (RFC 9147 §5, §5.3). With no ID, DTLS
        // ticket resumption is distinguished by the next server message.
        _ if cx.common.is_quic()
            || (cx.common.is_dtls() && (supports_tls13 || resuming.is_none())) =>
        {
            SessionId::empty()
        }
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

    // RFC 9849 §6.1: an ECH offer needs TLS 1.3. `find_session` already
    // left out TLS 1.2 sessions, before the session ID above was chosen.
    let mut ech_records = OfferKeyLogRecords::new();
    let ech = ClientEch::start(
        config.ech_mode.as_ref(),
        supports_tls13,
        config.provider.secure_random,
        config.client_auth_cert_resolver.has_certs(),
        &*config.key_log,
        &mut ech_records,
    )?;
    #[cfg(feature = "tls12")]
    debug_assert!(
        !(ech.as_ref().is_some_and(ClientEch::restricts_to_tls13)
            && matches!(&resuming, Some(r) if matches!(r.value, ClientSessionValue::Tls12(_))))
    );
    if let Some(ech) = &ech {
        cx.data.ech_status = ech.initial_status();
    }

    let random = Random::new(config.provider.secure_random)?;
    let grease = if config.enable_grease {
        Some(GreaseValues::random(config.provider.secure_random)?)
    } else {
        None
    };
    let input = ClientHelloInput {
        config,
        resuming,
        random,
        sent_tls13_fake_ccs: false,
        hello: ClientHelloDetails::new(),
        session_id,
        server_name,
        alpn_protocols,
        ech,
        grease,
    };
    // RFC 9850 §2.3: the ECH records are for a client that offered ECH, so
    // they wait until the ClientHello with the offer is on its way. The
    // KEM secret stays in this function's `ech_records` meanwhile.
    #[cfg(feature = "key-log")]
    let ech_key_log = ech_records.is_pending().then(|| Arc::clone(&input.config));
    let next = emit_client_hello_for_retry(
        transcript_buffer,
        None,
        key_share.map(OfferedKeyShare::Full),
        None,
        input,
        cx,
    )?;
    #[cfg(feature = "key-log")]
    if let Some(config) = &ech_key_log {
        ech_records.emit(&*config.key_log, config.ech_mode.as_ref());
    }
    Ok(next)
}

/// Builds and sends a ClientHello (the first, or the answer to a
/// HelloRetryRequest).
///
/// `committed_suite` is the suite a HelloRetryRequest fixed, which the
/// ServerHello must then repeat.
pub(super) fn emit_client_hello_for_retry(
    mut transcript_buffer: HandshakeHashBuffer,
    retryreq: Option<&HelloRetryRequest>,
    mut key_share: Option<OfferedKeyShare>,
    committed_suite: Option<SupportedCipherSuite>,
    mut input: ClientHelloInput,
    cx: &mut ClientContext<'_>,
) -> NextStateOrError {
    let config = &input.config;
    // RFC 9001 §4.2: a QUIC client MUST NOT offer TLS versions older than 1.3.
    let quic = cx.common.is_quic();
    // Endpoint version policy is independent of the shared TLS config.
    // No middlebox compatibility, 0-RTT, record size limit extension or
    // post-handshake authentication over DTLS.
    let dtls = cx.common.is_dtls();
    let supports_tls13 = config.supports_version(ProtocolVersion::TLSv1_3)
        && cx
            .common
            .dtls
            .as_ref()
            .is_none_or(|d| d.allows(ProtocolVersion::TLSv1_3));
    // RFC 9849 §6.1: with ECH, both ClientHellos offer TLS 1.3 only.
    let ech_tls13_only = input
        .ech
        .as_ref()
        .is_some_and(ClientEch::restricts_to_tls13);
    let supports_tls12 = !quic
        && config.supports_version(ProtocolVersion::TLSv1_2)
        && !ech_tls13_only
        && cx
            .common
            .dtls
            .as_ref()
            .is_none_or(|d| d.allows(ProtocolVersion::TLSv1_2));
    let offers_version = |v: ProtocolVersion| {
        config.supports_version(v)
            && (v != ProtocolVersion::TLSv1_2 || supports_tls12)
            && cx.common.dtls.as_ref().is_none_or(|d| d.allows(v))
    };

    let supported_versions: Vec<ProtocolVersion> =
        [ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_2]
            .into_iter()
            .filter(|v| offers_version(*v))
            .collect();

    let server_name = match (&input.server_name, config.enable_sni) {
        (ServerName::DnsName(dns), true) => Some(ServerNamePayload::SingleDnsName(dns.to_owned())),
        _ => None,
    };

    let offered_sigschemes = ClientHelloDetails::sigschemes_to_offer(
        config.verifier().supported_verify_schemes(),
        supported_versions.contains(&ProtocolVersion::TLSv1_3),
    );

    // Only groups usable with an offered version: a TLS 1.2-only hello must
    // not offer TLS 1.3-only groups such as FFDHE (RFC 10015 §3, RFC 7919
    // §3) or ML-KEM. The list may not be empty (RFC 9846 §4.3.7), so a
    // configuration without such a group fails here instead of sending one.
    let mut named_groups: Vec<NamedGroup> = Vec::new();
    for group in config
        .provider
        .kx_groups
        .iter()
        .filter(|g| supported_versions.iter().any(|v| g.usable_for_version(*v)))
        .map(|g| g.name())
    {
        if !named_groups.contains(&group) {
            named_groups.push(group);
        }
    }
    if named_groups.is_empty() {
        return Err(Error::General(
            "no key exchange group is usable with the enabled protocol versions".into(),
        ));
    }

    // RFC 7366 §2: ask for Encrypt-then-MAC whenever a block cipher suite
    // is on offer; the server answers only if it selects one.
    let offers_block_cipher = supports_tls12
        && config
            .provider
            .cipher_suites
            .iter()
            .any(|cs| cs.is_tls12_block_cipher());

    // RFC 9846 §4.3.8: key shares appear in the order of their groups in
    // supported_groups.
    let group_position = |group: NamedGroup| {
        named_groups
            .iter()
            .position(|g| *g == group)
            .unwrap_or(usize::MAX)
    };
    let key_shares = key_share.as_ref().map(|ks| {
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
        shares.sort_by_key(|share| group_position(share.group));
        shares
    });

    let mut exts = ClientExtensions {
        server_name,
        named_groups: Some(named_groups),
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
        sct_request: config.revocation_enabled().then_some(()),
        transparency_info: input
            .offers_transparency_info(retryreq.is_some())
            .then_some(()),
        extended_master_secret: supports_tls12.then_some(()),
        encrypt_then_mac: offers_block_cipher.then_some(()),
        supported_versions: Some(supported_versions),
        psk_modes: supports_tls13.then(|| vec![PskKeyExchangeMode::PSK_DHE_KE]),
        key_shares,
        cookie: retryreq.and_then(|r| r.extensions.cookie.clone()),
        // RFC 9846 §4.3.6: willing to authenticate after the handshake.
        // RFC 9001 §4.4: never in QUIC.
        post_handshake_auth: (supports_tls13
            && !quic
            && !dtls
            && config.enable_post_handshake_auth
            && config.client_auth_cert_resolver.has_certs())
        .then_some(()),
        // RFC 7250: raw public keys instead of certificates, in either
        // direction.
        client_certificate_types: config
            .client_auth_cert_resolver
            .only_raw_public_keys()
            .then(|| vec![CertificateType::RawPublicKey]),
        server_certificate_types: config
            .verifier
            .requires_raw_public_keys()
            .then(|| vec![CertificateType::RawPublicKey]),
        certificate_compression: supports_tls13
            .then(|| {
                crate::compress::offered_cert_compression(
                    &config.cert_decompressors,
                    config.cert_decompression_limit,
                )
            })
            .flatten(),
        // RFC 9001 §8.2: our transport parameters, on QUIC connections only.
        transport_parameters: cx
            .common
            .quic
            .as_ref()
            .map(|q| crate::msgs::base::Payload::new(q.local_params.clone())),
        ..Default::default()
    };

    // RFC 9345 §4.1.1: offer to accept a delegated credential (TLS 1.3 only).
    if supports_tls13 && config.enable_delegated_credentials {
        exts.delegated_credential = Some(tls13::delegated_credential_schemes(config));
    }

    // RFC 6066 §5: offer certificate URLs (TLS 1.2 only, so never on QUIC
    // or in an ECH inner hello, which offer TLS 1.3 alone).
    #[cfg(feature = "tls12")]
    if supports_tls12
        && !dtls
        && config.enable_client_certificate_url
        && config.client_auth_cert_resolver.has_certs()
    {
        exts.client_certificate_url = Some(());
    }

    #[cfg(feature = "tls12")]
    if supports_tls12
        && !config.revocation_enabled()
        && config.external_binding.is_none()
        && config.resumption.tls12_resumption == super::super::Tls12Resumption::SessionIdOrTickets
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

    // RFC 9846 §4.2.4: after a HelloRetryRequest, a PSK whose hash differs
    // from that of the cipher suite the server selected cannot be used (its
    // binder would cover a transcript hashed differently), so it is dropped.
    if let Some(committed) = committed_suite
        && let Some(Retrieved {
            value: ClientSessionValue::Tls13(inner),
            ..
        }) = &input.resuming
        && inner.suite().common.hash_provider.algorithm() != committed.hash_provider().algorithm()
    {
        input.resuming = None;
    }

    // Our external PSKs, in configuration order (RFC 9846 §4.3.11): whether
    // we offer any decides which ticket may go with them. Never in the
    // clear after the server rejected ECH at the HelloRetryRequest (RFC
    // 9849 §6.1.5): their identities belong to the inner hello.
    let ech_rejected_at_retry = matches!(input.ech, Some(ClientEch::RejectedAtRetry { .. }));
    let can_offer_external = cx.data.service_identity.is_none() || config.cert_with_extern_psk;
    let external_offers = if supports_tls13
        && !config.external_psks.is_empty()
        && !ech_rejected_at_retry
        && can_offer_external
    {
        crate::psk::client_external_offers(
            &config.external_psks,
            &config.provider.cipher_suites,
            committed_suite.and_then(|s| s.tls13()),
            &input.server_name,
            &input.alpn_protocols,
            Protocol::of(cx.common),
        )
    } else {
        Vec::new()
    };
    let cert_with_extern_psk = config.cert_with_extern_psk && !external_offers.is_empty();
    if cert_with_extern_psk {
        exts.cert_with_extern_psk = Some(());
    }

    if let Some(Retrieved {
        value: ClientSessionValue::Tls13(inner),
        ..
    }) = &input.resuming
    {
        // A session established with an external PSK is resumed only while
        // that PSK is still configured and usable on this connection: the
        // resumption carries its authentication forward. With
        // `require_external_psk`, other sessions are not offered at all.
        let ticket_usable = match inner.external_psk() {
            Some(binding) => config.external_psks.iter().any(|psk| {
                binding.matches(psk, &config.provider.cipher_suites, inner.secret())
                    && psk.usable_by_client(&input.server_name, &input.alpn_protocols)
            }),
            None => !config.require_external_psk,
        };
        // RFC 9973 §5.1: all PSKs in this offer must be external.
        if !ticket_usable || cert_with_extern_psk {
            input.resuming = None;
        }
    }

    // RFC 9846 §4.3.11: offer the TLS 1.3 session as a PSK, binder filled in
    // below.
    let tls13_session = match &input.resuming {
        Some(retrieved) if supports_tls13 => retrieved.map(|v| match v {
            ClientSessionValue::Tls13(inner) => Some(inner),
            #[cfg(feature = "tls12")]
            _ => None,
        }),
        _ => None,
    };
    // The ticket goes first, then the external PSKs; their binders are
    // filled in below.
    let mut offered_psks: Vec<OfferedPsk> = Vec::new();
    if let Some(resuming) = &tls13_session {
        offered_psks.push(OfferedPsk {
            identity: resuming.ticket().to_vec(),
            obfuscated_ticket_age: resuming.obfuscated_ticket_age(),
            suite: resuming.suite(),
            secret: PskSecret::new(resuming.secret()),
            label: BinderLabel::Resumption,
            external: None,
        });
    }
    offered_psks.extend(external_offers);

    // RFC 9846 §4.3.10: offer 0-RTT with the first PSK when it and the
    // configuration allow it, but never in the second ClientHello of a
    // retry. An external PSK needs a provisioned suite, and is not used for
    // 0-RTT when we ask for certificate authentication (RFC 9973). Nor with
    // an RFC 8844 binding: the server would read the data before we check
    // its answer in EncryptedExtensions.
    if let Some(first) = offered_psks.first()
        && config.enable_early_data
        && config.external_binding.is_none()
        && retryreq.is_none()
        && !ech_tls13_only
        && !dtls
    {
        let (max_early_data_size, alpn) = match (&first.external, &tls13_session) {
            (Some(psk), _)
                if psk.cipher_suite() == Some(first.suite.common.suite)
                    && !cert_with_extern_psk =>
            {
                (psk.max_early_data_size(), psk.alpn_protocol())
            }
            (None, Some(resuming)) => (resuming.max_early_data_size(), resuming.early_data_alpn()),
            _ => (0, None),
        };
        // RFC 9001 §4.6.1: in QUIC a ticket allows 0-RTT only with the
        // sentinel size, and 0-RTT needs the server's remembered transport
        // parameters (RFC 9000 §7.4.1), which an external PSK does not have.
        let max_early_data_size = match (quic, &first.external) {
            (false, _) => max_early_data_size,
            (true, None) if max_early_data_size == u32::MAX => max_early_data_size,
            (true, _) => 0,
        };
        if max_early_data_size > 0 {
            cx.data
                .early_data
                .enable(max_early_data_size as usize, alpn);
            exts.early_data = Some(());
            // RFC 9000 §7.4.1: 0-RTT runs under the server's remembered
            // transport parameters until EncryptedExtensions brings new ones.
            if let (Some(quic), Some(resuming)) = (&mut cx.common.quic, &tls13_session) {
                quic.peer_params = Some(resuming.quic_params().to_vec());
            }
        }
    }

    if !offered_psks.is_empty() {
        exts.preshared_key = Some(PresharedKeyOffer {
            identities: offered_psks
                .iter()
                .map(|o| PresharedKeyIdentity::new(o.identity.clone(), o.obfuscated_ticket_age))
                .collect(),
            binders: offered_psks
                .iter()
                .map(|o| {
                    PresharedKeyBinder::new(vec![0u8; o.suite.common.hash_provider.output_len()])
                })
                .collect(),
        });
    }

    exts.connection_id = cx.common.dtls.as_deref().and_then(|dtls| dtls.cid.offer());
    exts.return_routability_check = cx.common.dtls.as_deref().and_then(|dtls| dtls.rrc_offer());

    // RFC 8449: the largest record we accept. The protocol maximum is that
    // of the highest version offered; a TLS 1.2 server does not enforce a
    // larger value (RFC 8449 §4) and we clamp what we enforce.
    exts.record_size_limit = cx
        .common
        .local_record_size_limit(config.record_size_limit, supports_tls13);
    // RFC 6066 §6: a TLS 1.2 extension only; `supports_tls12` is false
    // over QUIC and with an ECH offer (RFC 9849 §6.1).
    exts.trusted_ca_keys = config.trusted_ca_keys.clone().filter(|_| supports_tls12);
    // RFC 9149: a TLS 1.3 extension only.
    let ticket_limit = u8::try_from(config.max_tls13_tickets_per_connection).unwrap_or(u8::MAX);
    exts.ticket_request = config
        .tls13_ticket_request
        .filter(|_| supports_tls13)
        .map(|request| ClientTicketRequest {
            new_session_count: request.new_session_count.min(ticket_limit),
            resumption_count: request.resumption_count.min(ticket_limit),
        });
    // RFC 8844: the same values in every ClientHello.
    crate::external_binding::handshake::client_offer(config.external_binding.as_ref(), &mut exts);

    let mut cipher_suites: Vec<CipherSuite> = config
        .provider
        .cipher_suites
        .iter()
        .filter(|cs| offers_version(cs.version().version))
        // RFC 9001 §5.3: only suites with a QUIC header protection scheme.
        .filter(|cs| !quic || cs.usable_for_quic())
        // RFC 9147 §4.2.3, §4.5.3: only suites that encrypt DTLS record
        // numbers, and no CCM_8.
        .filter(|cs| !dtls || cs.usable_for_dtls())
        .map(|cs| cs.suite())
        .collect();
    if retryreq.is_some() {
        input.check_cert_with_extern_psk_retry(cx.common, cert_with_extern_psk)?;
    }
    // RFC 5746 §3.3: signal secure renegotiation support (we never
    // renegotiate); a TLS 1.3-only hello has nothing to signal.
    if supports_tls12 || !ech_tls13_only {
        cipher_suites.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    // RFC 7924: fingerprints of cached TLS 1.2 messages. The second
    // ClientHello after a HelloRetryRequest repeats the first one's offer.
    #[cfg(feature = "tls12")]
    {
        if retryreq.is_none() {
            input.hello.cached_info = crate::cached_info::client::ClientCachedInfo::offer(
                config,
                &input.server_name,
                supports_tls12 && !dtls,
            );
        }
        exts.cached_info = input.hello.cached_info.as_ref().and_then(|c| c.extension());
    }

    // What the server's choices are checked against: never a GREASE value.
    cx.data.offered_post_handshake_auth = exts.post_handshake_auth.is_some();
    input.hello.offered_sigschemes = offered_sigschemes;
    input.hello.sent_record_size_limit = exts.record_size_limit;

    if let Some(grease) = &input.grease {
        add_grease(grease, retryreq, &mut cipher_suites, &mut exts);
    }

    if let Some(ech) = &mut input.ech {
        // Everything but the extensions: version, random, an empty
        // session ID, the suites and the compression methods.
        let other_len = 2 + 32 + 1 + 2 + 2 * cipher_suites.len() + 2;
        ech.prepare(&mut exts, other_len, config.provider.secure_random)?;
    }
    // GREASE extensions are never part of `present_types`.
    input.hello.sent_extensions = exts.present_types();

    let mut chp = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: input.random,
        session_id: input.session_id,
        // RFC 9147 §5.3: an empty legacy_cookie, which selects the DTLS
        // encoding.
        legacy_cookie: dtls.then(PayloadU8::empty),
        cipher_suites,
        compression_methods: vec![Compression::Null],
        extensions: exts,
    };
    // RFC 7685: the length is final here, binders included (they are
    // zero-filled placeholders of the right size until computed below).
    // With a real ECH offer this is the inner hello, which RFC 9849 §6.1.3
    // pads instead; the outer hello is padded when it is sealed. The
    // middlebox workaround has no place in DTLS.
    if !matches!(input.ech, Some(ClientEch::Offer(_))) && !dtls {
        chp.extensions.padding = padding_len(
            config.client_hello_padding,
            HANDSHAKE_HEADER_LEN + chp.get_encoding().len(),
        );
    }
    // RFC 9147 §5.1: a first ClientHello that fits one datagram lets the
    // server answer it without keeping state. If our key shares make it
    // too large, it goes without any: the server's HelloRetryRequest
    // (which a DTLS server sends for its cookie anyway) then names the
    // group it wants.
    if retryreq.is_none()
        && let Some(engine) = cx.common.dtls.as_deref()
        && chp
            .extensions
            .key_shares
            .as_ref()
            .is_some_and(|shares| !shares.is_empty())
        && HANDSHAKE_HEADER_LEN + chp.get_encoding().len() > engine.max_unfragmented_handshake()
    {
        debug!("ClientHello too large for one datagram: offering no key share");
        chp.extensions.key_shares = Some(Vec::new());
        key_share = None;
        cx.common.kx_state = KxState::Start;
    }
    // A ClientHello must fit in a handshake message, and its extension
    // block in a two-byte length; a large `trusted_ca_keys` list or ALPN
    // offer could break either, which would send a malformed message. With
    // an ECH offer this checks the inner ClientHello; the outer one is
    // built from it later.
    if chp.get_encoding().len() > MAX_HANDSHAKE_SIZE as usize {
        return Err(Error::general(
            "the ClientHello is longer than a handshake message may be",
        ));
    }
    let mut hmp = HandshakeMessagePayload(HandshakePayload::ClientHello(chp));

    tls13::fill_in_psk_binders(
        Protocol::of(cx.common),
        &offered_psks,
        &transcript_buffer,
        &mut hmp,
    );

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

    // RFC 9849 §6.1.1: with a real ECH offer, `ch` is the inner hello: it
    // goes into our transcript, sealed into the outer hello that is sent.
    let outer = match (&mut input.ech, &ch.payload) {
        (
            Some(ClientEch::Offer(offer)),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(inner)),
                ..
            },
        ) => {
            let outer = offer.seal_outer(
                inner,
                retryreq.is_some(),
                |len| padding_len(config.client_hello_padding, HANDSHAKE_HEADER_LEN + len),
                config.provider.secure_random,
            )?;
            let outer = Message {
                version: ch.version,
                payload: MessagePayload::handshake(HandshakeMessagePayload(
                    HandshakePayload::ClientHello(outer),
                )),
            };
            offer.outer_transcript.add_message(&outer);
            Some(outer)
        }
        _ => None,
    };

    trace!("Sending ClientHello {:#?}", ch);
    transcript_buffer.add_message(&ch);
    cx.common.send_msg(outer.unwrap_or(ch), false);

    // With 0-RTT offered, the early traffic key derives from the ClientHello
    // alone, so early data can go out right behind it.
    if let Some(first) = offered_psks.first()
        && cx.data.early_data.is_enabled()
    {
        tls13::derive_early_traffic_secret(
            &*config.key_log,
            cx,
            first,
            tls13_session.as_ref().map(|session| session.value),
            &mut input.sent_tls13_fake_ccs,
            &transcript_buffer,
            &input.random.0,
        );
    }

    let next = ExpectServerHello {
        input,
        transcript_buffer,
        offered_psks,
        offered_key_share: key_share,
        suite: committed_suite,
    };

    Ok(if retryreq.is_some() {
        Box::new(next)
    } else {
        Box::new(ExpectServerHelloOrHelloRetryRequest { next })
    })
}

/// The four-byte handshake message header: type and 24-bit length.
const HANDSHAKE_HEADER_LEN: usize = 4;

/// Puts the GREASE values (RFC 8701 §3) into the ClientHello, each first in
/// its list. After a HelloRetryRequest that names a group, the key share
/// list must hold exactly one share for that group (RFC 9846 §4.2.2), so no
/// GREASE share goes into that second ClientHello.
fn add_grease(
    grease: &GreaseValues,
    retryreq: Option<&HelloRetryRequest>,
    cipher_suites: &mut Vec<CipherSuite>,
    exts: &mut ClientExtensions,
) {
    cipher_suites.insert(0, CipherSuite::Unknown(grease.cipher_suite));
    if let Some(groups) = &mut exts.named_groups {
        groups.insert(0, NamedGroup::Unknown(grease.group));
    }
    let hrr_named_group = retryreq.is_some_and(|rr| rr.extensions.key_share.is_some());
    if let Some(shares) = &mut exts.key_shares
        && !hrr_named_group
    {
        // RFC 8701 §3: a GREASE key share carries a single byte.
        shares.insert(
            0,
            KeyShareEntry::new(NamedGroup::Unknown(grease.group), &[0]),
        );
    }
    if let Some(schemes) = &mut exts.signature_schemes {
        schemes.insert(0, SignatureScheme::Unknown(grease.signature_scheme));
    }
    if let Some(versions) = &mut exts.supported_versions {
        versions.insert(0, ProtocolVersion::Unknown(grease.version));
    }
    if let Some(modes) = &mut exts.psk_modes {
        modes.insert(0, PskKeyExchangeMode::Unknown(grease.psk_mode));
    }
    exts.grease_first = Some(grease.first_extension);
    exts.grease_last = Some(grease.last_extension);
}

/// The length of the `padding` extension body (RFC 7685) for a ClientHello
/// handshake message of `unpadded` bytes, or `None` for no extension.
///
/// Lengths of 256 to 511 bytes are padded to 512, the workaround RFC 7685
/// §4 was written for; an `AtLeast` target is reached first. The extension
/// itself takes four bytes of header.
fn padding_len(policy: ClientHelloPadding, unpadded: usize) -> Option<usize> {
    const PROBLEMATIC: core::ops::Range<usize> = 256..512;
    let mut body = match policy {
        ClientHelloPadding::Disabled => return None,
        ClientHelloPadding::AtLeast(target) if unpadded < usize::from(target) => {
            Some((usize::from(target) - unpadded).saturating_sub(4))
        }
        _ => None,
    };
    let padded = unpadded + body.map_or(0, |b| 4 + b);
    if PROBLEMATIC.contains(&padded) {
        let missing = PROBLEMATIC.end - padded;
        body = Some(match body {
            Some(b) => b + missing,
            None => missing.saturating_sub(4),
        });
    }
    body
}

#[cfg(test)]
mod tests;
