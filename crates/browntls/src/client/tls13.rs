//! The TLS 1.3 client handshake after the ServerHello (RFC 8446 §4).

use alloc::boxed::Box;
use alloc::vec::Vec;

use browntls_pki::ServerName;

use super::client_conn::ClientConnectionData;
use super::common::{ClientAuthDetails, ClientHelloDetails, ServerCertDetails};
use super::hs::{ClientContext, NextState, NextStateOrError, OfferedKeyShare};
use super::{ClientConfig, hs};
use crate::common_state::{CommonState, ConnectionRandoms, HandshakeKind, KxState, Side};
use crate::conn::State;
use crate::crypto::hmac;
use crate::ct::constant_time_eq;
use crate::delegated_credential::{self, DelegatedCredential};
use crate::ech::{EchStatus, RejectedEch};
use crate::enums::{
    AlertDescription, CertificateCompressionAlgorithm, ContentType, HandshakeType, ProtocolVersion,
};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::log::{debug, trace, warning};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::enums::KeyUpdateRequest;
use crate::msgs::handshake::{
    CertificatePayloadTls13, CertificateRequestPayloadTls13, HandshakeMessagePayload,
    HandshakePayload, NewSessionTicketPayloadTls13, PresharedKeyBinder, ServerExtensions,
    ServerHelloPayload,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::psk::{ExternalPsk, OfferedPsk};
use crate::sign::{CertifiedKey, Signer};
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::extensions::{Tls13Message, first_disallowed};
use crate::tls13::key_schedule::{
    KeyScheduleEarly, KeyScheduleHandshake, KeySchedulePreHandshake, KeyScheduleTraffic,
};
use crate::verify::{
    DigitallySignedStruct, FinishedMessageVerified, HandshakeSignatureValid, ServerCertVerified,
};

/// How many `update_requested` KeyUpdates we tolerate without sending data.
const MAX_KEY_UPDATE_REQUESTS: u8 = 8;

/// How many post-handshake CertificateRequests we answer while the server
/// sends no application data: each answer costs a signature, so this is a
/// local resource bound, not an RFC 9846 rule.
const MAX_POST_HANDSHAKE_AUTH_REQUESTS: u8 = 8;

/// Computes the binder of every offered PSK (RFC 9846 §4.3.11.2), each
/// with its own hash and label, over the ClientHello up to the binders, and
/// writes them into the ClientHello.
pub(super) fn fill_in_psk_binders(
    offered: &[OfferedPsk],
    transcript: &HandshakeHashBuffer,
    hmp: &mut HandshakeMessagePayload<'_>,
) {
    if offered.is_empty() {
        return;
    }
    let binder_plaintext = hmp.encoding_for_binder_signing();
    let binders: Vec<PresharedKeyBinder> = offered
        .iter()
        .map(|psk| {
            let handshake_hash =
                transcript.hash_given(psk.suite.common.hash_provider, &binder_plaintext);
            let binder = KeyScheduleEarly::new(psk.suite, psk.secret.as_ref())
                .psk_binder(psk.label, handshake_hash.as_ref());
            PresharedKeyBinder::new(binder.as_ref().to_vec())
        })
        .collect();

    if let HandshakePayload::ClientHello(ch) = &mut hmp.0
        && let Some(psk) = &mut ch.extensions.preshared_key
    {
        psk.binders = binders;
    }
}

/// Derives `client_early_traffic_secret` from the ClientHello alone and
/// starts encrypting under it, so 0-RTT data can follow the ClientHello.
pub(super) fn derive_early_traffic_secret(
    key_log: &dyn crate::key_log::KeyLog,
    cx: &mut ClientContext<'_>,
    hash_provider: &'static dyn crate::crypto::hash::Hash,
    early_key_schedule: &KeyScheduleEarly,
    sent_tls13_fake_ccs: &mut bool,
    transcript_buffer: &HandshakeHashBuffer,
    client_random: &[u8; 32],
) {
    // The compatibility ChangeCipherSpec must precede our first ciphertext.
    emit_fake_ccs(sent_tls13_fake_ccs, cx.common);

    let client_hello_hash = transcript_buffer.hash_given(hash_provider, &[]);
    early_key_schedule.client_early_traffic_secret(
        client_hello_hash.as_ref(),
        key_log,
        client_random,
        cx.common,
    );
    cx.common.early_exporter =
        Some(early_key_schedule.early_exporter(client_hello_hash.as_ref(), key_log, client_random));
    cx.common.early_traffic = true;
    trace!("Starting early data traffic");
}

/// Sends the middlebox-compatibility ChangeCipherSpec once (RFC 8446 appendix D.4).
pub(super) fn emit_fake_ccs(sent: &mut bool, common: &mut CommonState) {
    if *sent {
        return;
    }
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload),
    };
    common.send_msg(m, false);
    *sent = true;
}

pub(super) fn validate_server_hello(
    common: &mut CommonState,
    server_hello: &ServerHelloPayload,
) -> Result<(), Error> {
    // RFC 9846 §4.3: a recognised extension that Table 1 does not allow in
    // a ServerHello is illegal_parameter.
    if first_disallowed(
        server_hello.extensions.present_types(),
        Tls13Message::ServerHello,
    )
    .is_some()
    {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::UnexpectedCleartextExtension,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_server_hello(
    config: Arc<ClientConfig>,
    cx: &mut ClientContext<'_>,
    server_hello: &ServerHelloPayload,
    mut resuming_session: Option<persist::Tls13ClientSessionValue>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    offered_psks: Vec<OfferedPsk>,
    hello: ClientHelloDetails,
    our_key_share: OfferedKeyShare,
    mut sent_tls13_fake_ccs: bool,
    alpn_protocols: Vec<Vec<u8>>,
) -> NextStateOrError {
    let their_key_share = server_hello
        .extensions
        .key_share
        .as_ref()
        .ok_or_else(|| cx.common.missing_extension(PeerMisbehaved::MissingKeyShare))?;

    // The server may answer our hybrid share with its classical half, which we
    // also offered (when the provider supports that group on its own).
    let our_key_share = match our_key_share {
        OfferedKeyShare::Full(kx)
            if kx.group() != their_key_share.group
                && kx
                    .hybrid_component()
                    .is_some_and(|(g, _)| g == their_key_share.group)
                && let Some(component_group) =
                    config.find_kx_group(their_key_share.group, ProtocolVersion::TLSv1_3) =>
        {
            cx.common.kx_state = KxState::Started(component_group);
            OfferedKeyShare::HybridComponent(kx)
        }
        other => other,
    };

    if our_key_share.group() != their_key_share.group {
        return Err(cx.common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::WrongGroupForKeyShare,
        ));
    }

    let mut external_psk = None;
    let key_schedule_pre = match server_hello.extensions.pre_shared_key {
        Some(_) if offered_psks.is_empty() => {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SelectedUnofferedPsk,
            ));
        }
        Some(selected) => {
            // RFC 9846 §4.3.11: an identity we offered, whose hash is the
            // selected suite's (and, for an external PSK restricted to one
            // suite, that suite).
            let Some(offered) = offered_psks.get(usize::from(selected)) else {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SelectedInvalidPsk,
                ));
            };
            let pinned_suite_ok = offered
                .external
                .as_ref()
                .and_then(|psk| psk.cipher_suite())
                .is_none_or(|cs| cs == suite.common.suite);
            if offered.suite.common.hash_provider.algorithm()
                != suite.common.hash_provider.algorithm()
                || !pinned_suite_ok
            {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::ResumptionOfferedWithIncompatibleCipherSuite,
                ));
            }
            if cx.data.early_data.is_enabled() {
                if selected != 0 {
                    // Our early data went out under the first PSK, which
                    // the server did not take: it cannot have read it.
                    cx.data.early_data.rejected();
                    cx.common.early_traffic = false;
                } else if offered.suite.common.suite != suite.common.suite {
                    // Early data was encrypted with the PSK's suite; the
                    // server may not switch suites and still read it.
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::EarlyDataOfferedWithVariedCipherSuite,
                    ));
                }
            }
            match &offered.external {
                None => {
                    debug!("Resuming using PSK");
                    cx.common.handshake_kind = Some(HandshakeKind::Resumed);
                    // A session established with an external PSK carries
                    // it forward (we offered the ticket only while the PSK
                    // is configured); reported once the server's Finished
                    // verifies.
                    cx.common.external_psk = resuming_session
                        .as_ref()
                        .and_then(|session| session.external_psk())
                        .and_then(|binding| {
                            config
                                .external_psks
                                .iter()
                                .find(|psk| binding.matches(psk))
                                .cloned()
                        });
                }
                Some(psk) => {
                    debug!("Using external PSK");
                    resuming_session = None;
                    // Reported once the server's Finished verifies.
                    cx.common.external_psk = Some(psk.clone());
                    external_psk = Some(psk.clone());
                }
            }
            // The schedule continues with the negotiated suite, which may
            // differ from the binder's in everything but the hash.
            KeyScheduleEarly::new(suite, offered.secret.as_ref()).into_pre_handshake()
        }
        None => {
            debug!("Not resuming");
            // Any early data went out under a PSK the server did not take.
            if cx.data.early_data.is_enabled() {
                cx.data.early_data.rejected();
            }
            cx.common.early_traffic = false;
            cx.common.early_exporter = None;
            resuming_session = None;
            KeySchedulePreHandshake::new(suite)
        }
    };

    // RFC 8773: the server authenticates with its certificate on top of an
    // external PSK. It may only say so when it selected one.
    let cert_with_extern_psk = server_hello.extensions.cert_with_extern_psk.is_some();
    if cert_with_extern_psk && external_psk.is_none() {
        return Err(cx.common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::CertWithExternPskWithoutExternalPsk,
        ));
    }

    let shared_secret =
        our_key_share
            .complete(&their_key_share.payload.0)
            .map_err(|err| match err {
                Error::PeerMisbehaved(_) => cx
                    .common
                    .send_fatal_alert(AlertDescription::IllegalParameter, err),
                other => other,
            })?;
    cx.common.kx_state.complete();

    let key_schedule = key_schedule_pre.into_handshake_with_shared_secret(&shared_secret);
    drop(shared_secret);

    // Any ChangeCipherSpec we send must precede our first protected record.
    emit_fake_ccs(&mut sent_tls13_fake_ccs, cx.common);

    // While early data may still be in flight our encrypter stays on the
    // early key; the handshake key is installed once that question settles.
    let hash_at_server_hello = transcript.current_hash();
    let key_schedule = key_schedule.derive_client_handshake_secrets(
        cx.data.early_data.is_enabled(),
        hash_at_server_hello.as_ref(),
        &*config.key_log,
        &randoms.client,
        cx.common,
    );

    // Refusals of what the server selected, sent once our alert can be
    // protected under the handshake key the server now reads with: no 0-RTT
    // is in flight (none was accepted without a PSK, and none is sent with
    // RFC 8773).
    if config.require_external_psk && cx.common.external_psk.is_none() {
        return Err(cx.common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            PeerIncompatible::ExternalPskRequired,
        ));
    }
    if external_psk.is_some() && config.require_cert_with_extern_psk && !cert_with_extern_psk {
        return Err(cx.common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            PeerIncompatible::CertWithExternPskRequired,
        ));
    }

    Ok(Box::new(ExpectEncryptedExtensions {
        config,
        resuming_session,
        external_psk,
        cert_with_extern_psk,
        server_name,
        randoms,
        suite,
        transcript,
        key_schedule,
        hello,
        alpn_protocols,
    }))
}

struct ExpectEncryptedExtensions {
    config: Arc<ClientConfig>,
    resuming_session: Option<persist::Tls13ClientSessionValue>,
    /// The external PSK the server selected, if it did.
    external_psk: Option<Arc<ExternalPsk>>,
    /// Whether RFC 8773 certificate authentication was negotiated.
    cert_with_extern_psk: bool,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    hello: ClientHelloDetails,
    alpn_protocols: Vec<Vec<u8>>,
}

impl State<ClientConnectionData> for ExpectEncryptedExtensions {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        let exts: &ServerExtensions = require_handshake_msg!(
            m,
            HandshakeType::EncryptedExtensions,
            HandshakePayload::EncryptedExtensions
        )?;
        debug!("TLS1.3 encrypted extensions: {:?}", exts);
        self.transcript.add_message(&m);

        let received = exts.present_types();
        // RFC 9846 §4.3: a recognised extension that Table 1 does not allow
        // in EncryptedExtensions is illegal_parameter; checked before the
        // solicitation check, which would otherwise mask it.
        if first_disallowed(received.iter().copied(), Tls13Message::EncryptedExtensions).is_some() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::DisallowedEncryptedExtension,
            ));
        }
        if self
            .hello
            .server_sent_unsolicited_extensions(&received, &[])
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerMisbehaved::UnsolicitedEncryptedExtension,
            ));
        }

        // RFC 9849 §5: retry configurations answer a rejected offer only;
        // after a GREASE offer they are ignored (§6.2.1).
        match cx.data.ech_status {
            EchStatus::Accepted if exts.encrypted_client_hello.is_some() => {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::UnsupportedExtension,
                    PeerMisbehaved::UnsolicitedEchExtension,
                ));
            }
            EchStatus::Rejected => {
                cx.data.ech_retry_configs = exts.encrypted_client_hello.clone();
            }
            _ => {}
        }

        hs::process_alpn_protocol(
            cx.common,
            &self.alpn_protocols,
            exts.alpn.as_ref().map(|p| p.as_ref()),
        )?;
        hs::process_cert_type_extensions(
            cx.common,
            &self.config,
            exts.client_certificate_type,
            exts.server_certificate_type,
        )?;
        // RFC 8449 §4: in TLS 1.3 the server's limit comes here. RFC 9149's
        // `expected_count` is a hint only and needs no action.
        hs::process_record_size_limit(cx.common, &self.hello, exts.record_size_limit, true)?;

        let psk_selected = self.resuming_session.is_some() || self.external_psk.is_some();
        // RFC 9846 §4.3.10: early_data here requires a PSK, and the first
        // one we offered (under which our early data went out).
        let was_early_traffic = cx.common.early_traffic;
        if exts.early_data.is_some() && !psk_selected {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerMisbehaved::EarlyDataExtensionWithoutResumption,
            ));
        }
        if exts.early_data.is_some() && !was_early_traffic {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::EarlyDataAcceptedWithOtherPsk,
            ));
        }

        // An external PSK restricted to an ALPN protocol is used with that
        // protocol only, also through a session resumed from it; with early
        // data, RFC 9846 §4.3.10 requires the provisioned protocol to be the
        // negotiated one.
        let negotiated = cx.common.alpn_protocol.as_deref();
        if let Some(psk) = &self.external_psk
            && exts.early_data.is_some()
            && psk.alpn_protocol() != negotiated
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SelectedExternalPskWithOtherAlpn,
            ));
        }
        if let Some(psk) = &cx.common.external_psk
            && psk.alpn_protocol().is_some_and(|p| Some(p) != negotiated)
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerMisbehaved::SelectedExternalPskWithOtherAlpn,
            ));
        }

        // RFC 9846 §4.3.10: the early_data acknowledgement decides the fate
        // of what we sent; without it we switch to handshake keys.
        if was_early_traffic {
            match exts.early_data {
                Some(()) => cx.data.early_data.accepted(),
                None => {
                    cx.data.early_data.rejected();
                    cx.common.early_traffic = false;
                    cx.common.early_exporter = None;
                    self.key_schedule.set_handshake_encrypter(cx.common);
                }
            }
        }

        match (self.resuming_session, self.external_psk) {
            (Some(resuming), _) => {
                // The server authenticated through the PSK; reinstate the
                // certificates seen when the session was established (none
                // for a session authenticated by an external PSK alone).
                let chain = resuming.server_cert_chain();
                cx.common.peer_certificates = (!chain.0.is_empty()).then(|| chain.clone());
                cx.data.delegated_credential_expiry = resuming.delegated_credential_expiry();
                Ok(Box::new(ExpectFinished {
                    config: self.config,
                    server_name: self.server_name,
                    randoms: self.randoms,
                    suite: self.suite,
                    transcript: self.transcript,
                    key_schedule: self.key_schedule,
                    client_auth: None,
                    client_cert_compression: Vec::new(),
                    cert_verified: ServerCertVerified::assertion(),
                    sig_verified: HandshakeSignatureValid::assertion(),
                }))
            }
            (None, Some(_)) if !self.cert_with_extern_psk => {
                // The server authenticated through the external PSK alone:
                // no certificate follows.
                Ok(Box::new(ExpectFinished {
                    config: self.config,
                    server_name: self.server_name,
                    randoms: self.randoms,
                    suite: self.suite,
                    transcript: self.transcript,
                    key_schedule: self.key_schedule,
                    client_auth: None,
                    client_cert_compression: Vec::new(),
                    cert_verified: ServerCertVerified::assertion(),
                    sig_verified: HandshakeSignatureValid::assertion(),
                }))
            }
            // A full handshake, or RFC 8773 certificate authentication on
            // top of an external PSK.
            _ => Ok(Box::new(ExpectCertificateOrCertReq {
                config: self.config,
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                offered_sigschemes: self.hello.offered_sigschemes,
            })),
        }
    }
}

struct ExpectCertificateOrCertReq {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    offered_sigschemes: Vec<crate::enums::SignatureScheme>,
}

impl State<ClientConnectionData> for ExpectCertificateOrCertReq {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        match &m.payload {
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload(
                        HandshakePayload::CertificateTls13(..)
                        | HandshakePayload::CompressedCertificate(..),
                    ),
                ..
            } => Box::new(ExpectCertificate {
                config: self.config,
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: None,
                client_cert_compression: Vec::new(),
                offered_sigschemes: self.offered_sigschemes,
            })
            .handle(cx, m),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateRequestTls13(..)),
                ..
            } => Box::new(ExpectCertificateRequest {
                config: self.config,
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                offered_sigschemes: self.offered_sigschemes,
            })
            .handle(cx, m),
            payload => Err(crate::check::inappropriate_handshake_message(
                payload,
                &[ContentType::Handshake],
                &[
                    HandshakeType::Certificate,
                    HandshakeType::CertificateRequest,
                ],
            )),
        }
    }
}

struct ExpectCertificateRequest {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    offered_sigschemes: Vec<crate::enums::SignatureScheme>,
}

impl State<ClientConnectionData> for ExpectCertificateRequest {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        let certreq = require_handshake_msg!(
            m,
            HandshakeType::CertificateRequest,
            HandshakePayload::CertificateRequestTls13
        )?;
        self.transcript.add_message(&m);
        debug!("Got CertificateRequest {:?}", certreq);

        // RFC 9846 §4.4.2: the context is empty during the handshake. The
        // message is well formed, so a non-empty one is illegal_parameter.
        if !certreq.context.0.is_empty() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::IllegalCertificateRequestContext,
            ));
        }

        let compat_sigschemes = certificate_request_sigschemes(cx.common, certreq)?;

        let client_cert_compression = certreq
            .extensions
            .certificate_compression
            .clone()
            .unwrap_or_default();

        // RFC 9849 §6.1.7: a server that rejected ECH gets no certificate.
        let client_auth = if cx.data.ech_status == EchStatus::Rejected {
            ClientAuthDetails::Empty {
                auth_context_tls13: Some(certreq.context.0.clone()),
            }
        } else {
            ClientAuthDetails::resolve(
                &*self.config.client_auth_cert_resolver,
                certreq.extensions.authorities.as_deref(),
                None,
                &compat_sigschemes,
                Some(certreq.context.0.clone()),
            )
        };

        Ok(Box::new(ExpectCertificate {
            config: self.config,
            server_name: self.server_name,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            client_auth: Some(client_auth),
            client_cert_compression,
            offered_sigschemes: self.offered_sigschemes,
        }))
    }
}

/// Checks a CertificateRequest's extensions (RFC 9846 §4.4.2) and returns
/// the TLS 1.3 signature schemes it allows.
fn certificate_request_sigschemes(
    common: &mut CommonState,
    certreq: &CertificateRequestPayloadTls13,
) -> Result<Vec<crate::enums::SignatureScheme>, Error> {
    // RFC 9846 §4.3: a recognised extension that may not appear in a
    // CertificateRequest is illegal_parameter.
    if first_disallowed(
        certreq.extensions.unknown.iter().copied(),
        Tls13Message::CertificateRequest,
    )
    .is_some()
    {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::DisallowedCertificateRequestExtension,
        ));
    }

    // RFC 9846 §4.4.2: signature_algorithms MUST be specified; its
    // absence is missing_extension (§6.2).
    let Some(sigschemes) = &certreq.extensions.signature_algorithms else {
        return Err(common.send_fatal_alert(
            AlertDescription::MissingExtension,
            PeerIncompatible::SignatureAlgorithmsExtensionRequired,
        ));
    };
    let compat_sigschemes: Vec<_> = sigschemes
        .iter()
        .copied()
        .filter(crate::enums::SignatureScheme::supported_in_tls13)
        .collect();
    if compat_sigschemes.is_empty() {
        return Err(common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            PeerIncompatible::NoCertificateRequestSignatureSchemesInCommon,
        ));
    }
    Ok(compat_sigschemes)
}

struct ExpectCertificate {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    client_auth: Option<ClientAuthDetails>,
    /// The compression algorithms the server's CertificateRequest accepts
    /// for our Certificate (RFC 8879 §3); empty when it named none.
    client_cert_compression: Vec<CertificateCompressionAlgorithm>,
    offered_sigschemes: Vec<crate::enums::SignatureScheme>,
}

impl State<ClientConnectionData> for ExpectCertificate {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        let cert_chain: CertificatePayloadTls13<'static> = match &m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateTls13(chain)),
                ..
            } => chain.clone().into_owned(),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CompressedCertificate(compressed)),
                ..
            } => crate::compress::receive_compressed_certificate(
                cx.common,
                &self.config.cert_decompressors,
                self.config.cert_decompression_limit,
                compressed,
            )?,
            payload => {
                return Err(crate::check::inappropriate_handshake_message(
                    payload,
                    &[ContentType::Handshake],
                    &[HandshakeType::Certificate],
                ));
            }
        };
        self.transcript.add_message(&m);

        // RFC 9846 §4.5.1: the context is empty for server authentication.
        // The message is well formed, so a non-empty one is illegal_parameter.
        if !cert_chain.context.0.is_empty() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::IllegalCertificateRequestContext,
            ));
        }
        // RFC 9846 §4.5.1: the server MUST send a non-empty chain.
        if cert_chain.entries.is_empty() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::DecodeError,
                Error::NoCertificatesPresented,
            ));
        }
        // We offer status_request, so OCSP responses may come with any entry
        // (only the end entity's is used). We never offer SCTs, so none may
        // be sent (RFC 9846 §4.5.1: extensions MUST correspond to ours).
        if cert_chain.entries.iter().any(|e| e.sct_list.is_some()) {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerMisbehaved::UnsolicitedSctList,
            ));
        }

        // RFC 9345 §4.1.1: a delegated credential we did not ask for is
        // unexpected_message; one on any entry but the end entity's is
        // illegal_parameter (the RFC allows ignoring it; we fail closed).
        let delegated_credential = cert_chain.end_entity_delegated_credential().cloned();
        if !self.config.enable_delegated_credentials
            && (delegated_credential.is_some()
                || cert_chain.delegated_credential_on_non_end_entity())
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnexpectedMessage,
                PeerMisbehaved::UnsolicitedDelegatedCredential,
            ));
        }
        if cert_chain.delegated_credential_on_non_end_entity() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::DelegatedCredentialNotOnEndEntity,
            ));
        }

        let end_entity_ocsp = cert_chain.end_entity_ocsp();
        let server_cert = ServerCertDetails::new(
            cert_chain.into_certificate_chain().into_owned(),
            end_entity_ocsp,
        );

        Ok(Box::new(ExpectCertificateVerify {
            config: self.config,
            server_name: self.server_name,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            server_cert,
            client_auth: self.client_auth,
            client_cert_compression: self.client_cert_compression,
            offered_sigschemes: self.offered_sigschemes,
            delegated_credential,
        }))
    }
}

struct ExpectCertificateVerify {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    server_cert: ServerCertDetails,
    client_auth: Option<ClientAuthDetails>,
    /// The compression algorithms the server's CertificateRequest accepts
    /// for our Certificate (RFC 8879 §3); empty when it named none.
    client_cert_compression: Vec<CertificateCompressionAlgorithm>,
    offered_sigschemes: Vec<crate::enums::SignatureScheme>,
    delegated_credential: Option<DelegatedCredential>,
}

impl State<ClientConnectionData> for ExpectCertificateVerify {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        let cert_verify = require_handshake_msg!(
            m,
            HandshakeType::CertificateVerify,
            HandshakePayload::CertificateVerify
        )?;
        trace!("Server cert is {:?}", self.server_cert.cert_chain);

        // The signature covers the transcript up to and including Certificate.
        let handshake_hash = self.transcript.current_hash();

        let (end_entity, intermediates) =
            self.server_cert.cert_chain.0.split_first().ok_or_else(|| {
                cx.common.send_fatal_alert(
                    AlertDescription::DecodeError,
                    Error::NoCertificatesPresented,
                )
            })?;

        if !self.offered_sigschemes.contains(&cert_verify.scheme) {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }

        let now = self.config.current_time()?;
        let cert_verified = self
            .config
            .verifier()
            .verify_server_cert(
                end_entity,
                intermediates,
                &self.server_name,
                &self.server_cert.ocsp_response,
                now,
            )
            .map_err(|err| send_cert_path_error_alert(cx.common, err))?;

        let message = construct_server_verify_message(&handshake_hash);
        let (sig_verified, delegated_credential_expiry) = match &self.delegated_credential {
            None => (
                self.config
                    .verifier()
                    .verify_tls13_signature(&message, end_entity, cert_verify)
                    .map_err(|err| send_cert_verify_error_alert(cx.common, err))?,
                None,
            ),
            Some(dc) => {
                // RFC 9345 §4.1.3: an invalid credential is illegal_parameter.
                let offered_dc_schemes = delegated_credential_schemes(&self.config);
                let presented = delegated_credential::Presented {
                    side: Side::Server,
                    end_entity,
                    offered_dc_schemes: &offered_dc_schemes,
                    offered_sig_schemes: &self.offered_sigschemes,
                    cert_verify_scheme: cert_verify.scheme,
                    now,
                };
                let expiry = delegated_credential::validate(dc, &presented, |msg, dss| {
                    self.config
                        .verifier()
                        .verify_tls13_signature(msg, end_entity, dss)
                })
                .map_err(|err| {
                    cx.common
                        .send_fatal_alert(AlertDescription::IllegalParameter, err)
                })?;
                // Then the credential's key verifies CertificateVerify.
                let verified = self
                    .config
                    .verifier()
                    .verify_tls13_signature_with_delegated_key(
                        &message,
                        &dc.credential.public_key,
                        cert_verify,
                    )
                    .map_err(|err| send_cert_verify_error_alert(cx.common, err))?;
                (verified, Some(expiry))
            }
        };
        cx.data.delegated_credential = self.delegated_credential;
        cx.data.delegated_credential_expiry = delegated_credential_expiry;

        cx.common.peer_certificates = Some(self.server_cert.cert_chain);
        self.transcript.add_message(&m);

        Ok(Box::new(ExpectFinished {
            config: self.config,
            server_name: self.server_name,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            client_auth: self.client_auth,
            client_cert_compression: self.client_cert_compression,
            cert_verified,
            sig_verified,
        }))
    }
}

/// The schemes a client accepts for a server's delegated credential
/// (RFC 9345 §4.1.1): the verifier's TLS 1.3 schemes, without
/// `rsa_pss_rsae_*` (RFC 9345 §4 forbids `rsaEncryption` credential keys).
pub(super) fn delegated_credential_schemes(
    config: &ClientConfig,
) -> Vec<crate::enums::SignatureScheme> {
    config
        .verifier()
        .supported_verify_schemes()
        .into_iter()
        .filter(|scheme| delegated_credential::credential_scheme_allowed(*scheme))
        .collect()
}

/// Sends the alert for a certificate chain that failed validation.
///
/// A signature inside the chain that does not verify, or that uses an
/// algorithm we do not accept (MD5 and SHA-1 included), is bad_certificate
/// (RFC 9846 §6.2, §4.5.1): decrypt_error is for handshake signatures
/// (CertificateVerify), see [`send_cert_verify_error_alert`].
pub(crate) fn send_cert_path_error_alert(common: &mut CommonState, err: Error) -> Error {
    match &err {
        Error::InvalidCertificate(
            crate::error::CertificateError::BadSignature
            | crate::error::CertificateError::UnsupportedSignatureAlgorithm,
        ) => common.send_fatal_alert(AlertDescription::BadCertificate, err),
        _ => send_cert_verify_error_alert(common, err),
    }
}

/// Sends the alert for a failed handshake signature check, or for any other
/// certificate error.
pub(crate) fn send_cert_verify_error_alert(common: &mut CommonState, err: Error) -> Error {
    match &err {
        Error::InvalidCertificate(e) => common.send_fatal_alert(e.clone().into(), err),
        Error::PeerMisbehaved(_) => {
            common.send_fatal_alert(AlertDescription::IllegalParameter, err)
        }
        _ => common.send_fatal_alert(AlertDescription::HandshakeFailure, err),
    }
}

/// The CertificateVerify content for a server signature (RFC 8446 §4.4.3).
pub(crate) fn construct_server_verify_message(
    handshake_hash: &crate::crypto::hash::Output,
) -> Vec<u8> {
    construct_verify_message(handshake_hash, b"TLS 1.3, server CertificateVerify")
}

/// The CertificateVerify content for a client signature.
pub(crate) fn construct_client_verify_message(
    handshake_hash: &crate::crypto::hash::Output,
) -> Vec<u8> {
    construct_verify_message(handshake_hash, b"TLS 1.3, client CertificateVerify")
}

fn construct_verify_message(
    handshake_hash: &crate::crypto::hash::Output,
    context: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64 + context.len() + 1 + handshake_hash.as_ref().len());
    msg.resize(64, 0x20);
    msg.extend_from_slice(context);
    msg.push(0x00);
    msg.extend_from_slice(handshake_hash.as_ref());
    msg
}

fn emit_certificate_tls13(
    transcript: &mut HandshakeHash,
    config: &ClientConfig,
    certkey: Option<&CertifiedKey>,
    auth_context: Option<Vec<u8>>,
    compression: &[CertificateCompressionAlgorithm],
    common: &mut CommonState,
) {
    let certs: &[browntls_pki::CertificateDer<'static>] =
        certkey.map(|ck| ck.cert.as_slice()).unwrap_or(&[]);
    let mut cert_payload = CertificatePayloadTls13::new(certs.iter(), None);
    cert_payload.context = PayloadU8::new(auth_context.unwrap_or_default());

    // RFC 8879 §4: compress when the CertificateRequest named an algorithm
    // we have.
    if let Some(compressed) = crate::compress::compress_certificate(
        &config.cert_compressors,
        &config.cert_compression_cache,
        compression,
        &cert_payload.get_encoding(),
    ) {
        let m = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::CompressedCertificate(compressed),
            )),
        };
        transcript.add_message(&m);
        common.send_msg(m, true);
        return;
    }

    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::CertificateTls13(cert_payload),
        )),
    };
    transcript.add_message(&m);
    common.send_msg(m, true);
}

fn emit_certverify_tls13(
    transcript: &mut HandshakeHash,
    signer: &dyn Signer,
    common: &mut CommonState,
) -> Result<(), Error> {
    let message = construct_client_verify_message(&transcript.current_hash());
    let scheme = signer.scheme();
    let sig = signer.sign(&message)?;
    let dss = DigitallySignedStruct::new(scheme, sig);
    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::CertificateVerify(dss),
        )),
    };
    transcript.add_message(&m);
    common.send_msg(m, true);
    Ok(())
}

fn emit_finished_tls13(
    transcript: &mut HandshakeHash,
    verify_data: &hmac::Tag,
    common: &mut CommonState,
) {
    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::Finished(
            Payload::new(verify_data.as_ref().to_vec()),
        ))),
    };
    transcript.add_message(&m);
    common.send_msg(m, true);
}

fn emit_end_of_early_data_tls13(transcript: &mut HandshakeHash, common: &mut CommonState) {
    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::EndOfEarlyData,
        )),
    };
    transcript.add_message(&m);
    common.send_msg(m, true);
}

struct ExpectFinished {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    client_auth: Option<ClientAuthDetails>,
    /// The compression algorithms the server's CertificateRequest accepts
    /// for our Certificate (RFC 8879 §3); empty when it named none.
    client_cert_compression: Vec<CertificateCompressionAlgorithm>,
    cert_verified: ServerCertVerified,
    sig_verified: HandshakeSignatureValid,
}

impl State<ClientConnectionData> for ExpectFinished {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        let handshake_hash = st.transcript.current_hash();
        let expect_verify_data = st.key_schedule.sign_server_finish(handshake_hash.as_ref());
        if !constant_time_eq(expect_verify_data.as_ref(), finished.bytes()) {
            return Err(cx
                .common
                .send_fatal_alert(AlertDescription::DecryptError, Error::DecryptError));
        }
        if let Some(expiry) = cx.data.delegated_credential_expiry
            && st.config.current_time()? >= expiry
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::DelegatedCredentialExpired,
            ));
        }
        let fin = FinishedMessageVerified::assertion();
        // The server has proven it holds the external PSK, if one is in use.
        cx.common.external_psk_confirmed = true;
        st.transcript.add_message(&m);

        // The application secrets derive from the transcript through the
        // server Finished (RFC 8446 §7.1), before anything we send now.
        let hash_after_handshake = st.transcript.current_hash();

        // RFC 8446 §4.5: EndOfEarlyData is still protected by the early
        // traffic key but follows the server Finished in the transcript.
        if cx.common.early_traffic {
            emit_end_of_early_data_tls13(&mut st.transcript, cx.common);
            cx.common.early_traffic = false;
            cx.data.early_data.finished();
            st.key_schedule.set_handshake_encrypter(cx.common);
        }

        // Derive the application secrets; the server already sends under
        // them, so switch our decrypter before anything else.
        let traffic_pending = st.key_schedule.into_traffic_with_client_finished_pending(
            hash_after_handshake.as_ref(),
            &*st.config.key_log,
            &st.randoms.client,
            cx.common,
        );
        traffic_pending.set_server_application_decrypter(cx.common);

        // Our flight still goes under the handshake key.
        if let Some(client_auth) = st.client_auth {
            match client_auth {
                ClientAuthDetails::Empty { auth_context_tls13 } => {
                    emit_certificate_tls13(
                        &mut st.transcript,
                        &st.config,
                        None,
                        auth_context_tls13,
                        &st.client_cert_compression,
                        cx.common,
                    );
                }
                ClientAuthDetails::Verify {
                    certkey,
                    signer,
                    auth_context_tls13,
                } => {
                    emit_certificate_tls13(
                        &mut st.transcript,
                        &st.config,
                        Some(&certkey),
                        auth_context_tls13,
                        &st.client_cert_compression,
                        cx.common,
                    );
                    emit_certverify_tls13(&mut st.transcript, &*signer, cx.common)?;
                }
            }
        }

        let verify_data = traffic_pending.sign_client_finish(st.transcript.current_hash().as_ref());
        emit_finished_tls13(&mut st.transcript, &verify_data, cx.common);

        let key_schedule = traffic_pending.into_traffic(cx.common);

        // RFC 9849 §6.1.6: a handshake with the outer ClientHello only
        // authenticates the rejection. Abort with ech_required before any
        // application data, handing back the retry configurations.
        if cx.data.ech_status == EchStatus::Rejected {
            let retry_configs = cx.data.ech_retry_configs.take();
            return Err(cx.common.send_fatal_alert(
                AlertDescription::EncryptedClientHelloRequired,
                Error::RejectedEch(RejectedEch { retry_configs }),
            ));
        }
        cx.common.start_traffic();

        if let Some(group) = cx.common.negotiated_key_exchange_group() {
            st.config
                .resumption
                .store
                .set_kx_hint(st.server_name.clone(), group.name());
        }

        // Post-handshake authentications each continue the transcript
        // through our Finished (RFC 9846 §4.5); keep it only if offered.
        let post_handshake_transcript = cx
            .data
            .offered_post_handshake_auth
            .then(|| st.transcript.fork());

        Ok(Box::new(ExpectTraffic {
            config: st.config,
            server_name: st.server_name,
            suite: st.suite,
            // Resumption secrets derive from the transcript through our Finished.
            final_hash: st.transcript.current_hash(),
            post_handshake_transcript,
            post_handshake_requests_since_data: 0,
            key_schedule,
            _cert_verified: st.cert_verified,
            _sig_verified: st.sig_verified,
            _fin_verified: fin,
        }))
    }
}

struct ExpectTraffic {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    suite: &'static Tls13CipherSuite,
    final_hash: crate::crypto::hash::Output,
    /// The transcript through our Finished, when we offered
    /// `post_handshake_auth`.
    post_handshake_transcript: Option<HandshakeHash>,
    /// CertificateRequests answered since the server last sent
    /// application data; see [`MAX_POST_HANDSHAKE_AUTH_REQUESTS`].
    post_handshake_requests_since_data: u8,
    key_schedule: KeyScheduleTraffic,
    _cert_verified: ServerCertVerified,
    _sig_verified: HandshakeSignatureValid,
    _fin_verified: FinishedMessageVerified,
}

impl ExpectTraffic {
    fn handle_new_ticket_tls13(
        &mut self,
        cx: &mut ClientContext<'_>,
        nst: &NewSessionTicketPayloadTls13,
    ) -> Result<(), Error> {
        // RFC 9846 §4.3: a recognised extension that may not appear in a
        // NewSessionTicket is illegal_parameter; unrecognised ones are
        // ignored (§4.7.1).
        if first_disallowed(
            nst.exts.unknown.iter().copied(),
            Tls13Message::NewSessionTicket,
        )
        .is_some()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::DisallowedNewSessionTicketExtension,
            ));
        }

        // RFC 9846 §4.7.1: a lifetime of zero means the ticket must be
        // discarded immediately.
        if nst.lifetime == 0 {
            debug!("Discarding NewSessionTicket with zero lifetime");
            return Ok(());
        }

        let secret = self
            .key_schedule
            .resumption_master_secret_and_derive_ticket_psk(self.final_hash.as_ref(), &nst.nonce.0);
        let now = self.config.current_time()?;
        if cx
            .data
            .delegated_credential_expiry
            .is_some_and(|expiry| now >= expiry)
        {
            debug!("Discarding NewSessionTicket after delegated credential expiry");
            return Ok(());
        }

        let server_cert_chain = cx.common.peer_certificates.clone().unwrap_or_default();

        let value = persist::Tls13ClientSessionValue::new(
            self.suite,
            nst.ticket.0.clone(),
            &secret,
            Arc::new(server_cert_chain),
            now,
            nst.lifetime,
            nst.age_add,
            nst.exts.max_early_data_size.unwrap_or(0),
        )
        .with_external_psk(cx.common.external_psk_binding())
        .with_delegated_credential_expiry(cx.data.delegated_credential_expiry);
        self.config
            .resumption
            .store
            .insert_tls13_ticket(self.server_name.clone(), value);
        cx.data.tls13_tickets_received = cx.data.tls13_tickets_received.saturating_add(1);
        Ok(())
    }

    /// Answers a post-handshake CertificateRequest (RFC 9846 §4.7.2) at
    /// once with Certificate, CertificateVerify (when we have a usable
    /// certificate) and Finished, consecutively.
    fn handle_post_handshake_certificate_request(
        &mut self,
        cx: &mut ClientContext<'_>,
        certreq: &CertificateRequestPayloadTls13,
        m: &Message<'_>,
    ) -> Result<(), Error> {
        let Some(base) = &self.post_handshake_transcript else {
            // RFC 9846 §4.7.2: without our post_handshake_auth offer this
            // is unexpected_message.
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnexpectedMessage,
                PeerMisbehaved::UnsolicitedPostHandshakeCertificateRequest,
            ));
        };
        // RFC 9846 §4.4.2: a post-handshake CertificateRequest needs a
        // non-empty context, which makes each answer distinct.
        if certreq.context.0.is_empty() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::IllegalCertificateRequestContext,
            ));
        }
        let sigschemes = certificate_request_sigschemes(cx.common, certreq)?;

        // RFC 9846 §6.1: nothing follows our close_notify.
        if cx.common.has_sent_close_notify() {
            debug!("Ignoring CertificateRequest after our close_notify");
            return Ok(());
        }

        // Each answer costs a signature: refuse a server that keeps
        // asking without sending application data in between.
        self.post_handshake_requests_since_data =
            self.post_handshake_requests_since_data.saturating_add(1);
        if self.post_handshake_requests_since_data > MAX_POST_HANDSHAKE_AUTH_REQUESTS {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnexpectedMessage,
                PeerMisbehaved::TooManyPostHandshakeCertificateRequests,
            ));
        }

        // Handshake Context: ClientHello ... client Finished +
        // CertificateRequest; earlier post-handshake exchanges are not
        // included (RFC 9846 §4.5).
        let mut transcript = base.fork();
        transcript.add_message(m);

        let client_auth = ClientAuthDetails::resolve(
            &*self.config.client_auth_cert_resolver,
            certreq.extensions.authorities.as_deref(),
            None,
            &sigschemes,
            Some(certreq.context.0.clone()),
        );
        let compression = certreq
            .extensions
            .certificate_compression
            .clone()
            .unwrap_or_default();
        match client_auth {
            ClientAuthDetails::Empty { auth_context_tls13 } => {
                emit_certificate_tls13(
                    &mut transcript,
                    &self.config,
                    None,
                    auth_context_tls13,
                    &compression,
                    cx.common,
                );
            }
            ClientAuthDetails::Verify {
                certkey,
                signer,
                auth_context_tls13,
            } => {
                emit_certificate_tls13(
                    &mut transcript,
                    &self.config,
                    Some(&certkey),
                    auth_context_tls13,
                    &compression,
                    cx.common,
                );
                emit_certverify_tls13(&mut transcript, &*signer, cx.common)?;
            }
        }
        let verify_data = self
            .key_schedule
            .sign_post_handshake_client_finish(transcript.current_hash().as_ref());
        emit_finished_tls13(&mut transcript, &verify_data, cx.common);
        cx.data.post_handshake_auth_responses =
            cx.data.post_handshake_auth_responses.saturating_add(1);
        Ok(())
    }

    fn handle_key_update(
        &mut self,
        common: &mut CommonState,
        request: KeyUpdateRequest,
    ) -> Result<(), Error> {
        match request {
            KeyUpdateRequest::UpdateNotRequested | KeyUpdateRequest::UpdateRequested => {
                // Our response, if one is owed, is sent once this flight is
                // processed (`ConnectionCore::maybe_send_key_update`).
                common.received_key_update(request, MAX_KEY_UPDATE_REQUESTS)?;
            }
            _ => {
                return Err(common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    crate::error::InvalidMessage::InvalidKeyUpdate,
                ));
            }
        }
        self.key_schedule.update_decrypter(common);
        Ok(())
    }
}

impl State<ClientConnectionData> for ExpectTraffic {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        match m.payload {
            MessagePayload::ApplicationData(payload) => {
                cx.common.received_key_update_requests = 0;
                self.post_handshake_requests_since_data = 0;
                cx.common.take_received_plaintext(payload);
            }
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::NewSessionTicketTls13(ref nst)),
                ..
            } => self.handle_new_ticket_tls13(cx, nst)?,
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::KeyUpdate(request)),
                ..
            } => self.handle_key_update(cx.common, request)?,
            MessagePayload::Handshake {
                parsed:
                    HandshakeMessagePayload(HandshakePayload::CertificateRequestTls13(ref certreq)),
                ..
            } => self.handle_post_handshake_certificate_request(cx, certreq, &m)?,
            payload => {
                return Err(crate::check::inappropriate_handshake_message(
                    &payload,
                    &[ContentType::ApplicationData, ContentType::Handshake],
                    &[
                        HandshakeType::NewSessionTicket,
                        HandshakeType::KeyUpdate,
                        HandshakeType::CertificateRequest,
                    ],
                ));
            }
        }
        Ok(self)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.key_schedule
            .export_keying_material(output, label, context)
    }

    fn extract_secrets(&self) -> Result<PartiallyExtractedSecrets, Error> {
        self.key_schedule.extract_secrets(Side::Client)
    }

    fn send_key_update(
        &mut self,
        common: &mut CommonState,
        request: KeyUpdateRequest,
    ) -> Result<(), Error> {
        common.send_key_update(request);
        self.key_schedule.update_encrypter_and_notify(common);
        Ok(())
    }
}

#[allow(dead_code)]
fn unused(_: NextState) {
    warning!("");
}
