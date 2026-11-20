//! The TLS 1.3 client handshake after the ServerHello (RFC 8446 §4).

use alloc::boxed::Box;
use alloc::vec::Vec;

use browntls_pki::ServerName;

use super::client_conn::ClientConnectionData;
use super::common::ClientHelloDetails;
use super::hs::{ClientContext, NextState, NextStateOrError, OfferedKeyShare};
use super::{ClientConfig, hs};
use crate::common_state::{CommonState, ConnectionRandoms, HandshakeKind, KxState};
use crate::conn::State;
use crate::delegated_credential;
use crate::ech::EchStatus;
use crate::enums::{AlertDescription, HandshakeType, ProtocolVersion};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::log::{debug, trace, warning};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::handshake::{
    CertificateRequestPayloadTls13, HandshakeMessagePayload, HandshakePayload, PresharedKeyBinder,
    ServerExtensions, ServerHelloPayload,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::psk::{ExternalPsk, OfferedPsk};
use crate::sync::Arc;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::extensions::{Tls13Message, first_disallowed};
use crate::tls13::key_schedule::{KeyScheduleEarly, KeyScheduleHandshake, KeySchedulePreHandshake};
use crate::verify::{HandshakeSignatureValid, ServerCertVerified};

mod finished;
mod server_auth;

use finished::ExpectFinished;
use server_auth::ExpectCertificateOrCertReq;

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

/// Sends the middlebox-compatibility ChangeCipherSpec once (RFC 8446
/// appendix D.4).
///
/// Never on QUIC, which has no such record (RFC 9001 §8.4).
pub(super) fn emit_fake_ccs(sent: &mut bool, common: &mut CommonState) {
    if *sent || common.is_quic() {
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
                    cx.common.external_psk = resuming_session.as_ref().and_then(|session| {
                        let binding = session.external_psk()?;
                        config
                            .external_psks
                            .iter()
                            .find(|psk| {
                                binding.matches(
                                    psk,
                                    &config.provider.cipher_suites,
                                    session.secret(),
                                )
                            })
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
            if let Some(quic) = cx.common.quic.as_mut() {
                quic.clear_early_secret();
            }
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

        if let Some(quic) = &mut cx.common.quic {
            // RFC 9001 §8.2: the server MUST send its transport parameters.
            let Some(params) = &exts.transport_parameters else {
                return Err(cx
                    .common
                    .missing_extension(PeerMisbehaved::MissingQuicTransportParameters));
            };
            quic.peer_params = Some(params.bytes().to_vec());
            // RFC 9001 §8.1: with ALPN offered, a server that selects no
            // protocol ends the connection (no_application_protocol).
            if !self.alpn_protocols.is_empty() && cx.common.alpn_protocol.is_none() {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::NoApplicationProtocol,
                    Error::NoApplicationProtocol,
                ));
            }
        }
        hs::process_cert_type_extensions(
            cx.common,
            &self.config,
            exts.client_certificate_type,
            exts.server_certificate_type,
        )?;
        // RFC 8449 §4: in TLS 1.3 the server's limit comes here. RFC 9149's
        // `expected_count` is a hint only and needs no action.
        hs::process_record_size_limit(cx.common, &self.hello, exts.record_size_limit, true)?;
        crate::external_binding::handshake::client_check(
            cx.common,
            self.config.external_binding.as_ref(),
            exts,
            true,
            cx.data.ech_status == EchStatus::Rejected,
        )?;

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
                    if let Some(quic) = cx.common.quic.as_mut() {
                        quic.clear_early_secret();
                    }
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
                    client_cert_extensions: Default::default(),
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
                    client_cert_extensions: Default::default(),
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

#[allow(dead_code)]
fn unused(_: NextState) {
    warning!("");
}
