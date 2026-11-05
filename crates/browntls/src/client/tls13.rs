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
use crate::enums::{AlertDescription, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::{HandshakeHash, HandshakeHashBuffer};
use crate::log::{debug, trace, warning};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::enums::KeyUpdateRequest;
use crate::msgs::handshake::{
    CertificatePayloadTls13, HandshakeMessagePayload, HandshakePayload, MAX_CERTIFICATE_SIZE_LIMIT,
    NewSessionTicketPayloadTls13, PresharedKeyBinder, ServerExtensions, ServerHelloPayload,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist::{self, Retrieved};
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

/// Computes the real PSK binder (RFC 8446 §4.2.11.2) and writes it into the
/// ClientHello, returning the early key schedule for the offered PSK.
pub(super) fn fill_in_psk_binder(
    resuming: &Retrieved<&persist::Tls13ClientSessionValue>,
    transcript: &HandshakeHashBuffer,
    hmp: &mut HandshakeMessagePayload<'_>,
) -> KeyScheduleEarly {
    let suite = resuming.suite();
    let binder_plaintext = hmp.encoding_for_binder_signing();
    let handshake_hash = transcript.hash_given(suite.common.hash_provider, &binder_plaintext);

    let key_schedule = KeyScheduleEarly::new(suite, resuming.secret());
    let real_binder =
        key_schedule.resumption_psk_binder_key_and_sign_verify_data(handshake_hash.as_ref());

    if let HandshakePayload::ClientHello(ch) = &mut hmp.0
        && let Some(psk) = &mut ch.extensions.preshared_key
        && let Some(binder) = psk.binders.first_mut()
    {
        *binder = PresharedKeyBinder::new(real_binder.as_ref().to_vec());
    }
    key_schedule
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
    early_key_schedule: Option<KeyScheduleEarly>,
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

    let key_schedule_pre = match (
        server_hello.extensions.pre_shared_key,
        early_key_schedule,
        &resuming_session,
    ) {
        (Some(selected), Some(early), Some(resuming)) => {
            // RFC 8446 §4.2.11: we offered exactly one identity.
            if selected != 0 {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SelectedInvalidPsk,
                ));
            }
            if suite.can_resume_from(resuming.suite()).is_none() {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::ResumptionOfferedWithIncompatibleCipherSuite,
                ));
            }
            // Early data was encrypted with the ticket's suite; the server
            // may not switch suites and still read it.
            if cx.data.early_data.is_enabled()
                && resuming.suite().common.suite != suite.common.suite
            {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::EarlyDataOfferedWithVariedCipherSuite,
                ));
            }
            debug!("Resuming using PSK");
            cx.common.handshake_kind = Some(HandshakeKind::Resumed);
            early.into_pre_handshake()
        }
        (Some(_), ..) => {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SelectedUnofferedPsk,
            ));
        }
        (None, ..) => {
            debug!("Not resuming");
            // Any early data went out under a PSK the server did not take.
            if cx.data.early_data.is_enabled() {
                cx.data.early_data.rejected();
            }
            cx.common.early_traffic = false;
            resuming_session = None;
            KeySchedulePreHandshake::new(suite)
        }
    };

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

    Ok(Box::new(ExpectEncryptedExtensions {
        config,
        resuming_session,
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

        match self.resuming_session {
            Some(resuming) => {
                // RFC 8446 §4.2.10: the early_data acknowledgement decides the
                // fate of what we sent; without it we switch to handshake keys.
                let was_early_traffic = cx.common.early_traffic;
                if was_early_traffic {
                    match exts.early_data {
                        Some(()) => cx.data.early_data.accepted(),
                        None => {
                            cx.data.early_data.rejected();
                            cx.common.early_traffic = false;
                        }
                    }
                }
                if was_early_traffic && !cx.common.early_traffic {
                    self.key_schedule.set_handshake_encrypter(cx.common);
                }

                // The server authenticated through the PSK; reinstate the
                // certificates seen when the session was established.
                cx.common.peer_certificates = Some(resuming.server_cert_chain().clone());
                Ok(Box::new(ExpectFinished {
                    config: self.config,
                    server_name: self.server_name,
                    randoms: self.randoms,
                    suite: self.suite,
                    transcript: self.transcript,
                    key_schedule: self.key_schedule,
                    client_auth: None,
                    cert_verified: ServerCertVerified::assertion(),
                    sig_verified: HandshakeSignatureValid::assertion(),
                }))
            }
            None => {
                // RFC 8446 §4.2.10: early_data here requires a resumed session.
                if exts.early_data.is_some() {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::UnsupportedExtension,
                        PeerMisbehaved::EarlyDataExtensionWithoutResumption,
                    ));
                }
                Ok(Box::new(ExpectCertificateOrCertReq {
                    config: self.config,
                    server_name: self.server_name,
                    randoms: self.randoms,
                    suite: self.suite,
                    transcript: self.transcript,
                    key_schedule: self.key_schedule,
                    offered_sigschemes: self.hello.offered_sigschemes,
                }))
            }
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

        // RFC 9846 §4.3: a recognised extension that may not appear in a
        // CertificateRequest is illegal_parameter.
        if first_disallowed(
            certreq.extensions.unknown.iter().copied(),
            Tls13Message::CertificateRequest,
        )
        .is_some()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::DisallowedCertificateRequestExtension,
            ));
        }

        // RFC 9846 §4.4.2: signature_algorithms MUST be specified; its
        // absence is missing_extension (§6.2).
        let Some(sigschemes) = &certreq.extensions.signature_algorithms else {
            return Err(cx.common.send_fatal_alert(
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
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::NoCertificateRequestSignatureSchemesInCommon,
            ));
        }

        let client_auth = ClientAuthDetails::resolve(
            &*self.config.client_auth_cert_resolver,
            certreq.extensions.authorities.as_deref(),
            None,
            &compat_sigschemes,
            Some(certreq.context.0.clone()),
        );

        Ok(Box::new(ExpectCertificate {
            config: self.config,
            server_name: self.server_name,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            client_auth: Some(client_auth),
            offered_sigschemes: self.offered_sigschemes,
        }))
    }
}

struct ExpectCertificate {
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    transcript: HandshakeHash,
    key_schedule: KeyScheduleHandshake,
    client_auth: Option<ClientAuthDetails>,
    offered_sigschemes: Vec<crate::enums::SignatureScheme>,
}

impl ExpectCertificate {
    /// Expands a CompressedCertificate (RFC 8879 §4) with a decompressor we offered.
    fn decompress(
        &self,
        cx: &mut ClientContext<'_>,
        m: &Message<'_>,
    ) -> Result<CertificatePayloadTls13<'static>, Error> {
        let compressed = require_handshake_msg!(
            m,
            HandshakeType::CompressedCertificate,
            HandshakePayload::CompressedCertificate
        )?;
        let Some(decompressor) = self
            .config
            .cert_decompressors
            .iter()
            .find(|d| d.algorithm() == compressed.alg)
        else {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SelectedUnofferedCertCompression,
            ));
        };
        let len = compressed.uncompressed_len as usize;
        if len == 0 || len > MAX_CERTIFICATE_SIZE_LIMIT {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::BadCertificate,
                PeerMisbehaved::InvalidCertCompression,
            ));
        }
        let mut output = alloc::vec![0u8; len];
        if decompressor
            .decompress(compressed.compressed.0.bytes(), &mut output)
            .is_err()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::BadCertificate,
                PeerMisbehaved::InvalidCertCompression,
            ));
        }
        CertificatePayloadTls13::read_bytes(&output)
            .map(CertificatePayloadTls13::into_owned)
            .map_err(|_| {
                cx.common.send_fatal_alert(
                    AlertDescription::BadCertificate,
                    PeerMisbehaved::InvalidCertCompression,
                )
            })
    }
}

impl State<ClientConnectionData> for ExpectCertificate {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        let cert_chain: CertificatePayloadTls13<'static> = match &m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateTls13(chain)),
                ..
            } => chain.clone().into_owned(),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CompressedCertificate(..)),
                ..
            } => self.decompress(cx, &m)?,
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
            offered_sigschemes: self.offered_sigschemes,
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
    offered_sigschemes: Vec<crate::enums::SignatureScheme>,
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
        let sig_verified = self
            .config
            .verifier()
            .verify_tls13_signature(&message, end_entity, cert_verify)
            .map_err(|err| send_cert_verify_error_alert(cx.common, err))?;

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
            cert_verified,
            sig_verified,
        }))
    }
}

/// Picks the alert for a failed certificate or signature check.
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
    certkey: Option<&CertifiedKey>,
    auth_context: Option<Vec<u8>>,
    common: &mut CommonState,
) {
    let certs: &[browntls_pki::CertificateDer<'static>] =
        certkey.map(|ck| ck.cert.as_slice()).unwrap_or(&[]);
    let mut cert_payload = CertificatePayloadTls13::new(certs.iter(), None);
    cert_payload.context = PayloadU8::new(auth_context.unwrap_or_default());
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
        let fin = FinishedMessageVerified::assertion();
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
                    emit_certificate_tls13(&mut st.transcript, None, auth_context_tls13, cx.common);
                }
                ClientAuthDetails::Verify {
                    certkey,
                    signer,
                    auth_context_tls13,
                } => {
                    emit_certificate_tls13(
                        &mut st.transcript,
                        Some(&certkey),
                        auth_context_tls13,
                        cx.common,
                    );
                    emit_certverify_tls13(&mut st.transcript, &*signer, cx.common)?;
                }
            }
        }

        let verify_data = traffic_pending.sign_client_finish(st.transcript.current_hash().as_ref());
        emit_finished_tls13(&mut st.transcript, &verify_data, cx.common);

        let key_schedule = traffic_pending.into_traffic(cx.common);
        cx.common.start_traffic();

        if let Some(group) = cx.common.negotiated_key_exchange_group() {
            st.config
                .resumption
                .store
                .set_kx_hint(st.server_name.clone(), group.name());
        }

        Ok(Box::new(ExpectTraffic {
            config: st.config,
            server_name: st.server_name,
            suite: st.suite,
            // Resumption secrets derive from the transcript through our Finished.
            final_hash: st.transcript.current_hash(),
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
        );
        self.config
            .resumption
            .store
            .insert_tls13_ticket(self.server_name.clone(), value);
        cx.data.tls13_tickets_received = cx.data.tls13_tickets_received.saturating_add(1);
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
            payload => {
                return Err(crate::check::inappropriate_handshake_message(
                    &payload,
                    &[ContentType::ApplicationData, ContentType::Handshake],
                    &[HandshakeType::NewSessionTicket, HandshakeType::KeyUpdate],
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
