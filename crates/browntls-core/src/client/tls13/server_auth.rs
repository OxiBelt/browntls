//! Server authentication in the TLS 1.3 client handshake: CertificateRequest,
//! Certificate and CertificateVerify (RFC 8446 §4.3.2, §4.4.2, §4.4.3).

use alloc::boxed::Box;
use alloc::vec::Vec;

use browntls_pki::ServerName;

use super::super::ClientConfig;
use super::super::client_conn::ClientConnectionData;
use super::super::common::{ClientAuthDetails, ClientCertificateExtensions, ServerCertDetails};
use super::super::hs::{ClientContext, NextStateOrError};
use super::finished::ExpectFinished;
use super::{
    certificate_request_sigschemes, construct_server_verify_message, delegated_credential_request,
    delegated_credential_schemes, send_cert_path_error_alert, send_cert_verify_error_alert,
};
use crate::common_state::{ConnectionRandoms, Side};
use crate::conn::State;
use crate::delegated_credential::{self, DelegatedCredential};
use crate::ech::EchStatus;
use crate::enums::{AlertDescription, CertificateCompressionAlgorithm, ContentType, HandshakeType};
use crate::error::{Error, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace};
use crate::msgs::handshake::{CertificatePayloadTls13, HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{Message, MessagePayload};
use crate::revocation::{RevocationCheck, finish_or_pause, require_local};
use crate::sync::Arc;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::KeyScheduleHandshake;

pub(super) struct ExpectCertificateOrCertReq {
    pub(super) config: Arc<ClientConfig>,
    pub(super) server_name: ServerName<'static>,
    pub(super) randoms: ConnectionRandoms,
    pub(super) suite: &'static Tls13CipherSuite,
    pub(super) transcript: HandshakeHash,
    pub(super) key_schedule: KeyScheduleHandshake,
    pub(super) offered_sigschemes: Vec<crate::enums::SignatureScheme>,
    /// Whether the ClientHello carried `transparency_info` (RFC 9162 §6.5).
    pub(super) offered_transparency_info: bool,
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
                client_cert_extensions: ClientCertificateExtensions::default(),
                client_cert_compression: Vec::new(),
                offered_sigschemes: self.offered_sigschemes,
                offered_transparency_info: self.offered_transparency_info,
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
                offered_transparency_info: self.offered_transparency_info,
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
    offered_transparency_info: bool,
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
                delegated_credential_request(&self.config, certreq),
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
            client_cert_extensions: (&certreq.extensions).into(),
            client_cert_compression,
            offered_sigschemes: self.offered_sigschemes,
            offered_transparency_info: self.offered_transparency_info,
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
    client_cert_extensions: ClientCertificateExtensions,
    /// The compression algorithms the server's CertificateRequest accepts
    /// for our Certificate (RFC 8879 §3); empty when it named none.
    client_cert_compression: Vec<CertificateCompressionAlgorithm>,
    offered_sigschemes: Vec<crate::enums::SignatureScheme>,
    offered_transparency_info: bool,
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
        // RFC 9846 §4.5.1: CertificateEntry extensions must correspond to
        // our offer. OCSP was offered; SCTs are offered with revocation.
        if !self.config.revocation_enabled()
            && cert_chain.entries.iter().any(|e| e.sct_list.is_some())
        {
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

        // RFC 9162 §6.5: only on the end entity's entry, if offered.
        let transparency_info = super::super::transparency::tls13_end_entity_list(
            cx.common,
            self.offered_transparency_info,
            &cert_chain,
        )?;

        let server_cert = ServerCertDetails {
            ocsp: cert_chain.ocsp_responses(),
            scts: cert_chain.sct_lists(),
            transparency_info,
            cert_chain: cert_chain.into_certificate_chain().into_owned(),
        };

        Ok(Box::new(ExpectCertificateVerify {
            config: self.config,
            server_name: self.server_name,
            randoms: self.randoms,
            suite: self.suite,
            transcript: self.transcript,
            key_schedule: self.key_schedule,
            server_cert,
            client_auth: self.client_auth,
            client_cert_extensions: self.client_cert_extensions,
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
    client_cert_extensions: ClientCertificateExtensions,
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
        let identity = cx.data.certificate_identity(&self.server_name);
        let verification = self
            .config
            .verifier()
            .verify_server_cert_with_identity(
                end_entity,
                intermediates,
                identity,
                &self.server_cert.evidence(),
                now,
                true,
            )
            .map_err(|err| send_cert_path_error_alert(cx.common, err))?;
        let matched_identity = if cx.data.ech_status == EchStatus::Rejected {
            None
        } else {
            identity
                .matched_reference(verification.matched_reference)
                .map_err(|err| send_cert_path_error_alert(cx.common, err))?
        };
        let transparency_status = verification.transparency;
        let check = verification.revocation;

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
        self.transcript.add_message(&m);

        // An outer ECH handshake only authenticates the rejection. Avoid an
        // outbound lookup as a side effect of that fallback.
        let check = if cx.data.ech_status == EchStatus::Rejected {
            RevocationCheck::Complete(
                require_local(check).map_err(|err| send_cert_path_error_alert(cx.common, err))?,
            )
        } else {
            check
        };
        finish_or_pause(cx, check, move |cx, status| {
            cx.data.delegated_credential = self.delegated_credential;
            cx.data.delegated_credential_expiry = delegated_credential_expiry;
            cx.common.peer_certificates = Some(self.server_cert.cert_chain);
            cx.common.matched_service_identity = matched_identity;
            cx.common.peer_revocation_status = status;
            cx.data.transparency.info = self.server_cert.transparency_info;
            cx.data.transparency.status = transparency_status;
            Ok(Box::new(ExpectFinished {
                config: self.config,
                server_name: self.server_name,
                randoms: self.randoms,
                suite: self.suite,
                transcript: self.transcript,
                key_schedule: self.key_schedule,
                client_auth: self.client_auth,
                client_cert_extensions: self.client_cert_extensions,
                client_cert_compression: self.client_cert_compression,
                cert_verified: crate::verify::ServerCertVerified::assertion(),
                sig_verified,
            }))
        })
    }
}
