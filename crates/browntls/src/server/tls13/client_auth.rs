//! Client authentication in the TLS 1.3 server handshake: the client's
//! Certificate and CertificateVerify (RFC 8446 §4.4).

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::traffic::ExpectFinished;
use crate::common_state::CommonState;
use crate::conn::State;
use crate::enums::{AlertDescription, ContentType, HandshakeType, SignatureScheme};
use crate::error::{Error, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace};
use crate::msgs::handshake::{CertificatePayloadTls13, HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{Message, MessagePayload};
use crate::server::hs::{NextStateOrError, ServerContext};
use crate::server::server_conn::{ServerConfig, ServerConnectionData};
use crate::sync::Arc;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::KeyScheduleTrafficWithClientFinishedPending;
use crate::verify::{DigitallySignedStruct, HandshakeSignatureValid};

pub(super) struct ExpectCertificate {
    pub(super) config: Arc<ServerConfig>,
    pub(super) transcript: HandshakeHash,
    pub(super) suite: &'static Tls13CipherSuite,
    pub(super) key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    pub(super) send_tickets: usize,
    pub(super) offered_sigschemes: Vec<SignatureScheme>,
}

impl State<ServerConnectionData> for ExpectCertificate {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        // RFC 8879 §4: the client may compress with an algorithm that our
        // CertificateRequest offered.
        let certp: CertificatePayloadTls13<'static> = match &m.payload {
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

        let Some(client_cert) = check_client_certificate(cx.common, &self.config, &certp, &[])?
        else {
            debug!("client auth requested but no certificate supplied");
            return Ok(Box::new(ExpectFinished {
                config: self.config,
                transcript: self.transcript,
                suite: self.suite,
                key_schedule: self.key_schedule,
                send_tickets: self.send_tickets,
            }));
        };

        Ok(Box::new(ExpectCertificateVerify {
            config: self.config,
            transcript: self.transcript,
            suite: self.suite,
            key_schedule: self.key_schedule,
            client_cert,
            send_tickets: self.send_tickets,
            offered_sigschemes: self.offered_sigschemes,
        }))
    }
}

/// Checks a client Certificate message against the request it answers
/// (`context`) and the client certificate verifier. Returns `None` for an
/// empty certificate list the verifier allows.
pub(super) fn check_client_certificate(
    common: &mut CommonState,
    config: &ServerConfig,
    certp: &CertificatePayloadTls13<'_>,
    context: &[u8],
) -> Result<Option<crate::msgs::handshake::CertificateChain<'static>>, Error> {
    // RFC 9846 §4.4.2: the context echoes our request's. The message is
    // well formed, so a mismatch is illegal_parameter.
    if certp.context.0 != context {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::IllegalCertificateRequestContext,
        ));
    }
    // We never request stapled responses, SCTs or delegated credentials
    // (RFC 9345 client credentials are not supported) from clients.
    if certp
        .entries
        .iter()
        .any(|e| e.status.is_some() || e.sct_list.is_some() || e.delegated_credential.is_some())
    {
        return Err(common.send_fatal_alert(
            AlertDescription::UnsupportedExtension,
            PeerMisbehaved::UnsolicitedCertExtension,
        ));
    }

    let client_cert = certp.clone().into_certificate_chain().into_owned();

    let Some((end_entity, intermediates)) = client_cert.0.split_first() else {
        // RFC 9846 §4.5: an empty Certificate is allowed unless we
        // require one, which is certificate_required.
        if config.verifier.client_auth_mandatory() {
            return Err(common.send_fatal_alert(
                AlertDescription::CertificateRequired,
                Error::NoCertificatesPresented,
            ));
        }
        return Ok(None);
    };

    let now = config.current_time()?;
    config
        .verifier
        .verify_client_cert(end_entity, intermediates, now)
        .map_err(|err| crate::client::tls13::send_cert_path_error_alert(common, err))?;
    Ok(Some(client_cert))
}

/// Verifies a client CertificateVerify over `transcript` (RFC 9846 §4.5)
/// with a scheme from our CertificateRequest.
pub(super) fn check_client_certificate_verify(
    common: &mut CommonState,
    config: &ServerConfig,
    transcript: &HandshakeHash,
    client_cert: &crate::msgs::handshake::CertificateChain<'static>,
    offered_sigschemes: &[SignatureScheme],
    sig: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    if !offered_sigschemes.contains(&sig.scheme) {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
        ));
    }
    let handshake_hash = transcript.current_hash();
    let msg = crate::client::tls13::construct_client_verify_message(&handshake_hash);
    let end_entity = client_cert.0.first().ok_or_else(|| {
        common.send_fatal_alert(
            AlertDescription::DecodeError,
            Error::NoCertificatesPresented,
        )
    })?;
    config
        .verifier
        .verify_tls13_signature(&msg, end_entity, sig)
        .map_err(|err| crate::client::tls13::send_cert_verify_error_alert(common, err))
}

/// The TLS 1.3 signature schemes our CertificateRequest lists.
pub(super) fn client_auth_sigschemes(config: &ServerConfig) -> Vec<SignatureScheme> {
    config
        .verifier
        .supported_verify_schemes()
        .into_iter()
        .filter(SignatureScheme::supported_in_tls13)
        .collect()
}

struct ExpectCertificateVerify {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    client_cert: crate::msgs::handshake::CertificateChain<'static>,
    send_tickets: usize,
    offered_sigschemes: Vec<SignatureScheme>,
}

impl State<ServerConnectionData> for ExpectCertificateVerify {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        let sig = require_handshake_msg!(
            m,
            HandshakeType::CertificateVerify,
            HandshakePayload::CertificateVerify
        )?;

        let _sig_verified: HandshakeSignatureValid = check_client_certificate_verify(
            cx.common,
            &self.config,
            &self.transcript,
            &self.client_cert,
            &self.offered_sigschemes,
            sig,
        )?;

        trace!("client CertificateVerify OK");
        cx.common.peer_certificates = Some(self.client_cert);
        self.transcript.add_message(&m);

        Ok(Box::new(ExpectFinished {
            config: self.config,
            transcript: self.transcript,
            suite: self.suite,
            key_schedule: self.key_schedule,
            send_tickets: self.send_tickets,
        }))
    }
}
