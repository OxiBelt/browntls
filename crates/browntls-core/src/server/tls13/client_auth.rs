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
use crate::revocation::{CertificateEvidence, finish_or_pause};
use crate::server::common::{ClientCertAwaitingProof, client_revocation_enabled};
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
/// (`context`) and the client certificate verifier, which also gets the
/// OCSP responses and SCT lists stapled to the entries. Returns `None` for
/// an empty certificate list the verifier allows.
pub(super) fn check_client_certificate(
    common: &mut CommonState,
    config: &ServerConfig,
    certp: &CertificatePayloadTls13<'_>,
    context: &[u8],
) -> Result<Option<ClientCertAwaitingProof>, Error> {
    // RFC 9846 §4.4.2: the context echoes our request's. The message is
    // well formed, so a mismatch is illegal_parameter.
    if certp.context.0 != context {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::IllegalCertificateRequestContext,
        ));
    }
    // RFC 9846 §4.5.1: entry extensions must answer our CertificateRequest.
    // It asks for stapled responses and SCTs exactly when the verifier
    // evaluates revocation, and never for delegated credentials (RFC 9345
    // client credentials are not supported), nor for `transparency_info`
    // (RFC 9162 §6.1 defines no CT for client certificates).
    let evidence_requested = client_revocation_enabled(config);
    if certp.entries.iter().any(|e| {
        e.delegated_credential.is_some()
            || e.transparency_info.is_some()
            || (!evidence_requested && (e.status.is_some() || e.sct_list.is_some()))
    }) {
        return Err(common.send_fatal_alert(
            AlertDescription::UnsupportedExtension,
            PeerMisbehaved::UnsolicitedCertExtension,
        ));
    }

    // An empty response is no response (`OCSPResponse<1..2^24-1>`).
    let ocsp = certp.ocsp_responses();
    let scts = certp.sct_lists();
    let evidence: Vec<CertificateEvidence<'_>> = ocsp
        .iter()
        .zip(&scts)
        .map(|(ocsp, scts)| CertificateEvidence {
            ocsp: ocsp.as_deref().filter(|response| !response.is_empty()),
            scts: scts.as_deref(),
            transparency_info: None,
        })
        .collect();
    let client_cert = certp.clone().into_certificate_chain().into_owned();

    if client_cert.0.is_empty() {
        // RFC 9846 §4.5: an empty Certificate is allowed unless we
        // require one, which is certificate_required.
        if config.verifier.client_auth_mandatory() {
            return Err(common.send_fatal_alert(
                AlertDescription::CertificateRequired,
                Error::NoCertificatesPresented,
            ));
        }
        return Ok(None);
    }

    crate::server::common::verify_client_cert(common, config, client_cert, &evidence).map(Some)
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
    client_cert: ClientCertAwaitingProof,
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
            &self.client_cert.chain,
            &self.offered_sigschemes,
            sig,
        )?;

        trace!("client CertificateVerify OK");
        self.transcript.add_message(&m);

        // The client holds the key: a status lookup, if the verifier needs
        // one, may start now. Its Finished is read once that completes.
        let st = *self;
        let ClientCertAwaitingProof { chain, revocation } = st.client_cert;
        finish_or_pause(cx, revocation, move |cx, status| {
            cx.common.peer_certificates = Some(chain);
            cx.common.peer_revocation_status = status;
            Ok(Box::new(ExpectFinished {
                config: st.config,
                transcript: st.transcript,
                suite: st.suite,
                key_schedule: st.key_schedule,
                send_tickets: st.send_tickets,
            }))
        })
    }
}
