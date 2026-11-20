//! Client authentication in the TLS 1.3 server handshake: the client's
//! Certificate and CertificateVerify (RFC 8446 §4.4), with or without a
//! delegated credential (RFC 9345 §4.1.2).

use alloc::boxed::Box;
use alloc::vec::Vec;

use browntls_pki::UnixTime;

use super::traffic::ExpectFinished;
use crate::common_state::{CommonState, Side};
use crate::conn::State;
use crate::delegated_credential;
use crate::enums::{AlertDescription, ContentType, HandshakeType, SignatureScheme};
use crate::error::{Error, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace};
use crate::msgs::handshake::{CertificatePayloadTls13, HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{Message, MessagePayload};
use crate::revocation::{CertificateEvidence, finish_or_pause};
use crate::server::common::{
    ClientCertAwaitingProof, ValidatedCredential, client_revocation_enabled,
};
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
    // RFC 9345 §4.1.2: a delegated credential our CertificateRequest did
    // not ask for is unexpected_message; one on any entry but the end
    // entity's is illegal_parameter (the RFC allows ignoring it; we fail
    // closed).
    let delegated_credential = certp.end_entity_delegated_credential().cloned();
    if client_delegated_credential_schemes(config).is_none()
        && (delegated_credential.is_some() || certp.delegated_credential_on_non_end_entity())
    {
        return Err(common.send_fatal_alert(
            AlertDescription::UnexpectedMessage,
            PeerMisbehaved::UnsolicitedDelegatedCredential,
        ));
    }
    if certp.delegated_credential_on_non_end_entity() {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::DelegatedCredentialNotOnEndEntity,
        ));
    }
    // RFC 9846 §4.5.1: entry extensions must answer our CertificateRequest.
    // It asks for stapled responses and SCTs exactly when the verifier
    // evaluates revocation. RFC 9162 §6.1 defines no CT 2.0 for client
    // certificates.
    let evidence_requested = client_revocation_enabled(config);
    if certp.entries.iter().any(|e| {
        e.transparency_info.is_some()
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

    let mut client_cert =
        crate::server::common::verify_client_cert(common, config, client_cert, &evidence)?;
    client_cert.delegated_credential = delegated_credential;
    Ok(Some(client_cert))
}

/// Verifies a client CertificateVerify over `transcript` (RFC 9846 §4.5)
/// with a scheme from our CertificateRequest. When the client presented a
/// delegated credential, that is validated first (RFC 9345 §4.1.3) and its
/// key must have signed; it is returned with its expiry.
pub(super) fn check_client_certificate_verify(
    common: &mut CommonState,
    config: &ServerConfig,
    transcript: &HandshakeHash,
    client_cert: &ClientCertAwaitingProof,
    offered_sigschemes: &[SignatureScheme],
    sig: &DigitallySignedStruct,
) -> Result<(HandshakeSignatureValid, Option<ValidatedCredential>), Error> {
    if !offered_sigschemes.contains(&sig.scheme) {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
        ));
    }
    let handshake_hash = transcript.current_hash();
    let msg = crate::client::tls13::construct_client_verify_message(&handshake_hash);
    let end_entity = client_cert.chain.0.first().ok_or_else(|| {
        common.send_fatal_alert(
            AlertDescription::DecodeError,
            Error::NoCertificatesPresented,
        )
    })?;
    let Some(dc) = &client_cert.delegated_credential else {
        let verified = config
            .verifier
            .verify_tls13_signature(&msg, end_entity, sig)
            .map_err(|err| crate::client::tls13::send_cert_verify_error_alert(common, err))?;
        return Ok((verified, None));
    };

    // RFC 9345 §4.1.3: an invalid credential is illegal_parameter.
    let offered_dc_schemes = client_delegated_credential_schemes(config).unwrap_or_default();
    let presented = delegated_credential::Presented {
        side: Side::Client,
        end_entity,
        offered_dc_schemes: &offered_dc_schemes,
        offered_sig_schemes: offered_sigschemes,
        cert_verify_scheme: sig.scheme,
        now: config.current_time()?,
    };
    let expiry = delegated_credential::validate(dc, &presented, |message, dss| {
        config
            .verifier
            .verify_tls13_signature(message, end_entity, dss)
    })
    .map_err(|err| common.send_fatal_alert(AlertDescription::IllegalParameter, err))?;
    // Then the credential's key verifies CertificateVerify.
    let verified = config
        .verifier
        .verify_tls13_signature_with_delegated_key(&msg, &dc.credential.public_key, sig)
        .map_err(|err| crate::client::tls13::send_cert_verify_error_alert(common, err))?;
    Ok((verified, Some((dc.clone(), expiry))))
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

/// The schemes our CertificateRequest accepts for a client's delegated
/// credential (RFC 9345 §4.1.2), or `None` when it carries no
/// `delegated_credential` extension: those of [`client_auth_sigschemes`]
/// without `rsa_pss_rsae_*` (RFC 9345 §4 forbids `rsaEncryption`
/// credential keys), while `ServerConfig::enable_delegated_credentials`
/// is set and the verifier takes X.509 certificates.
pub(super) fn client_delegated_credential_schemes(
    config: &ServerConfig,
) -> Option<Vec<SignatureScheme>> {
    if !config.enable_delegated_credentials || config.verifier.requires_raw_public_keys() {
        return None;
    }
    let schemes: Vec<SignatureScheme> = client_auth_sigschemes(config)
        .into_iter()
        .filter(|scheme| delegated_credential::credential_scheme_allowed(*scheme))
        .collect();
    (!schemes.is_empty()).then_some(schemes)
}

/// Whether a client delegated credential that expires at `expiry` no
/// longer covers a handshake or an authentication completing now; this
/// sends the alert of RFC 9345 §4.1.3.
pub(super) fn check_client_credential_unexpired(
    common: &mut CommonState,
    config: &ServerConfig,
    expiry: Option<UnixTime>,
) -> Result<(), Error> {
    if let Some(expiry) = expiry
        && config.current_time()? >= expiry
    {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::DelegatedCredentialExpired,
        ));
    }
    Ok(())
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

        let (_sig_verified, credential): (HandshakeSignatureValid, _) =
            check_client_certificate_verify(
                cx.common,
                &self.config,
                &self.transcript,
                &self.client_cert,
                &self.offered_sigschemes,
                sig,
            )?;

        trace!("client CertificateVerify OK");
        self.transcript.add_message(&m);

        // The client holds the key: a status lookup, if the verifier needs
        // one, may start now. Its Finished is read once that completes.
        let st = *self;
        let ClientCertAwaitingProof {
            chain, revocation, ..
        } = st.client_cert;
        finish_or_pause(cx, revocation, move |cx, status| {
            let (credential, expiry) = credential.unzip();
            cx.data.client_delegated_credential = credential;
            cx.data.client_delegated_credential_expiry = expiry;
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
