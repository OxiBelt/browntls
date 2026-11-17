//! The end of the TLS 1.3 client handshake and what follows it: the server
//! Finished, our closing flight, and post-handshake messages (RFC 8446 §4.4.4,
//! §4.6).

use alloc::boxed::Box;
use alloc::vec::Vec;

use browntls_pki::ServerName;

use super::super::ClientConfig;
use super::super::client_conn::ClientConnectionData;
use super::super::common::ClientAuthDetails;
use super::super::hs::{ClientContext, NextStateOrError};
use super::{certificate_request_sigschemes, construct_client_verify_message};
use crate::common_state::{CommonState, ConnectionRandoms, Side};
use crate::conn::State;
use crate::crypto::hmac;
use crate::ct::constant_time_eq;
use crate::ech::{EchStatus, RejectedEch};
use crate::enums::{
    AlertDescription, CertificateCompressionAlgorithm, ContentType, HandshakeType, ProtocolVersion,
};
use crate::error::{Error, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::debug;
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::codec::Codec;
use crate::msgs::enums::KeyUpdateRequest;
use crate::msgs::handshake::{
    CertificatePayloadTls13, CertificateRequestPayloadTls13, HandshakeMessagePayload,
    HandshakePayload, NewSessionTicketPayloadTls13,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::sign::{CertifiedKey, Signer};
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::extensions::{Tls13Message, first_disallowed};
use crate::tls13::key_schedule::{KeyScheduleHandshake, KeyScheduleTraffic};
use crate::verify::{
    DigitallySignedStruct, FinishedMessageVerified, HandshakeSignatureValid, ServerCertVerified,
};

/// How many `update_requested` KeyUpdates we tolerate without sending data.
const MAX_KEY_UPDATE_REQUESTS: u8 = 8;

/// How many post-handshake CertificateRequests we answer while the server
/// sends no application data: each answer costs a signature, so this is a
/// local resource bound, not an RFC 9846 rule.
const MAX_POST_HANDSHAKE_AUTH_REQUESTS: u8 = 8;

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

pub(super) struct ExpectFinished {
    pub(super) config: Arc<ClientConfig>,
    pub(super) server_name: ServerName<'static>,
    pub(super) randoms: ConnectionRandoms,
    pub(super) suite: &'static Tls13CipherSuite,
    pub(super) transcript: HandshakeHash,
    pub(super) key_schedule: KeyScheduleHandshake,
    pub(super) client_auth: Option<ClientAuthDetails>,
    /// The compression algorithms the server's CertificateRequest accepts
    /// for our Certificate (RFC 8879 §3); empty when it named none.
    pub(super) client_cert_compression: Vec<CertificateCompressionAlgorithm>,
    pub(super) cert_verified: ServerCertVerified,
    pub(super) sig_verified: HandshakeSignatureValid,
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
        // QUIC clients MUST NOT send it (RFC 9001 §8.3).
        if cx.common.early_traffic && cx.common.is_quic() {
            cx.common.early_traffic = false;
            cx.data.early_data.finished();
        } else if cx.common.early_traffic {
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
    /// CertificateRequests answered since the server last sent non-empty
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

        // RFC 9001 §4.6.1: on QUIC, early_data in a ticket carries the
        // sentinel 0xffffffff; any other value is a QUIC PROTOCOL_VIOLATION,
        // which is not a TLS alert.
        if cx.common.is_quic()
            && nst
                .exts
                .max_early_data_size
                .is_some_and(|size| size != u32::MAX)
        {
            return Err(PeerMisbehaved::InvalidMaxEarlyDataSize.into());
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

        let mut value = persist::Tls13ClientSessionValue::new(
            self.suite,
            nst.ticket.0.clone(),
            &secret,
            Arc::new(server_cert_chain),
            &self.config.session_binding(),
            now,
            nst.lifetime,
            nst.age_add,
            nst.exts.max_early_data_size.unwrap_or(0),
        )
        .with_external_psk(
            cx.common
                .external_psk_binding(&self.config.provider.cipher_suites, &secret)?,
        )
        .with_delegated_credential_expiry(cx.data.delegated_credential_expiry);
        if let Some(params) = cx.common.quic.as_ref().and_then(|q| q.peer_params.as_ref()) {
            value.set_quic_params(params);
        }
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
            // RFC 9001 §4.4: in QUIC this is a PROTOCOL_VIOLATION, which
            // has no TLS alert.
            if cx.common.is_quic() {
                return Err(PeerMisbehaved::UnsolicitedPostHandshakeCertificateRequest.into());
            }
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
        // asking without sending (non-empty) application data in between.
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
                // A zero-length record (RFC 9846 §5.1 allows them) gives
                // the application nothing, so it does not renew the
                // request budgets.
                if !payload.bytes().is_empty() {
                    cx.common.received_key_update_requests = 0;
                    self.post_handshake_requests_since_data = 0;
                }
                cx.common.take_received_plaintext(payload);
            }
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::NewSessionTicketTls13(ref nst)),
                ..
            } => self.handle_new_ticket_tls13(cx, nst)?,
            // RFC 9001 §6: QUIC has its own key update; a TLS KeyUpdate is
            // a connection error equivalent to unexpected_message.
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::KeyUpdate(_)),
                ..
            } if cx.common.is_quic() => {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::UnexpectedMessage,
                    PeerMisbehaved::KeyUpdateReceivedInQuicConnection,
                ));
            }
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

    fn received_application_data(&mut self, common: &mut CommonState) {
        common.received_key_update_requests = 0;
        self.post_handshake_requests_since_data = 0;
    }
}
