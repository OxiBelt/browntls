//! The end of the TLS 1.3 server handshake and the connection after it: the
//! client's Finished, then application data, KeyUpdate and post-handshake
//! client authentication.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::client_auth::{
    check_client_certificate, check_client_certificate_verify, check_client_credential_unexpired,
    client_auth_sigschemes,
};
use super::flight::certificate_request_message;
use super::ticket::emit_ticket;
use crate::common_state::{CommonState, Side};
use crate::conn::State;
use crate::ct::constant_time_eq;
use crate::enums::{AlertDescription, ContentType, HandshakeType, SignatureScheme};
use crate::error::{Error, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace};
use crate::msgs::enums::KeyUpdateRequest;
use crate::msgs::handshake::CertificateChain;
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload};
use crate::msgs::message::{Message, MessagePayload};
use crate::revocation::{RevocationCheck, RevocationStatus};
use crate::server::common::{
    ClientCertAwaitingProof, ValidatedCredential, client_revocation_enabled,
};
use crate::server::hs::{NextStateOrError, ServerContext};
use crate::server::server_conn::{PostHandshakeAuthStatus, ServerConfig, ServerConnectionData};
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::{KeyScheduleTraffic, KeyScheduleTrafficWithClientFinishedPending};
use crate::verify::FinishedMessageVerified;

/// How many `update_requested` KeyUpdates we tolerate without sending data.
const MAX_KEY_UPDATE_REQUESTS: u8 = 8;

pub(super) struct ExpectFinished {
    pub(super) config: Arc<ServerConfig>,
    pub(super) transcript: HandshakeHash,
    pub(super) suite: &'static Tls13CipherSuite,
    pub(super) key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    pub(super) send_tickets: usize,
}

impl State<ServerConnectionData> for ExpectFinished {
    fn handle(self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        let handshake_hash = st.transcript.current_hash();
        let expect_verify_data = st.key_schedule.sign_client_finish(handshake_hash.as_ref());
        if !constant_time_eq(expect_verify_data.as_ref(), finished.bytes()) {
            return Err(cx
                .common
                .send_fatal_alert(AlertDescription::DecryptError, Error::DecryptError));
        }
        // A client credential that expired while the handshake, or the
        // resumption of a session it authenticated, was under way.
        check_client_credential_unexpired(
            cx.common,
            &st.config,
            cx.data.client_delegated_credential_expiry,
        )?;
        let fin = FinishedMessageVerified::assertion();
        // The client has proven it holds the external PSK, if one is in use;
        // tickets issued below record it.
        cx.common.external_psk_confirmed = true;

        st.transcript.add_message(&m);
        let key_schedule = st.key_schedule.into_traffic(cx.common);

        // A ticket would let the client resume its certificate identity
        // without a fresh revocation evaluation.
        for _ in 0..st.send_tickets {
            emit_ticket(&st.transcript, st.suite, cx, &key_schedule, &st.config)?;
        }

        cx.common.start_traffic();

        // Post-handshake authentications each continue the transcript
        // through the client Finished (RFC 9846 §4.5).
        let post_handshake_auth = cx
            .data
            .post_handshake_auth_offered
            .then(|| PostHandshakeAuth {
                config: st.config.clone(),
                transcript: st.transcript.fork(),
                requests_sent: 0,
                pending: None,
            });

        Ok(Box::new(ExpectTraffic {
            key_schedule,
            post_handshake_auth,
            _fin_verified: fin,
        }))
    }
}

struct ExpectTraffic {
    key_schedule: KeyScheduleTraffic,
    /// Present when the client offered `post_handshake_auth`.
    post_handshake_auth: Option<PostHandshakeAuth>,
    _fin_verified: FinishedMessageVerified,
}

/// Post-handshake client authentication (RFC 9846 §4.7.2) state.
struct PostHandshakeAuth {
    config: Arc<ServerConfig>,
    /// The transcript through the client Finished.
    transcript: HandshakeHash,
    /// How many CertificateRequests we sent, for unique contexts.
    requests_sent: u64,
    /// The request awaiting its answer; one at a time.
    pending: Option<PendingClientAuth>,
}

/// One outstanding post-handshake CertificateRequest.
struct PendingClientAuth {
    context: Vec<u8>,
    /// The transcript through the client Finished, then this request and
    /// the answer so far.
    transcript: HandshakeHash,
    offered_sigschemes: Vec<SignatureScheme>,
    stage: ClientAuthStage,
}

/// The message the answer to a post-handshake CertificateRequest needs next.
enum ClientAuthStage {
    Certificate,
    CertificateVerify(ClientCertAwaitingProof),
    /// The proof verified and `CommonState::pending_revocation` holds the
    /// status lookup; no message is read until it resolves
    /// ([`PostHandshakeAuth::resume_revocation`]).
    Revocation(ProvenClient),
    /// The identity and its revocation status, or `None` when the client
    /// declined. Neither is reported before the Finished verifies.
    Finished(Option<(ProvenClient, Option<RevocationStatus>)>),
}

/// A client certificate chain whose key the client proved to hold, with
/// the delegated credential (RFC 9345 §4.1.2) it did so with, if any.
struct ProvenClient {
    chain: CertificateChain<'static>,
    credential: Option<ValidatedCredential>,
}

/// The length of a post-handshake `certificate_request_context`: an 8-byte
/// request counter, which makes it unique on the connection, then random
/// bytes, which make it unpredictable (RFC 9846 §4.4.2).
const POST_HANDSHAKE_CONTEXT_RANDOM_LEN: usize = 24;

impl PostHandshakeAuth {
    fn request(&mut self, common: &mut CommonState) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::General(
                "a post-handshake client authentication is already in progress".into(),
            ));
        }
        if !self.config.verifier.offer_client_auth() {
            return Err(Error::General(
                "the client certificate verifier does not offer client authentication".into(),
            ));
        }
        // RFC 9846 §6.1: nothing follows our close_notify.
        if common.has_sent_close_notify() {
            return Err(Error::General(
                "cannot request client authentication after close_notify".into(),
            ));
        }
        let mut context = self.requests_sent.to_be_bytes().to_vec();
        context.extend(crate::rand::random_vec(
            self.config.provider.secure_random,
            POST_HANDSHAKE_CONTEXT_RANDOM_LEN,
        )?);
        let m = certificate_request_message(&self.config, context.clone())?;
        let mut transcript = self.transcript.fork();
        transcript.add_message(&m);
        trace!("Sending post-handshake CertificateRequest {:?}", m);
        common.send_msg(m, true);
        // Until the answer completes, the connection may stop to look up
        // the certificate's status.
        common.revocation_auth_outstanding = client_revocation_enabled(&self.config);
        self.requests_sent = self.requests_sent.wrapping_add(1);
        self.pending = Some(PendingClientAuth {
            context,
            transcript,
            offered_sigschemes: client_auth_sigschemes(&self.config),
            stage: ClientAuthStage::Certificate,
        });
        Ok(())
    }

    /// Whether `m` continues the pending answer: an answer, once begun,
    /// must arrive without other messages in between (RFC 9846 §4.7.2).
    fn answer_in_progress(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|p| !matches!(p.stage, ClientAuthStage::Certificate))
    }

    /// Continues the answer whose status lookup finished with `status`.
    fn resume_revocation(&mut self, status: Option<RevocationStatus>) -> Result<(), Error> {
        let no_continuation = || Error::general("no revocation continuation");
        let pending = self.pending.as_mut().ok_or_else(no_continuation)?;
        pending.stage = match core::mem::replace(&mut pending.stage, ClientAuthStage::Certificate) {
            ClientAuthStage::Revocation(client) => {
                ClientAuthStage::Finished(Some((client, status)))
            }
            _ => return Err(no_continuation()),
        };
        Ok(())
    }

    fn handle(
        &mut self,
        cx: &mut ServerContext<'_>,
        key_schedule: &KeyScheduleTraffic,
        m: &Message<'_>,
    ) -> Result<(), Error> {
        let Some(mut pending) = self.pending.take() else {
            return Err(crate::check::inappropriate_handshake_message(
                &m.payload,
                &[ContentType::ApplicationData, ContentType::Handshake],
                &[HandshakeType::KeyUpdate],
            ));
        };
        let MessagePayload::Handshake {
            parsed: HandshakeMessagePayload(payload),
            ..
        } = &m.payload
        else {
            return Err(interleaved(cx.common));
        };
        pending.stage = match (pending.stage, payload) {
            (ClientAuthStage::Certificate, HandshakePayload::CertificateTls13(certp)) => {
                pending.transcript.add_message(m);
                match check_client_certificate(cx.common, &self.config, certp, &pending.context)? {
                    Some(cert) => ClientAuthStage::CertificateVerify(cert),
                    None => ClientAuthStage::Finished(None),
                }
            }
            // RFC 8879 §4: our CertificateRequest offers the same
            // compression algorithms as in the handshake.
            (ClientAuthStage::Certificate, HandshakePayload::CompressedCertificate(compressed)) => {
                let certp = crate::compress::receive_compressed_certificate(
                    cx.common,
                    &self.config.cert_decompressors,
                    self.config.cert_decompression_limit,
                    compressed,
                )?;
                pending.transcript.add_message(m);
                match check_client_certificate(cx.common, &self.config, &certp, &pending.context)? {
                    Some(cert) => ClientAuthStage::CertificateVerify(cert),
                    None => ClientAuthStage::Finished(None),
                }
            }
            (
                ClientAuthStage::CertificateVerify(cert),
                HandshakePayload::CertificateVerify(sig),
            ) => {
                let (_, credential) = check_client_certificate_verify(
                    cx.common,
                    &self.config,
                    &pending.transcript,
                    &cert,
                    &pending.offered_sigschemes,
                    sig,
                )?;
                pending.transcript.add_message(m);
                let client = ProvenClient {
                    chain: cert.chain,
                    credential,
                };
                // The client holds the key: a status lookup, if the
                // verifier needs one, may start now. The traffic state
                // stays; the Finished is read once the lookup resolves.
                match cert.revocation {
                    RevocationCheck::Complete(status) => {
                        ClientAuthStage::Finished(Some((client, status)))
                    }
                    RevocationCheck::Pending(lookup) => {
                        cx.common.pending_revocation = Some(lookup);
                        ClientAuthStage::Revocation(client)
                    }
                }
            }
            (ClientAuthStage::Finished(identity), HandshakePayload::Finished(finished)) => {
                // RFC 9846 §4.5: the MAC uses the current
                // client_application_traffic_secret_N as base key.
                let expected = key_schedule
                    .sign_post_handshake_client_finish(pending.transcript.current_hash().as_ref());
                if !constant_time_eq(expected.as_ref(), finished.bytes()) {
                    return Err(cx
                        .common
                        .send_fatal_alert(AlertDescription::DecryptError, Error::DecryptError));
                }
                // A credential that expired while the answer, or a status
                // lookup for it, was under way.
                let expiry = identity
                    .as_ref()
                    .and_then(|(client, _)| client.credential.as_ref())
                    .map(|(_, expiry)| *expiry);
                check_client_credential_unexpired(cx.common, &self.config, expiry)?;
                cx.common.revocation_auth_outstanding = false;
                cx.data.post_handshake_auth = Some(match identity {
                    Some((client, status)) => {
                        debug!("post-handshake client authentication succeeded");
                        let (credential, expiry) = client.credential.unzip();
                        cx.data.client_delegated_credential = credential;
                        cx.data.client_delegated_credential_expiry = expiry;
                        cx.common.peer_certificates = Some(client.chain);
                        cx.common.peer_revocation_status = status;
                        PostHandshakeAuthStatus::Authenticated
                    }
                    None => {
                        debug!("client declined post-handshake authentication");
                        PostHandshakeAuthStatus::Declined
                    }
                });
                return Ok(());
            }
            (ClientAuthStage::Certificate, _) => {
                return Err(crate::check::inappropriate_handshake_message(
                    &m.payload,
                    &[ContentType::ApplicationData, ContentType::Handshake],
                    &[HandshakeType::KeyUpdate, HandshakeType::Certificate],
                ));
            }
            (ClientAuthStage::Revocation(_), _) => {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::InternalError,
                    Error::general("handshake input processed during revocation verification"),
                ));
            }
            _ => return Err(interleaved(cx.common)),
        };
        self.pending = Some(pending);
        Ok(())
    }
}

/// A message other than the next one of a post-handshake authentication
/// answer arrived in the middle of it (RFC 9846 §4.7.2).
fn interleaved(common: &mut CommonState) -> Error {
    common.send_fatal_alert(
        AlertDescription::UnexpectedMessage,
        PeerMisbehaved::MessageInterleavedWithPostHandshakeAuthentication,
    )
}

impl ExpectTraffic {
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

impl State<ServerConnectionData> for ExpectTraffic {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        if let Some(auth) = &mut self.post_handshake_auth
            && auth.answer_in_progress()
        {
            auth.handle(cx, &self.key_schedule, &m)?;
            return Ok(self);
        }
        match m.payload {
            MessagePayload::ApplicationData(payload) => {
                // Only data counts as progress: an empty record must not
                // let the peer keep requesting KeyUpdates.
                if !payload.bytes().is_empty() {
                    cx.common.received_key_update_requests = 0;
                }
                cx.common.take_received_plaintext(payload);
            }
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
                    HandshakeMessagePayload(
                        HandshakePayload::CertificateTls13(_)
                        | HandshakePayload::CompressedCertificate(_)
                        | HandshakePayload::CertificateVerify(_)
                        | HandshakePayload::Finished(_),
                    ),
                ..
            } if self.post_handshake_auth.is_some() => {
                if let Some(auth) = &mut self.post_handshake_auth {
                    auth.handle(cx, &self.key_schedule, &m)?;
                }
            }
            payload => {
                return Err(crate::check::inappropriate_handshake_message(
                    &payload,
                    &[ContentType::ApplicationData, ContentType::Handshake],
                    &[HandshakeType::KeyUpdate],
                ));
            }
        }
        Ok(self)
    }

    fn resume_revocation(
        mut self: Box<Self>,
        _cx: &mut ServerContext<'_>,
        status: Option<RevocationStatus>,
    ) -> NextStateOrError {
        match &mut self.post_handshake_auth {
            Some(auth) => auth.resume_revocation(status)?,
            None => return Err(Error::general("no revocation continuation")),
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

    fn request_client_auth(&mut self, cx: &mut ServerContext<'_>) -> Result<(), Error> {
        let Some(auth) = &mut self.post_handshake_auth else {
            return Err(Error::General(
                "the client did not offer post-handshake authentication".into(),
            ));
        };
        auth.request(cx.common)?;
        cx.data.post_handshake_auth = Some(PostHandshakeAuthStatus::Requested);
        Ok(())
    }

    fn extract_secrets(&self) -> Result<PartiallyExtractedSecrets, Error> {
        self.key_schedule.extract_secrets(Side::Server)
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
