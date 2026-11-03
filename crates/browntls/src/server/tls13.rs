//! The TLS 1.3 server handshake (RFC 8446 §4).

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use super::common::ActiveCertifiedKey;
use super::hs::{self, HandshakeHashOrBuffer, NextStateOrError, ServerContext};
use super::server_conn::{ServerConfig, ServerConnectionData};
use crate::common_state::{CommonState, ConnectionRandoms, HandshakeKind, Side};
use crate::conn::State;
use crate::crypto::SupportedKxGroup;
use crate::ct::constant_time_eq;
use crate::enums::{
    AlertDescription, ContentType, HandshakeType, ProtocolVersion, SignatureScheme,
};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace, warning};
use crate::msgs::base::{Payload, PayloadU8, PayloadU24};
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::msgs::codec::Codec;
use crate::msgs::enums::{Compression, KeyUpdateRequest, NamedGroup, PskKeyExchangeMode};
use crate::msgs::handshake::{
    CertificatePayloadTls13, CertificateRequestExtensions, CertificateRequestPayloadTls13,
    ClientHelloPayload, CompressedCertificatePayload, HandshakeMessagePayload, HandshakePayload,
    HelloRetryRequest, HelloRetryRequestExtensions, KeyShareEntry, NewSessionTicketPayloadTls13,
    ServerExtensions, ServerHelloPayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist::ServerSessionValue;
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::{
    KeyScheduleEarly, KeyScheduleHandshake, KeySchedulePreHandshake, KeyScheduleTraffic,
    KeyScheduleTrafficWithClientFinishedPending,
};
use crate::verify::{DigitallySignedStruct, FinishedMessageVerified, HandshakeSignatureValid};

/// How many `update_requested` KeyUpdates we tolerate without sending data.
const MAX_KEY_UPDATE_REQUESTS: u8 = 8;

pub(super) struct CompleteClientHelloHandling {
    pub(super) config: Arc<ServerConfig>,
    pub(super) transcript: HandshakeHash,
    pub(super) suite: &'static Tls13CipherSuite,
    pub(super) randoms: ConnectionRandoms,
    pub(super) done_retry: bool,
    pub(super) send_tickets: usize,
}

impl CompleteClientHelloHandling {
    /// Verifies a PSK binder (RFC 8446 §4.2.11.2) over the transcript so far
    /// plus the ClientHello without its binders.
    fn check_binder(
        &self,
        suite: &'static Tls13CipherSuite,
        client_hello: &Message<'_>,
        psk: &[u8],
        binder: &[u8],
    ) -> bool {
        // Hash the bytes as received, not a re-encoding: the peer may order
        // its extensions differently from us.
        let binder_plaintext = match &client_hello.payload {
            MessagePayload::Handshake { parsed, encoded } => {
                let bytes = encoded.bytes();
                &bytes[..bytes.len().saturating_sub(parsed.total_binder_length())]
            }
            _ => return false,
        };
        let handshake_hash = self.transcript.hash_with(binder_plaintext);
        let key_schedule = KeyScheduleEarly::new(suite, psk);
        let real_binder =
            key_schedule.resumption_psk_binder_key_and_sign_verify_data(handshake_hash.as_ref());
        constant_time_eq(real_binder.as_ref(), binder)
    }

    fn attempt_tls13_ticket_decryption(&self, ticket: &[u8]) -> Option<ServerSessionValue> {
        let plain = if self.config.ticketer.enabled() {
            self.config.ticketer.decrypt(ticket)?
        } else {
            self.config.session_storage.take(ticket)?
        };
        ServerSessionValue::read_bytes(&plain).ok()
    }

    pub(super) fn handle_client_hello(
        mut self,
        cx: &mut ServerContext<'_>,
        server_key: ActiveCertifiedKey<'_>,
        chm: &Message<'_>,
        client_hello: &ClientHelloPayload,
        selected_kxg: &'static dyn SupportedKxGroup,
        sigschemes_ext: Vec<SignatureScheme>,
    ) -> NextStateOrError {
        let shares_ext = client_hello.key_shares().ok_or_else(|| {
            cx.common.send_fatal_alert(
                AlertDescription::MissingExtension,
                PeerIncompatible::KeyShareExtensionRequired,
            )
        })?;

        let sigschemes: Vec<SignatureScheme> = sigschemes_ext
            .into_iter()
            .filter(SignatureScheme::supported_in_tls13)
            .collect();
        if sigschemes.is_empty() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::NoSignatureSchemesInCommon,
            ));
        }

        // RFC 8446 §4.2.9: a PSK offer needs psk_key_exchange_modes.
        if client_hello.extensions.preshared_key.is_some()
            && client_hello.extensions.psk_modes.is_none()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::MissingExtension,
                PeerMisbehaved::MissingPskModesExtension,
            ));
        }

        // RFC 8446 §4.2.10: early_data may only appear in the first ClientHello.
        let early_data_requested = client_hello.early_data_offered();
        if self.done_retry && early_data_requested {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::EarlyDataAttemptedInSecondClientHello,
            ));
        }

        let Some(chosen_share) = shares_ext
            .iter()
            .find(|share| share.group == selected_kxg.name())
        else {
            // RFC 8446 §4.1.4: ask for a share in the group we want.
            if self.done_retry {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::RefusedToFollowHelloRetryRequest,
                ));
            }
            self.transcript.add_message(chm);
            self.transcript.rollup_for_hrr();
            emit_hello_retry_request(
                &mut self.transcript,
                self.suite,
                client_hello.session_id,
                selected_kxg.name(),
                cx.common,
            );
            emit_fake_ccs(cx.common);
            cx.common.handshake_kind = Some(HandshakeKind::FullWithHelloRetryRequest);
            let skip_data_left = max_early_data_size(self.config.max_early_data_size);
            let next = Box::new(hs::ExpectClientHello {
                config: self.config,
                transcript: HandshakeHashOrBuffer::Hash(self.transcript),
                session_id: SessionId::empty(),
                done_retry: true,
                send_tickets: self.send_tickets,
            });
            // Early data sent behind that first ClientHello is unreadable
            // (no PSK was taken); skip it up to the announced limit.
            return Ok(if early_data_requested {
                Box::new(ExpectAndSkipRejectedEarlyData {
                    skip_data_left,
                    next,
                })
            } else {
                next
            });
        };

        // PSK resumption (RFC 8446 §4.2.11).
        let mut chosen_psk_index = None;
        let mut resumedata = None;
        if let Some(psk_offer) = &client_hello.extensions.preshared_key {
            let dhe_allowed = client_hello
                .extensions
                .psk_modes
                .as_ref()
                .is_some_and(|modes| modes.contains(&PskKeyExchangeMode::PSK_DHE_KE));
            if psk_offer.binders.len() != psk_offer.identities.len() {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::PskExtensionWithMismatchedIdsAndBinders,
                ));
            }
            if dhe_allowed {
                for (i, psk_id) in psk_offer.identities.iter().enumerate() {
                    let Some(resume) = self.attempt_tls13_ticket_decryption(&psk_id.identity.0)
                    else {
                        continue;
                    };
                    let Some(prev_suite) = self
                        .config
                        .find_cipher_suite(resume.cipher_suite)
                        .and_then(|s| s.tls13())
                    else {
                        continue;
                    };
                    if self.suite.can_resume_from(prev_suite).is_none() || resume.sni != cx.data.sni
                    {
                        continue;
                    }
                    if !self.check_binder(
                        self.suite,
                        chm,
                        &resume.master_secret.0,
                        psk_offer.binders[i].as_ref(),
                    ) {
                        return Err(cx.common.send_fatal_alert(
                            AlertDescription::DecryptError,
                            PeerMisbehaved::IncorrectBinder,
                        ));
                    }
                    chosen_psk_index = Some(i);
                    resumedata =
                        Some(resume.set_freshness(
                            psk_id.obfuscated_ticket_age,
                            self.config.current_time()?,
                        ));
                    break;
                }
            }
        }

        if resumedata.is_some() {
            cx.common.handshake_kind = Some(HandshakeKind::Resumed);
        } else if cx.common.handshake_kind.is_none() {
            cx.common.handshake_kind = Some(HandshakeKind::Full);
        }

        self.transcript.add_message(chm);

        let kx = selected_kxg
            .start_and_complete(&chosen_share.payload.0)
            .map_err(|err| match err {
                Error::PeerMisbehaved(_) => cx
                    .common
                    .send_fatal_alert(AlertDescription::IllegalParameter, err),
                other => other,
            })?;
        cx.common.kx_state.complete();

        let early_data = decide_if_early_data_allowed(
            cx,
            early_data_requested,
            chosen_psk_index.zip(resumedata.as_ref()),
            self.suite,
            &self.config,
        );

        let client_hello_hash = self.transcript.current_hash();
        let key_schedule_pre = match &resumedata {
            Some(resume) => {
                let early = KeyScheduleEarly::new(self.suite, &resume.master_secret.0);
                // Start reading under the early traffic key: it carries any
                // 0-RTT data, and is replaced below when we do not accept it.
                early.client_early_traffic_secret(
                    client_hello_hash.as_ref(),
                    &*self.config.key_log,
                    &self.randoms.client,
                    cx.common,
                );
                early.into_pre_handshake()
            }
            None => KeySchedulePreHandshake::new(self.suite),
        };
        let key_schedule = key_schedule_pre.into_handshake_with_shared_secret(&kx.secret);

        emit_server_hello(
            &mut self.transcript,
            &self.randoms,
            self.suite,
            cx.common,
            &client_hello.session_id,
            chosen_psk_index,
            KeyShareEntry::new(selected_kxg.name(), &kx.pub_key),
        );
        if !self.done_retry {
            emit_fake_ccs(cx.common);
        }

        let hash_at_server_hello = self.transcript.current_hash();
        let key_schedule = key_schedule.derive_client_handshake_secrets(
            true,
            hash_at_server_hello.as_ref(),
            &*self.config.key_log,
            &self.randoms.client,
            cx.common,
        );

        // Which key the client's next records are read under.
        match early_data {
            EarlyDataDecision::Disabled => {
                key_schedule.set_handshake_decrypter(None, cx.common);
                cx.data.early_data.reject();
            }
            EarlyDataDecision::RequestedButRejected => {
                // RFC 8446 §4.2.10: skip the client's early data records (we
                // cannot read them) until its handshake-key records appear.
                debug!("Client requested early_data, but not accepted: trial decryption");
                key_schedule.set_handshake_decrypter(
                    Some(max_early_data_size(self.config.max_early_data_size)),
                    cx.common,
                );
                cx.data.early_data.reject();
            }
            EarlyDataDecision::Accepted => {
                cx.data
                    .early_data
                    .accept(self.config.max_early_data_size as usize);
            }
        }

        emit_encrypted_extensions(
            &mut self.transcript,
            cx,
            client_hello,
            early_data == EarlyDataDecision::Accepted,
        );

        let doing_client_auth = if resumedata.is_none() {
            let client_auth =
                emit_certificate_req_tls13(&mut self.transcript, cx.common, &self.config)?;
            emit_certificate_tls13(
                &mut self.transcript,
                cx.common,
                &self.config,
                &server_key,
                client_hello,
            );
            emit_certificate_verify_tls13(
                &mut self.transcript,
                cx.common,
                &server_key,
                &sigschemes,
            )?;
            client_auth
        } else {
            false
        };

        if let Some(resume) = &resumedata {
            cx.data.received_resumption_data = Some(resume.application_data.0.clone());
            cx.common.peer_certificates = resume.client_cert_chain.clone();
        }

        self.send_tickets = self.config.send_tls13_tickets;

        let key_schedule = emit_finished_tls13(
            &mut self.transcript,
            &self.randoms,
            cx,
            key_schedule,
            &self.config,
        );

        if self.config.send_half_rtt_data {
            cx.common.start_outgoing_traffic();
        }

        if doing_client_auth {
            let offered_sigschemes = self.config.verifier.supported_verify_schemes();
            Ok(Box::new(ExpectCertificate {
                config: self.config,
                transcript: self.transcript,
                suite: self.suite,
                key_schedule,
                send_tickets: self.send_tickets,
                offered_sigschemes,
            }))
        } else if early_data == EarlyDataDecision::Accepted {
            Ok(Box::new(ExpectEarlyData {
                config: self.config,
                transcript: self.transcript,
                suite: self.suite,
                key_schedule,
                send_tickets: self.send_tickets,
            }))
        } else {
            Ok(Box::new(ExpectFinished {
                config: self.config,
                transcript: self.transcript,
                suite: self.suite,
                key_schedule,
                send_tickets: self.send_tickets,
            }))
        }
    }
}

/// The outcome of the client's `early_data` request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EarlyDataDecision {
    /// Not requested.
    Disabled,
    /// Requested, but we will not read it.
    RequestedButRejected,
    /// Requested and accepted.
    Accepted,
}

/// How much rejected early data to skip: the configured limit, or one
/// maximum-sized record when early data is off (a client may hold a ticket
/// from when it was on).
fn max_early_data_size(configured: u32) -> usize {
    if configured != 0 {
        configured as usize
    } else {
        16384
    }
}

/// RFC 8446 §4.2.10: early data is accepted only with a fresh, first-listed
/// PSK that reproduces the version, suite and ALPN protocol it was issued
/// under, and only with stateful resumption (RFC 8446 §8.1 anti-replay).
fn decide_if_early_data_allowed(
    cx: &mut ServerContext<'_>,
    early_data_requested: bool,
    resuming: Option<(usize, &ServerSessionValue)>,
    suite: &'static Tls13CipherSuite,
    config: &ServerConfig,
) -> EarlyDataDecision {
    let rejected_or_disabled = if early_data_requested {
        EarlyDataDecision::RequestedButRejected
    } else {
        EarlyDataDecision::Disabled
    };

    let Some((psk_index, resume)) = resuming else {
        return rejected_or_disabled;
    };

    let early_data_configured = config.max_early_data_size > 0 && !config.ticketer.enabled();
    let early_data_possible = early_data_requested
        && psk_index == 0
        && resume.is_fresh()
        && Some(resume.version) == cx.common.negotiated_version
        && resume.cipher_suite == suite.common.suite
        && resume.alpn.as_ref().map(|p| p.0.as_slice()) == cx.common.alpn_protocol.as_deref();

    if early_data_configured && early_data_possible && !cx.data.early_data.was_rejected() {
        EarlyDataDecision::Accepted
    } else {
        rejected_or_disabled
    }
}

/// Discards a client's early data records (unreadable because its PSK was
/// not taken) up to a limit, then hands everything else to `next`.
struct ExpectAndSkipRejectedEarlyData {
    skip_data_left: usize,
    next: Box<hs::ExpectClientHello>,
}

impl State<ServerConnectionData> for ExpectAndSkipRejectedEarlyData {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        // RFC 8446 §4.2.10: "skipping all records with an external content
        // type of application_data ... up to the configured max_early_data_size".
        if let MessagePayload::ApplicationData(skip_data) = &m.payload
            && skip_data.bytes().len() <= self.skip_data_left
        {
            self.skip_data_left -= skip_data.bytes().len();
            return Ok(self);
        }
        self.next.handle(cx, m)
    }
}

/// Reads accepted early data until EndOfEarlyData.
struct ExpectEarlyData {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    send_tickets: usize,
}

impl State<ServerConnectionData> for ExpectEarlyData {
    fn handle(self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        match &m.payload {
            MessagePayload::ApplicationData(payload) => {
                if cx.data.early_data.take_received_plaintext(payload.bytes()) {
                    Ok(self)
                } else {
                    Err(cx.common.send_fatal_alert(
                        AlertDescription::UnexpectedMessage,
                        PeerMisbehaved::TooMuchEarlyDataReceived,
                    ))
                }
            }
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::EndOfEarlyData),
                ..
            } => {
                let mut st = *self;
                // RFC 8446 §4.5: the client's next records use its handshake key.
                st.key_schedule.update_decrypter(cx.common);
                st.transcript.add_message(&m);
                Ok(Box::new(ExpectFinished {
                    config: st.config,
                    transcript: st.transcript,
                    suite: st.suite,
                    key_schedule: st.key_schedule,
                    send_tickets: st.send_tickets,
                }))
            }
            payload => Err(crate::check::inappropriate_handshake_message(
                payload,
                &[ContentType::ApplicationData, ContentType::Handshake],
                &[HandshakeType::EndOfEarlyData],
            )),
        }
    }
}

fn emit_server_hello(
    transcript: &mut HandshakeHash,
    randoms: &ConnectionRandoms,
    suite: &'static Tls13CipherSuite,
    common: &mut CommonState,
    session_id: &SessionId,
    chosen_psk_index: Option<usize>,
    key_share: KeyShareEntry,
) {
    let extensions = ServerExtensions {
        key_share: Some(key_share),
        pre_shared_key: chosen_psk_index.and_then(|i| u16::try_from(i).ok()),
        supported_versions: Some(ProtocolVersion::TLSv1_3),
        ..Default::default()
    };
    let sh = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ServerHello(
            ServerHelloPayload {
                legacy_version: ProtocolVersion::TLSv1_2,
                random: randoms.server.into(),
                session_id: *session_id,
                cipher_suite: suite.common.suite,
                compression_method: Compression::Null,
                extensions,
            },
        ))),
    };
    trace!("sending server hello {:?}", sh);
    transcript.add_message(&sh);
    common.send_msg(sh, false);
}

/// Sends the middlebox-compatibility ChangeCipherSpec (RFC 8446 appendix D.4).
fn emit_fake_ccs(common: &mut CommonState) {
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload),
    };
    common.send_msg(m, false);
}

fn emit_hello_retry_request(
    transcript: &mut HandshakeHash,
    suite: &'static Tls13CipherSuite,
    session_id: SessionId,
    group: NamedGroup,
    common: &mut CommonState,
) {
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::HelloRetryRequest(HelloRetryRequest {
                legacy_version: ProtocolVersion::TLSv1_2,
                session_id,
                cipher_suite: suite.common.suite,
                compression_method: Compression::Null,
                extensions: HelloRetryRequestExtensions {
                    key_share: Some(group),
                    cookie: None,
                    supported_versions: Some(ProtocolVersion::TLSv1_3),
                    unknown: Vec::new(),
                },
            }),
        )),
    };
    trace!("Requesting retry {:?}", m);
    transcript.add_message(&m);
    common.send_msg(m, false);
}

fn emit_encrypted_extensions(
    transcript: &mut HandshakeHash,
    cx: &mut ServerContext<'_>,
    client_hello: &ClientHelloPayload,
    early_data_accepted: bool,
) {
    let exts = ServerExtensions {
        alpn: cx
            .common
            .alpn_protocol
            .clone()
            .map(crate::msgs::handshake::ProtocolName::from),
        server_name_ack: client_hello.sni().map(|_| ()),
        early_data: early_data_accepted.then_some(()),
        ..Default::default()
    };
    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::EncryptedExtensions(exts),
        )),
    };
    trace!("sending encrypted extensions {:?}", m);
    transcript.add_message(&m);
    cx.common.send_msg(m, true);
}

/// Sends a CertificateRequest if the configuration wants client authentication.
fn emit_certificate_req_tls13(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    config: &ServerConfig,
) -> Result<bool, Error> {
    if !config.verifier.offer_client_auth() {
        return Ok(false);
    }
    let schemes: Vec<SignatureScheme> = config
        .verifier
        .supported_verify_schemes()
        .into_iter()
        .filter(SignatureScheme::supported_in_tls13)
        .collect();
    if schemes.is_empty() {
        return Err(Error::general(
            "client certificate verifier supports no TLS 1.3 signature schemes",
        ));
    }
    let authorities = config.verifier.root_hint_subjects();
    let cr = CertificateRequestPayloadTls13 {
        context: PayloadU8::empty(),
        extensions: CertificateRequestExtensions {
            signature_algorithms: Some(schemes),
            authorities: (!authorities.is_empty()).then(|| authorities.to_vec()),
            certificate_compression: (!config.cert_decompressors.is_empty()).then(|| {
                config
                    .cert_decompressors
                    .iter()
                    .map(|d| d.algorithm())
                    .collect()
            }),
            ..Default::default()
        },
    };
    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::CertificateRequestTls13(cr),
        )),
    };
    trace!("Sending CertificateRequest {:?}", m);
    transcript.add_message(&m);
    common.send_msg(m, true);
    Ok(true)
}

fn emit_certificate_tls13(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    config: &ServerConfig,
    server_key: &ActiveCertifiedKey<'_>,
    client_hello: &ClientHelloPayload,
) {
    // RFC 6066 §8: staple only when the client asked.
    let ocsp = client_hello
        .extensions
        .certificate_status_request
        .as_ref()
        .and_then(|_| server_key.get_ocsp());
    let cert_body = CertificatePayloadTls13::new(server_key.get_cert().iter(), ocsp);

    // RFC 8879 §4: compress when the client offered an algorithm we have.
    let compressor = client_hello
        .extensions
        .certificate_compression
        .as_ref()
        .and_then(|offered| {
            config
                .cert_compressors
                .iter()
                .find(|c| offered.contains(&c.algorithm()))
        });
    if let Some(compressor) = compressor {
        let encoded = cert_body.get_encoding();
        if let Ok(compressed) = config
            .cert_compression_cache
            .compression_for(*compressor, &encoded)
            && let Ok(uncompressed_len) = u32::try_from(encoded.len())
        {
            let m = Message {
                version: ProtocolVersion::TLSv1_3,
                payload: MessagePayload::handshake(HandshakeMessagePayload(
                    HandshakePayload::CompressedCertificate(CompressedCertificatePayload {
                        alg: compressor.algorithm(),
                        uncompressed_len,
                        compressed: PayloadU24(Payload::new(compressed)),
                    }),
                )),
            };
            transcript.add_message(&m);
            common.send_msg(m, true);
            return;
        }
    }

    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::CertificateTls13(cert_body),
        )),
    };
    trace!("sending certificate {:?}", m);
    transcript.add_message(&m);
    common.send_msg(m, true);
}

fn emit_certificate_verify_tls13(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    server_key: &ActiveCertifiedKey<'_>,
    schemes: &[SignatureScheme],
) -> Result<(), Error> {
    let message = crate::client::tls13::construct_server_verify_message(&transcript.current_hash());
    let signer = server_key.get_key().choose_scheme(schemes).ok_or_else(|| {
        common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            PeerIncompatible::NoSignatureSchemesInCommon,
        )
    })?;
    let scheme = signer.scheme();
    let sig = signer.sign(&message)?;
    let cv = DigitallySignedStruct::new(scheme, sig);
    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::CertificateVerify(cv),
        )),
    };
    trace!("sending certificate-verify {:?}", m);
    transcript.add_message(&m);
    common.send_msg(m, true);
    Ok(())
}

fn emit_finished_tls13(
    transcript: &mut HandshakeHash,
    randoms: &ConnectionRandoms,
    cx: &mut ServerContext<'_>,
    key_schedule: KeyScheduleHandshake,
    config: &ServerConfig,
) -> KeyScheduleTrafficWithClientFinishedPending {
    let handshake_hash = transcript.current_hash();
    let verify_data = key_schedule.sign_server_finish(handshake_hash.as_ref());
    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::Finished(
            Payload::new(verify_data.as_ref().to_vec()),
        ))),
    };
    trace!("sending finished {:?}", m);
    transcript.add_message(&m);
    let hash_at_server_fin = transcript.current_hash();
    cx.common.send_msg(m, true);

    // The server starts sending application data under the application
    // traffic secret right away.
    key_schedule.into_traffic_with_client_finished_pending(
        hash_at_server_fin.as_ref(),
        &*config.key_log,
        &randoms.client,
        cx.common,
    )
}

struct ExpectCertificate {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    send_tickets: usize,
    offered_sigschemes: Vec<SignatureScheme>,
}

impl State<ServerConnectionData> for ExpectCertificate {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        let certp = require_handshake_msg!(
            m,
            HandshakeType::Certificate,
            HandshakePayload::CertificateTls13
        )?;
        self.transcript.add_message(&m);

        // RFC 8446 §4.4.2: the context echoes our (empty) request context.
        if !certp.context.0.is_empty() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::DecodeError,
                crate::error::InvalidMessage::InvalidCertRequest,
            ));
        }
        if certp.any_entry_after_first_has_extensions() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerMisbehaved::BadCertChainExtensions,
            ));
        }
        // We never request stapled responses or SCTs from clients.
        if certp
            .entries
            .iter()
            .any(|e| e.status.is_some() || e.sct_list.is_some())
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerMisbehaved::UnsolicitedCertExtension,
            ));
        }

        let client_cert = certp.clone().into_certificate_chain().into_owned();

        let Some((end_entity, intermediates)) = client_cert.0.split_first() else {
            // RFC 8446 §4.4.2.4: an empty Certificate is allowed unless we require one.
            if self.config.verifier.client_auth_mandatory() {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::CertificateRequired,
                    Error::NoCertificatesPresented,
                ));
            }
            debug!("client auth requested but no certificate supplied");
            return Ok(Box::new(ExpectFinished {
                config: self.config,
                transcript: self.transcript,
                suite: self.suite,
                key_schedule: self.key_schedule,
                send_tickets: self.send_tickets,
            }));
        };

        let now = self.config.current_time()?;
        self.config
            .verifier
            .verify_client_cert(end_entity, intermediates, now)
            .map_err(|err| crate::client::tls13::send_cert_verify_error_alert(cx.common, err))?;

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

        if !self.offered_sigschemes.contains(&sig.scheme) {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }

        let handshake_hash = self.transcript.current_hash();
        let msg = crate::client::tls13::construct_client_verify_message(&handshake_hash);
        let end_entity = self.client_cert.0.first().ok_or_else(|| {
            cx.common.send_fatal_alert(
                AlertDescription::DecodeError,
                Error::NoCertificatesPresented,
            )
        })?;
        let sig_verified: HandshakeSignatureValid = self
            .config
            .verifier
            .verify_tls13_signature(&msg, end_entity, sig)
            .map_err(|err| crate::client::tls13::send_cert_verify_error_alert(cx.common, err))?;
        let _ = sig_verified;

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

/// Issues one NewSessionTicket.
fn emit_ticket(
    transcript: &HandshakeHash,
    suite: &'static Tls13CipherSuite,
    cx: &mut ServerContext<'_>,
    key_schedule: &KeyScheduleTraffic,
    config: &ServerConfig,
) -> Result<(), Error> {
    let rng = config.provider.secure_random;
    let nonce = crate::rand::random_vec(rng, 32)?;
    let age_add = crate::rand::random_u32(rng)?;
    let secret = key_schedule
        .resumption_master_secret_and_derive_ticket_psk(transcript.current_hash().as_ref(), &nonce);

    let now = config.current_time()?;
    let plain = ServerSessionValue::new(
        cx.data.sni.as_ref(),
        ProtocolVersion::TLSv1_3,
        suite.common.suite,
        &secret,
        cx.common.peer_certificates.clone(),
        cx.common.alpn_protocol.clone(),
        cx.data.resumption_data.clone(),
        now,
        age_add,
    )
    .get_encoding();

    let ticket = if config.ticketer.enabled() {
        match config.ticketer.encrypt(&plain) {
            Some(t) => t,
            None => return Ok(()),
        }
    } else if config.session_storage.can_cache() {
        let id = crate::rand::random_vec(rng, 32)?;
        if !config.session_storage.put(id.clone(), plain) {
            return Ok(());
        }
        id
    } else {
        return Ok(());
    };

    let mut payload =
        NewSessionTicketPayloadTls13::new(config.ticketer.lifetime(), age_add, nonce, ticket);
    if config.max_early_data_size > 0 {
        if config.ticketer.enabled() {
            // RFC 8446 §8.1: without a server-side session record there is no
            // single-use guarantee, so 0-RTT is never offered on such tickets.
            warning!("early_data with stateless resumption is not allowed");
        } else {
            payload.exts.max_early_data_size = Some(config.max_early_data_size);
        }
    }
    let m = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::NewSessionTicketTls13(payload),
        )),
    };
    trace!("sending new ticket {:?}", m);
    cx.common.send_msg(m, true);
    Ok(())
}

struct ExpectFinished {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    suite: &'static Tls13CipherSuite,
    key_schedule: KeyScheduleTrafficWithClientFinishedPending,
    send_tickets: usize,
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
        let fin = FinishedMessageVerified::assertion();

        st.transcript.add_message(&m);
        let key_schedule = st.key_schedule.into_traffic(cx.common);

        for _ in 0..st.send_tickets {
            emit_ticket(&st.transcript, st.suite, cx, &key_schedule, &st.config)?;
        }

        cx.common.start_traffic();

        Ok(Box::new(ExpectTraffic {
            key_schedule,
            _fin_verified: fin,
        }))
    }
}

struct ExpectTraffic {
    key_schedule: KeyScheduleTraffic,
    _fin_verified: FinishedMessageVerified,
}

impl ExpectTraffic {
    fn handle_key_update(
        &mut self,
        common: &mut CommonState,
        request: KeyUpdateRequest,
    ) -> Result<(), Error> {
        match request {
            KeyUpdateRequest::UpdateNotRequested => {}
            KeyUpdateRequest::UpdateRequested => {
                common.received_key_update_requests =
                    common.received_key_update_requests.saturating_add(1);
                if common.received_key_update_requests > MAX_KEY_UPDATE_REQUESTS {
                    return Err(common.send_fatal_alert(
                        AlertDescription::UnexpectedMessage,
                        PeerMisbehaved::TooManyKeyUpdateRequests,
                    ));
                }
                common.send_key_update(KeyUpdateRequest::UpdateNotRequested);
                self.key_schedule.update_encrypter_and_notify(common);
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
        match m.payload {
            MessagePayload::ApplicationData(payload) => {
                cx.common.received_key_update_requests = 0;
                cx.common.take_received_plaintext(payload);
            }
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::KeyUpdate(request)),
                ..
            } => self.handle_key_update(cx.common, request)?,
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
        self.key_schedule.extract_secrets(Side::Server)
    }

    fn send_key_update_request(&mut self, common: &mut CommonState) -> Result<(), Error> {
        common.send_key_update(KeyUpdateRequest::UpdateRequested);
        self.key_schedule.update_encrypter_and_notify(common);
        Ok(())
    }
}

#[allow(dead_code)]
fn unused() -> Vec<u8> {
    vec![]
}
