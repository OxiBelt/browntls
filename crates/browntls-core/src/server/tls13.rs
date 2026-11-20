//! The TLS 1.3 server handshake (RFC 8446 §4).

mod client_auth;
mod early_data;
mod flight;
mod ticket;
mod traffic;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use client_auth::{ExpectCertificate, client_auth_sigschemes};
use early_data::{
    EarlyDataDecision, ExpectAndSkipRejectedEarlyData, ExpectEarlyData,
    decide_if_early_data_allowed, decide_if_external_early_data_allowed, max_early_data_size,
};
pub(super) use flight::hello_retry_request_message;
use flight::{
    HrrEch, choose_delegated_credential, emit_certificate_req_tls13, emit_certificate_tls13,
    emit_certificate_verify_tls13, emit_encrypted_extensions, emit_fake_ccs, emit_finished_tls13,
    emit_hello_retry_request, emit_server_hello, hello_retry_request,
};
use ticket::tls13_ticket_lifetime;
use traffic::ExpectFinished;

use super::common::{ActiveCertifiedKey, client_revocation_enabled};
use super::cookie::RetryCookie;
use super::hs::{self, HandshakeHashOrBuffer, NextStateOrError, ServerContext};
use super::server_conn::ServerConfig;
use crate::common_state::{ConnectionRandoms, HandshakeKind};
use crate::crypto::SupportedKxGroup;
use crate::ct::constant_time_eq;
use crate::delegated_credential::DelegatedCredentialKey;
use crate::ech::server::ServerEch;
use crate::enums::{AlertDescription, ProtocolVersion, SignatureScheme};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::debug;
use crate::msgs::codec::Codec;
use crate::msgs::enums::PskKeyExchangeMode;
use crate::msgs::handshake::{ClientHelloPayload, KeyShareEntry, SessionId};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist::ServerSessionValue;
use crate::psk::{ExternalPskCandidate, MAX_PSK_IDENTITIES_CONSIDERED, PskSecret};
use crate::sync::Arc;
use crate::tls13::Tls13CipherSuite;
use crate::tls13::key_schedule::{BinderLabel, KeyScheduleEarly, KeySchedulePreHandshake};

pub(super) struct CompleteClientHelloHandling {
    pub(super) config: Arc<ServerConfig>,
    pub(super) transcript: HandshakeHash,
    pub(super) suite: &'static Tls13CipherSuite,
    pub(super) randoms: ConnectionRandoms,
    pub(super) done_retry: bool,
    pub(super) send_tickets: usize,
    pub(super) cert_types: hs::NegotiatedCertTypes,
    /// The offered identities that name one of our external PSKs.
    pub(super) external_psks: Vec<ExternalPskCandidate>,
}

impl CompleteClientHelloHandling {
    /// Verifies a PSK binder (RFC 9846 §4.3.11.2) over the transcript so far
    /// plus the ClientHello without its binders, in constant time.
    fn check_binder(
        &self,
        suite: &'static Tls13CipherSuite,
        client_hello: &Message<'_>,
        psk: &[u8],
        label: BinderLabel,
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
        let real_binder = key_schedule.psk_binder(label, handshake_hash.as_ref());
        constant_time_eq(real_binder.as_ref(), binder)
    }

    fn attempt_tls13_ticket_decryption(&self, ticket: &[u8]) -> Option<ServerSessionValue> {
        // RFC 8844 §5: a bound connection resumes no session.
        if self.config.external_binding.is_some() {
            return None;
        }
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
        server_key: Option<ActiveCertifiedKey<'_>>,
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
        // RFC 8844: checked in each ClientHello, the second one included.
        crate::external_binding::handshake::server_check(
            cx.common,
            self.config.external_binding.as_ref(),
            &client_hello.extensions,
            true,
        )?;

        // Empty when the client sent no signature_algorithms, which it may
        // only do when offering a PSK (`hs::process_client_hello`); checked
        // once we know whether we authenticate with a certificate.
        let sigschemes_sent = !sigschemes_ext.is_empty();
        let sigschemes: Vec<SignatureScheme> = sigschemes_ext
            .into_iter()
            .filter(SignatureScheme::supported_in_tls13)
            .collect();

        // RFC 8446 §4.2.9: a PSK offer needs psk_key_exchange_modes.
        if client_hello.extensions.preshared_key.is_some()
            && client_hello.extensions.psk_modes.is_none()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::MissingExtension,
                PeerMisbehaved::MissingPskModesExtension,
            ));
        }

        // RFC 8446 §4.2.10: early_data may only appear in the first
        // ClientHello.
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
            let client_hello_hash = self.transcript.current_hash();
            self.transcript.rollup_for_hrr();
            let ech = match &cx.data.ech {
                ServerEch::Accepted(_) | ServerEch::Backend => {
                    HrrEch::Confirm(client_hello.random.0)
                }
                ServerEch::Rejected => HrrEch::Random,
                ServerEch::NotOffered => HrrEch::None,
            };
            // RFC 9846 §4.3.2: with a cookie sealer configured the retry is
            // stateless. Not when 0-RTT data follows the first ClientHello:
            // its records would reach a fresh connection ahead of the second
            // ClientHello, so that handshake stays with this connection. Nor
            // when the client offered ECH (RFC 9849): the HPKE context and
            // the HelloRetryRequest's ECH extension cannot be rebuilt from a
            // cookie.
            let cookie = match &self.config.hello_retry_cookies {
                Some(sealer) if !early_data_requested && matches!(ech, HrrEch::None) => {
                    RetryCookie {
                        issued_at: match self.config.current_time() {
                            Ok(now) => now.as_secs(),
                            Err(err) => {
                                return Err(cx
                                    .common
                                    .send_fatal_alert(AlertDescription::InternalError, err));
                            }
                        },
                        suite: self.suite.common.suite,
                        group: selected_kxg.name(),
                        client_hello_hash: client_hello_hash.as_ref().to_vec(),
                        session_id: client_hello.session_id,
                        server_name: cx
                            .data
                            .sni
                            .as_ref()
                            .map(|name| name.as_ref().as_bytes().to_vec())
                            .unwrap_or_default(),
                    }
                    .seal(&**sealer)
                }
                _ => None,
            };
            emit_hello_retry_request(
                &mut self.transcript,
                hello_retry_request(
                    self.suite,
                    client_hello.session_id,
                    selected_kxg.name(),
                    cookie.clone(),
                ),
                self.suite,
                ech,
                cx.common,
                self.config.provider.secure_random,
            )?;
            emit_fake_ccs(cx.common);
            cx.common.handshake_kind = Some(HandshakeKind::FullWithHelloRetryRequest);
            let skip_data_left = max_early_data_size(self.config.max_early_data_size);
            let next = Box::new(hs::ExpectClientHello {
                config: self.config,
                transcript: HandshakeHashOrBuffer::Hash(self.transcript),
                session_id: SessionId::empty(),
                done_retry: true,
                retry_choice: Some(hs::RetryChoice {
                    suite: self.suite,
                    group: selected_kxg,
                }),
                sent_cookie: cookie,
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

        // PSK selection (RFC 9846 §4.3.11): the first of the first
        // `MAX_PSK_IDENTITIES_CONSIDERED` identities that names an external
        // PSK or a resumption ticket usable with the suite we selected. Only
        // that PSK's binder is checked.
        let mut external_psks = core::mem::take(&mut self.external_psks);
        let mut chosen_psk_index = None;
        let mut resumedata = None;
        let mut external: Option<(ExternalPskCandidate, PskSecret)> = None;
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
                for (i, psk_id) in psk_offer
                    .identities
                    .iter()
                    .enumerate()
                    .take(MAX_PSK_IDENTITIES_CONSIDERED)
                {
                    if let Some(pos) = external_psks.iter().position(|c| c.index == i) {
                        let candidate = &external_psks[pos];
                        if !candidate.compatible_with(self.suite) {
                            continue;
                        }
                        let Some(secret) = candidate.secret(&self.config.provider.cipher_suites)
                        else {
                            continue;
                        };
                        if !self.check_binder(
                            self.suite,
                            chm,
                            secret.as_ref(),
                            candidate.binder_label(),
                            psk_offer.binders[i].as_ref(),
                        ) {
                            return Err(cx.common.send_fatal_alert(
                                AlertDescription::DecryptError,
                                PeerMisbehaved::IncorrectBinder,
                            ));
                        }
                        chosen_psk_index = Some(i);
                        external = Some((external_psks.swap_remove(pos), secret));
                        break;
                    }
                    let Some(resume) = self.attempt_tls13_ticket_decryption(&psk_id.identity.0)
                    else {
                        continue;
                    };
                    // Even a previous connection without a client
                    // certificate could bypass client authentication now.
                    if client_revocation_enabled(&self.config) && !resume.certificate_free {
                        continue;
                    }
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
                    // A session established with an external PSK resumes
                    // only while that PSK still resolves, unchanged, and is
                    // usable on this connection (ALPN, server name, suite);
                    // `require_external_psk` passes over other sessions.
                    let resumed_external = match &resume.external_psk {
                        Some(binding) => {
                            let Some(psk) = self
                                .config
                                .external_psks
                                .as_ref()
                                .and_then(|resolver| resolver.resolve(&binding.identity))
                                .filter(|psk| {
                                    binding.matches(
                                        psk,
                                        &self.config.provider.cipher_suites,
                                        &resume.master_secret.0,
                                    ) && psk.usable_by_server(
                                        cx.data.sni.as_ref(),
                                        cx.common.alpn_protocol.as_deref(),
                                    ) && psk
                                        .cipher_suite()
                                        .is_none_or(|cs| cs == self.suite.common.suite)
                                })
                            else {
                                continue;
                            };
                            Some(psk)
                        }
                        None if self.config.require_external_psk => continue,
                        None => None,
                    };
                    // A PSK past the lifetime we announced for it is not
                    // offered resumption (RFC 9846 §4.7.1).
                    let now = self.config.current_time()?;
                    if now.as_secs().saturating_sub(resume.creation_time_sec)
                        > u64::from(tls13_ticket_lifetime(&self.config))
                    {
                        continue;
                    }
                    if resume
                        .delegated_credential_expiry
                        .is_some_and(|expiry| now >= expiry)
                    {
                        continue;
                    }
                    if !self.check_binder(
                        self.suite,
                        chm,
                        &resume.master_secret.0,
                        BinderLabel::Resumption,
                        psk_offer.binders[i].as_ref(),
                    ) {
                        return Err(cx.common.send_fatal_alert(
                            AlertDescription::DecryptError,
                            PeerMisbehaved::IncorrectBinder,
                        ));
                    }
                    chosen_psk_index = Some(i);
                    // Reported once the client's Finished verifies.
                    cx.common.external_psk = resumed_external;
                    cx.data.delegated_credential_expiry = resume.delegated_credential_expiry;
                    resumedata = Some(resume.set_freshness(psk_id.obfuscated_ticket_age, now));
                    break;
                }
            }
        }

        if resumedata.is_some() {
            cx.common.handshake_kind = Some(HandshakeKind::Resumed);
        } else if cx.common.handshake_kind.is_none() {
            cx.common.handshake_kind = Some(HandshakeKind::Full);
        }
        if let Some((candidate, _)) = &external {
            debug!("Selected external PSK at index {}", candidate.index);
            // Reported once the client's Finished verifies.
            cx.common.external_psk = Some(candidate.psk.clone());
        }
        if self.config.require_external_psk && cx.common.external_psk.is_none() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::ExternalPskRequired,
            ));
        }

        // RFC 8773: certificate authentication on top of an external PSK,
        // when the client asked and we have a certificate to show.
        let cert_with_extern_psk = external.is_some()
            && self.config.cert_with_extern_psk
            && client_hello.extensions.cert_with_extern_psk.is_some()
            && server_key.is_some()
            && !sigschemes.is_empty();

        // Without a PSK (or with RFC 8773) we authenticate with our
        // certificate, which needs one and a signature scheme for it.
        let psk_selected = resumedata.is_some() || external.is_some();
        let server_key = match server_key {
            Some(key) if !psk_selected || cert_with_extern_psk => {
                if !sigschemes_sent {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::MissingExtension,
                        PeerIncompatible::SignatureAlgorithmsExtensionRequired,
                    ));
                }
                if sigschemes.is_empty() {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::HandshakeFailure,
                        PeerIncompatible::NoSignatureSchemesInCommon,
                    ));
                }
                Some(key)
            }
            None if !psk_selected => {
                if self.config.external_psks.is_some() {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::HandshakeFailure,
                        PeerIncompatible::NoUsablePskForServerWithoutCertificate,
                    ));
                }
                return Err(hs::no_server_certificate(cx));
            }
            _ => None,
        };
        cx.data.certificate_free = (external.is_some() && server_key.is_none())
            || resumedata
                .as_ref()
                .is_some_and(|resume| resume.certificate_free);

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

        let early_data = match &external {
            Some((candidate, _)) => decide_if_external_early_data_allowed(
                cx,
                early_data_requested,
                candidate,
                self.suite,
                cert_with_extern_psk,
            ),
            None => decide_if_early_data_allowed(
                cx,
                early_data_requested,
                chosen_psk_index.zip(resumedata.as_ref()),
                self.suite,
                &self.config,
            ),
        };
        // How much 0-RTT data we read, or skip when we reject it.
        let early_data_limit = match &external {
            Some((candidate, _)) => candidate.psk.max_early_data_size(),
            None => self.config.max_early_data_size,
        };
        let skip_early_data_limit =
            max_early_data_size(self.config.max_early_data_size).max(early_data_limit as usize);

        let client_hello_hash = self.transcript.current_hash();
        let psk_secret: Option<&[u8]> = match (&resumedata, &external) {
            (Some(resume), _) => Some(&resume.master_secret.0),
            (None, Some((_, secret))) => Some(secret.as_ref()),
            (None, None) => None,
        };
        let key_schedule_pre = match psk_secret {
            Some(psk) => {
                let early = KeyScheduleEarly::new(self.suite, psk);
                // Start reading under the early traffic key: it carries any
                // 0-RTT data, and is replaced below when we do not accept it.
                early.client_early_traffic_secret(
                    client_hello_hash.as_ref(),
                    &*self.config.key_log,
                    &self.randoms.client,
                    cx.common,
                );
                // RFC 9846 §7.5: the early exporter, for use with the 0-RTT
                // data we accepted.
                if early_data == EarlyDataDecision::Accepted {
                    cx.common.early_exporter = Some(early.early_exporter(
                        client_hello_hash.as_ref(),
                        &*self.config.key_log,
                        &self.randoms.client,
                    ));
                }
                early.into_pre_handshake()
            }
            None => KeySchedulePreHandshake::new(self.suite),
        };
        let key_schedule = key_schedule_pre.into_handshake_with_shared_secret(&kx.secret);

        let ech_accepted = cx.data.ech.is_accepted();
        emit_server_hello(
            &mut self.transcript,
            &mut self.randoms,
            self.suite,
            cx.common,
            &client_hello.session_id,
            chosen_psk_index,
            KeyShareEntry::new(selected_kxg.name(), &kx.pub_key),
            ech_accepted,
            cert_with_extern_psk,
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

        // A QUIC server exposes 0-RTT keys only when it accepts early data.
        if !matches!(early_data, EarlyDataDecision::Accepted)
            && let Some(quic) = cx.common.quic.as_mut()
        {
            quic.clear_early_secret();
        }

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
                key_schedule.set_handshake_decrypter(Some(skip_early_data_limit), cx.common);
                cx.data.early_data.reject();
            }
            // QUIC carries 0-RTT data in its own packets (RFC 9001 §4.6.1);
            // nothing arrives through TLS.
            EarlyDataDecision::Accepted if cx.common.is_quic() => {
                cx.data.early_data.accept(0);
            }
            EarlyDataDecision::Accepted => {
                cx.data.early_data.accept(early_data_limit as usize);
            }
        }

        // RFC 9846 §4.3.7: when the group we would most like is not the one
        // the client's key shares let us use, say which groups we prefer so
        // the client can do better next time.
        let our_groups =
            hs::kx_groups_by_preference(self.config.kx_groups(), ProtocolVersion::TLSv1_3);
        let most_preferred_mutual = client_hello.named_groups().and_then(|theirs| {
            our_groups
                .iter()
                .find(|g| theirs.contains(&g.name()))
                .map(|g| g.name())
        });
        let supported_groups = (most_preferred_mutual.is_some()
            && most_preferred_mutual != Some(selected_kxg.name()))
        .then(|| our_groups.iter().map(|g| g.name()).collect());

        // RFC 9846 §4.3.6: the client is willing to authenticate later.
        // RFC 9001 §4.4: QUIC has no post-handshake client authentication,
        // so an offer over QUIC is ignored and client auth stays in the
        // handshake.
        cx.data.post_handshake_auth_offered =
            client_hello.extensions.post_handshake_auth.is_some() && !cx.common.is_quic();
        let defer_client_auth =
            self.config.request_client_auth_after_handshake && cx.data.post_handshake_auth_offered;

        // RFC 9846 §4.7.1 and RFC 9149: how many tickets follow, announced
        // in EncryptedExtensions when the client sent ticket_request.
        let (mut send_tickets, mut expected_tickets) =
            hs::tls13_tickets_to_send(&self.config, client_hello, resumedata.is_some());
        // RFC 8844 §5: no session of a bound connection is kept for later.
        if (client_revocation_enabled(&self.config) && !cx.data.certificate_free)
            || self.config.external_binding.is_some()
        {
            send_tickets = 0;
            expected_tickets = expected_tickets.map(|_| 0);
        }
        self.send_tickets = send_tickets;

        // RFC 9849 §7.1: a client whose ECH extension did not decrypt gets
        // our current configurations to retry with.
        let retry_configs = match (&cx.data.ech, &self.config.ech) {
            (ServerEch::Rejected, Some(ech)) => Some(ech.ech_config_list().to_vec()),
            _ => None,
        };
        emit_encrypted_extensions(
            &mut self.transcript,
            cx,
            &self.config,
            client_hello,
            early_data == EarlyDataDecision::Accepted,
            self.cert_types,
            supported_groups,
            retry_configs,
            expected_tickets,
        );

        let doing_client_auth = if let Some(server_key) = server_key {
            let client_auth = !defer_client_auth
                && emit_certificate_req_tls13(&mut self.transcript, cx.common, &self.config)?;
            let delegated = choose_delegated_credential(
                &self.config,
                &server_key,
                client_hello,
                &sigschemes,
                self.cert_types,
            );
            cx.data.delegated_credential_expiry = delegated.map(DelegatedCredentialKey::expiry);
            emit_certificate_tls13(
                &mut self.transcript,
                cx.common,
                &self.config,
                server_key.certified_key(),
                client_hello,
                delegated,
            );
            emit_certificate_verify_tls13(
                &mut self.transcript,
                cx.common,
                &server_key,
                &sigschemes,
                delegated,
            )?;
            client_auth
        } else {
            false
        };

        if let Some(resume) = &resumedata {
            cx.data.received_resumption_data = Some(resume.application_data.0.clone());
            cx.common.peer_certificates = resume.client_cert_chain.clone();
        }

        let key_schedule = emit_finished_tls13(
            &mut self.transcript,
            &self.randoms,
            cx,
            key_schedule,
            &self.config,
        );

        // Not ahead of a client certificate whose revocation status is
        // still to be evaluated: nothing is sent to that client before.
        if self.config.send_half_rtt_data
            && !(doing_client_auth && client_revocation_enabled(&self.config))
        {
            cx.common.start_outgoing_traffic();
        }

        if doing_client_auth {
            // RFC 9846 §4.5.2: the client's CertificateVerify must use a
            // scheme from our CertificateRequest, which lists only the
            // verifier's TLS 1.3 schemes.
            let offered_sigschemes = client_auth_sigschemes(&self.config);
            Ok(Box::new(ExpectCertificate {
                config: self.config,
                transcript: self.transcript,
                suite: self.suite,
                key_schedule,
                send_tickets: self.send_tickets,
                offered_sigschemes,
            }))
        } else if early_data == EarlyDataDecision::Accepted && !cx.common.is_quic() {
            // RFC 9001 §8.3: on QUIC no EndOfEarlyData ends the early data;
            // the client's Finished follows directly.
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

#[allow(dead_code)]
fn unused() -> Vec<u8> {
    vec![]
}
