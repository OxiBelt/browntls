//! Full and abbreviated ServerHello handling, including RFC 5077
//! empty-session-ID discrimination over DTLS.

use super::*;

pub(in crate::client) struct CompleteServerHelloHandling {
    pub(in crate::client) config: Arc<ClientConfig>,
    pub(in crate::client) resuming_session: Option<persist::Tls12ClientSessionValue>,
    pub(in crate::client) server_name: ServerName<'static>,
    pub(in crate::client) randoms: ConnectionRandoms,
    pub(in crate::client) using_ems: bool,
    pub(in crate::client) using_etm: bool,
    pub(in crate::client) transcript: HandshakeHash,
    pub(in crate::client) hello: ClientHelloDetails,
    pub(in crate::client) alpn_protocols: Vec<Vec<u8>>,
}

impl CompleteServerHelloHandling {
    pub(in crate::client) fn handle_server_hello(
        mut self,
        cx: &mut ClientContext<'_>,
        suite: &'static Tls12CipherSuite,
        server_hello: &ServerHelloPayload,
        tls13_supported: bool,
    ) -> NextStateOrError {
        let _ = tls13_supported;

        // RFC 5746 §3.4: on an initial handshake the server's
        // renegotiation_info is empty.
        if let Some(ri) = &server_hello.extensions.renegotiation_info
            && !ri.0.is_empty()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerMisbehaved::UnsolicitedServerHelloExtension,
            ));
        }
        // RFC 9325 §3.5: a TLS 1.2 server that does not acknowledge
        // renegotiation_info is unsafe to talk to (RFC 5746 §4.1), whether
        // or not either side ever renegotiates.
        if self.config.require_secure_renegotiation
            && server_hello.extensions.renegotiation_info.is_none()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::SecureRenegotiationExtensionRequired,
            ));
        }
        // RFC 7366 §3: encrypt_then_mac applies to block ciphers only, and a
        // server must not acknowledge it after selecting an AEAD suite.
        if self.using_etm && !suite.record.is_block_cipher() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::EncryptThenMacWithAeadCipherSuite,
            ));
        }
        // RFC 9325 §4.2: a CBC suite should not be used without
        // encrypt_then_mac.
        if suite.record.is_block_cipher() && !self.using_etm && !self.config.allow_mac_then_encrypt
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::EncryptThenMacExtensionRequired,
            ));
        }
        // RFC 8422 §5.2: only uncompressed points are used.
        if let Some(formats) = &server_hello.extensions.ec_point_formats
            && !formats.contains(&ECPointFormat::Uncompressed)
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerMisbehaved::ServerHelloMustOfferUncompressedEcPoints,
            ));
        }
        // TLS 1.3-only extensions may not appear in a TLS 1.2 ServerHello
        // (RFC 9149 defines `ticket_request` for TLS 1.3 only).
        if server_hello.extensions.key_share.is_some()
            || server_hello.extensions.pre_shared_key.is_some()
            || server_hello.extensions.ticket_request.is_some()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerMisbehaved::UnsolicitedServerHelloExtension,
            ));
        }

        hs::process_alpn_protocol(
            cx.common,
            &self.alpn_protocols,
            server_hello.extensions.alpn.as_ref().map(|p| p.as_ref()),
        )?;
        hs::process_cert_type_extensions(
            cx.common,
            &self.config,
            server_hello.extensions.client_certificate_type,
            server_hello.extensions.server_certificate_type,
        )?;
        // RFC 8449 §4: in TLS 1.2 the server's limit comes in the ServerHello.
        hs::process_record_size_limit(
            cx.common,
            &self.hello,
            server_hello.extensions.record_size_limit,
            false,
        )?;
        crate::external_binding::handshake::client_check(
            cx.common,
            self.config.external_binding.as_ref(),
            &server_hello.extensions,
            false,
            false,
        )?;
        // RFC 7924 §4: which messages the server replaces by fingerprints.
        cached_info::process_server_hello(
            cx.common,
            self.hello.cached_info.as_mut(),
            server_hello.extensions.cached_info.as_ref(),
        )?;

        if (self.config.require_ems || cx.common.is_dtls()) && !self.using_ems {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::ExtendedMasterSecretExtensionRequired,
            ));
        }

        let must_issue_new_ticket = server_hello.extensions.session_ticket_ack.is_some();

        // RFC 5077 section 3.4: with an empty ClientHello session ID,
        // Certificate means a full handshake; NewSessionTicket or CCS
        // means an abbreviated handshake. A dual-version DTLS client
        // cannot invent a compatibility ID (RFC 9147 section 5.3).
        if cx.common.is_dtls()
            && server_hello.session_id.is_empty()
            && self
                .resuming_session
                .as_ref()
                .is_some_and(|s| s.session_id.is_empty() && !s.ticket().is_empty())
        {
            return Ok(Box::new(ExpectCertificateOrResume {
                pending: self,
                suite,
                hello: server_hello.clone(),
                must_issue_new_ticket,
            }));
        }

        if let Some(resuming) = self.resuming_session.take() {
            if !server_hello.session_id.is_empty() && resuming.session_id == server_hello.session_id
            {
                return self.resume(cx, suite, server_hello, resuming, must_issue_new_ticket);
            }
            // The server declined; forget the stale session.
            if cx.common.is_dtls() {
                self.config
                    .resumption
                    .store
                    .remove_dtls12_session(&self.server_name);
            } else {
                self.config
                    .resumption
                    .store
                    .remove_tls12_session(&self.server_name);
            }
        }

        self.full(cx, suite, server_hello, must_issue_new_ticket)
    }

    fn resume(
        self,
        cx: &mut ClientContext<'_>,
        suite: &'static Tls12CipherSuite,
        server_hello: &ServerHelloPayload,
        resuming: persist::Tls12ClientSessionValue,
        must_issue_new_ticket: bool,
    ) -> NextStateOrError {
        debug!("Server agreed to resume");
        crate::client::transparency::refuse_on_resumption(cx.common, &server_hello.extensions)?;
        if resuming.suite() != suite {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerMisbehaved::ResumptionOfferedWithVariedCipherSuite,
            ));
        }
        if resuming.extended_ms() != self.using_ems {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerMisbehaved::ResumptionOfferedWithVariedEms,
            ));
        }

        let secrets = ConnectionSecrets::new_resume(
            self.randoms,
            suite,
            resuming.secret(),
            resuming.extended_ms(),
        );
        self.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            secrets.master_secret(),
        );
        cx.common
            .start_encryption_tls12(&secrets, Side::Client, mac_order(self.using_etm));
        cx.common.peer_certificates = Some(resuming.server_cert_chain().clone());
        cx.common.handshake_kind = Some(HandshakeKind::Resumed);
        if let Some(dtls) = &mut cx.common.dtls {
            dtls.set_v12_resuming();
        }
        cx.common.kx_state = KxState::Start;

        let next = ExpectCcs {
            config: self.config,
            secrets,
            resuming_session: Some(resuming),
            session_id: server_hello.session_id,
            server_name: self.server_name,
            using_ems: self.using_ems,
            transcript: self.transcript,
            ticket: None,
            resuming: true,
            cert_verified: ServerCertVerified::assertion(),
            sig_verified: HandshakeSignatureValid::assertion(),
            cached_info: None,
        };
        // RFC 5077 §3.3: a new ticket, if any, precedes
        // ChangeCipherSpec.
        Ok(if must_issue_new_ticket {
            Box::new(ExpectNewTicket { next })
        } else {
            Box::new(next)
        })
    }

    fn full(
        mut self,
        cx: &mut ClientContext<'_>,
        suite: &'static Tls12CipherSuite,
        server_hello: &ServerHelloPayload,
        must_issue_new_ticket: bool,
    ) -> NextStateOrError {
        if cx.common.handshake_kind.is_none() {
            cx.common.handshake_kind = Some(HandshakeKind::Full);
        }
        cached_info::expect_hash_forms(cx.common, self.hello.cached_info.as_ref());
        // RFC 6066 §6: the server says our trusted_ca_keys guided its
        // choice of chain (unsolicited, it was refused above). Only a full
        // handshake sends a chain, so a resumed one never records it.
        cx.data.trusted_ca_keys_acknowledged =
            server_hello.extensions.trusted_ca_keys_ack.is_some();

        if let Some(list) = &server_hello.extensions.sct_list {
            crate::msgs::handshake::CertificatePayloadTls13::validate_sct_list(list.bytes())
                .map_err(|e| cx.common.send_fatal_alert(AlertDescription::DecodeError, e))?;
        }

        // RFC 6066 §5; an acknowledgement we did not ask for was refused
        // above as unsolicited.
        self.hello.certificate_url_accepted =
            server_hello.extensions.client_certificate_url.is_some();
        Ok(Box::new(ExpectCertificate {
            config: self.config,
            session_id: server_hello.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            using_etm: self.using_etm,
            transcript: self.transcript,
            suite,
            may_send_cert_status: server_hello.extensions.status_request_ack.is_some(),
            sct_list: server_hello
                .extensions
                .sct_list
                .as_ref()
                .map(|list| list.bytes().to_vec()),
            transparency_info: server_hello
                .extensions
                .transparency_info
                .as_ref()
                .map(|list| list.bytes().to_vec()),
            must_issue_new_ticket,
            hello: self.hello,
        }))
    }
}

/// The server's first message after an ambiguous ticket ServerHello.
struct ExpectCertificateOrResume {
    pending: CompleteServerHelloHandling,
    suite: &'static Tls12CipherSuite,
    hello: ServerHelloPayload,
    must_issue_new_ticket: bool,
}

impl State<ClientConnectionData> for ExpectCertificateOrResume {
    fn expects_dtls12_ccs(&self) -> bool {
        !self.must_issue_new_ticket
    }

    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        let mut st = *self;
        if matches!(
            &m.payload,
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::Certificate(_)),
                ..
            }
        ) {
            st.pending
                .config
                .resumption
                .store
                .remove_dtls12_session(&st.pending.server_name);
            st.pending.resuming_session = None;
            return st
                .pending
                .full(cx, st.suite, &st.hello, st.must_issue_new_ticket)?
                .handle(cx, m);
        }
        let resuming = st
            .pending
            .resuming_session
            .take()
            .ok_or_else(|| Error::General("missing DTLS 1.2 ticket candidate".into()))?;
        st.pending
            .resume(cx, st.suite, &st.hello, resuming, st.must_issue_new_ticket)?
            .handle(cx, m)
    }
}
