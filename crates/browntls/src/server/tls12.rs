//! The TLS 1.2 server handshake (RFC 5246 §7.3, RFC 8422, RFC 7627, RFC 5077,
//! RFC 5746).

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use super::common::ActiveCertifiedKey;
use super::hs::{self, NextStateOrError, ServerContext};
use super::server_conn::{ServerConfig, ServerConnectionData};
use crate::common_state::{CommonState, ConnectionRandoms, HandshakeKind, Side};
use crate::conn::State;
use crate::crypto::cipher::Tls12MacOrder;
use crate::crypto::{ActiveKeyExchange, SupportedKxGroup};
use crate::ct::constant_time_eq;
use crate::enums::{
    AlertDescription, CipherSuite, ContentType, HandshakeType, ProtocolVersion, SignatureScheme,
};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace, warning};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::codec::Codec;
use crate::msgs::enums::{ClientCertificateType, Compression, ECPointFormat};
use crate::msgs::handshake::{
    CertificateChain, CertificateRequestPayload, CertificateStatus, ClientEcdhParams,
    ClientHelloPayload, ClientSessionTicket, DOWNGRADE_SENTINEL_TLS12, HandshakeMessagePayload,
    HandshakePayload, NewSessionTicketPayload, ServerEcdhParams, ServerExtensions,
    ServerHelloPayload, ServerKeyExchange, ServerKeyExchangeParams, ServerKeyExchangePayload,
    SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist::ServerSessionValue;
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls12::{ConnectionSecrets, Tls12CipherSuite};
use crate::verify::{DigitallySignedStruct, FinishedMessageVerified};

/// How many unsolicited ClientHellos (renegotiation attempts) we tolerate.
const MAX_RENEGOTIATION_REQUESTS: u8 = 16;

/// The MAC order negotiated for a block cipher suite (RFC 7366).
fn mac_order(using_etm: bool) -> Tls12MacOrder {
    if using_etm {
        Tls12MacOrder::EncryptThenMac
    } else {
        Tls12MacOrder::MacThenEncrypt
    }
}

pub(super) struct CompleteClientHelloHandling {
    pub(super) config: Arc<ServerConfig>,
    pub(super) transcript: HandshakeHash,
    pub(super) session_id: SessionId,
    pub(super) suite: &'static Tls12CipherSuite,
    pub(super) using_ems: bool,
    pub(super) using_etm: bool,
    pub(super) randoms: ConnectionRandoms,
    pub(super) send_ticket: bool,
    pub(super) cert_types: hs::NegotiatedCertTypes,
}

impl CompleteClientHelloHandling {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_client_hello(
        mut self,
        cx: &mut ServerContext<'_>,
        server_key: ActiveCertifiedKey<'_>,
        chm: &Message<'_>,
        client_hello: &ClientHelloPayload,
        selected_kxg: &'static dyn SupportedKxGroup,
        sigschemes_ext: Vec<SignatureScheme>,
        tls13_enabled: bool,
    ) -> NextStateOrError {
        // RFC 8446 §4.1.3: a TLS 1.3-capable server negotiating TLS 1.2 marks
        // its random so a downgraded client can detect the downgrade.
        if tls13_enabled {
            self.randoms.server[24..].copy_from_slice(&DOWNGRADE_SENTINEL_TLS12);
        }

        // RFC 5746 §3.6: an initial handshake's renegotiation_info is empty.
        if let Some(ri) = &client_hello.extensions.renegotiation_info
            && !ri.0.is_empty()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerMisbehaved::UnexpectedCleartextExtension,
            ));
        }
        let client_supports_secure_renegotiation = client_hello
            .cipher_suites
            .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
            || client_hello.extensions.renegotiation_info.is_some();

        let sigschemes = self.suite.resolve_sig_schemes(&sigschemes_ext);
        if sigschemes.is_empty() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::NoSignatureSchemesInCommon,
            ));
        }

        self.transcript.add_message(chm);

        let ticket_requested = client_hello.extensions.session_ticket.is_some();

        // RFC 5077 §3.4: a ticket takes precedence over a session ID.
        if let Some(ClientSessionTicket::Offer(ticket)) = &client_hello.extensions.session_ticket
            && let Some(resume) = self
                .config
                .ticketer
                .decrypt(ticket.bytes())
                .and_then(|plain| ServerSessionValue::read_bytes(&plain).ok())
            && hs::can_resume(self.suite.into(), &cx.data.sni, self.using_ems, &resume)
        {
            return self.start_resumption(
                cx,
                client_hello,
                &client_hello.session_id,
                resume,
                ticket_requested,
            );
        }

        if !client_hello.session_id.is_empty()
            && let Some(resume) = self
                .config
                .session_storage
                .get(client_hello.session_id.as_ref())
                .and_then(|plain| ServerSessionValue::read_bytes(&plain).ok())
            && hs::can_resume(self.suite.into(), &cx.data.sni, self.using_ems, &resume)
        {
            // The entry stays in the cache for later resumptions unless this
            // connection fails (RFC 5246 §7.2.2).
            cx.data.tls12_session = Some((
                self.config.session_storage.clone(),
                client_hello.session_id.as_ref().to_vec(),
            ));
            return self.start_resumption(
                cx,
                client_hello,
                &client_hello.session_id,
                resume,
                ticket_requested,
            );
        }

        // Full handshake.
        self.send_ticket = ticket_requested && self.config.ticketer.enabled();
        self.session_id = if !self.send_ticket && self.config.session_storage.can_cache() {
            SessionId::random(self.config.provider.secure_random)?
        } else {
            SessionId::empty()
        };
        cx.common.handshake_kind = Some(HandshakeKind::Full);

        let ocsp = client_hello
            .extensions
            .certificate_status_request
            .as_ref()
            .and_then(|_| server_key.get_ocsp());

        self.emit_server_hello(
            cx,
            client_hello,
            client_supports_secure_renegotiation,
            ocsp.is_some(),
            false,
        );
        emit_certificate(&mut self.transcript, cx.common, server_key.get_cert());
        if let Some(ocsp) = ocsp {
            emit_cert_status(&mut self.transcript, cx.common, ocsp);
        }
        let kx = emit_server_kx(
            &mut self.transcript,
            cx.common,
            &sigschemes,
            selected_kxg,
            server_key.get_key(),
            &self.randoms,
        )?;
        let doing_client_auth =
            emit_certificate_req(&mut self.transcript, cx.common, &self.config)?;
        emit_server_hello_done(&mut self.transcript, cx.common);

        if doing_client_auth {
            Ok(Box::new(ExpectCertificate {
                config: self.config,
                transcript: self.transcript,
                randoms: self.randoms,
                session_id: self.session_id,
                suite: self.suite,
                using_ems: self.using_ems,
                using_etm: self.using_etm,
                server_kx: kx,
                send_ticket: self.send_ticket,
            }))
        } else {
            Ok(Box::new(ExpectClientKx {
                config: self.config,
                transcript: self.transcript,
                randoms: self.randoms,
                session_id: self.session_id,
                suite: self.suite,
                using_ems: self.using_ems,
                using_etm: self.using_etm,
                server_kx: kx,
                client_cert: None,
                send_ticket: self.send_ticket,
            }))
        }
    }

    fn start_resumption(
        mut self,
        cx: &mut ServerContext<'_>,
        client_hello: &ClientHelloPayload,
        id: &SessionId,
        resumedata: ServerSessionValue,
        ticket_requested: bool,
    ) -> NextStateOrError {
        debug!("Resuming connection");

        // RFC 7627 §5.3: a session may not drop the extended master secret.
        if resumedata.extended_ms && !self.using_ems {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerMisbehaved::ResumptionAttemptedWithVariedEms,
            ));
        }

        let client_supports_secure_renegotiation = client_hello
            .cipher_suites
            .contains(&CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
            || client_hello.extensions.renegotiation_info.is_some();

        self.session_id = *id;
        self.send_ticket = ticket_requested && self.config.ticketer.enabled();
        self.emit_server_hello(
            cx,
            client_hello,
            client_supports_secure_renegotiation,
            false,
            true,
        );

        let secrets = ConnectionSecrets::new_resume(
            self.randoms,
            self.suite,
            &resumedata.master_secret.0,
            resumedata.extended_ms,
        );
        self.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            secrets.master_secret(),
        );
        cx.common
            .start_encryption_tls12(&secrets, Side::Server, mac_order(self.using_etm));
        cx.common.peer_certificates = resumedata.client_cert_chain.clone();
        cx.data.received_resumption_data = Some(resumedata.application_data.0.clone());
        cx.common.handshake_kind = Some(HandshakeKind::Resumed);

        if self.send_ticket {
            let value = make_session_value(cx, &self.config, &secrets, self.suite, self.using_ems)?;
            emit_ticket(&mut self.transcript, cx.common, &self.config, value)?;
        }
        cx.common.send_change_cipher_spec();
        emit_finished(&secrets, &mut self.transcript, cx.common);

        Ok(Box::new(ExpectCcs {
            config: self.config,
            secrets,
            transcript: self.transcript,
            session_id: self.session_id,
            using_ems: self.using_ems,
            resuming: true,
            send_ticket: false,
        }))
    }

    fn emit_server_hello(
        &mut self,
        cx: &mut ServerContext<'_>,
        client_hello: &ClientHelloPayload,
        secure_renegotiation: bool,
        staple_ocsp: bool,
        resuming: bool,
    ) {
        let extensions = ServerExtensions {
            // RFC 5746 §3.6: echo an empty renegotiation_info to a capable client.
            renegotiation_info: secure_renegotiation.then(PayloadU8::empty),
            extended_master_secret: self.using_ems.then_some(()),
            // RFC 7366 §2: acknowledged only for a block cipher suite.
            encrypt_then_mac: self.using_etm.then_some(()),
            // RFC 8422 §5.2: we only send uncompressed points.
            ec_point_formats: client_hello
                .extensions
                .ec_point_formats
                .as_ref()
                .map(|_| vec![ECPointFormat::Uncompressed]),
            session_ticket_ack: self.send_ticket.then_some(()),
            status_request_ack: staple_ocsp.then_some(()),
            client_certificate_type: self.cert_types.client,
            server_certificate_type: self.cert_types.server,
            alpn: cx
                .common
                .alpn_protocol
                .clone()
                .map(crate::msgs::handshake::ProtocolName::from),
            // RFC 6066 §3: never acknowledged when resuming a session.
            server_name_ack: (!resuming)
                .then(|| client_hello.sni().map(|_| ()))
                .flatten(),
            ..Default::default()
        };
        let sh = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ServerHello(ServerHelloPayload {
                    legacy_version: ProtocolVersion::TLSv1_2,
                    random: self.randoms.server.into(),
                    session_id: self.session_id,
                    cipher_suite: self.suite.common.suite,
                    compression_method: Compression::Null,
                    extensions,
                }),
            )),
        };
        trace!("sending server hello {:?}", sh);
        self.transcript.add_message(&sh);
        cx.common.send_msg(sh, false);
    }
}

fn emit_certificate(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    certs: &[browntls_pki::CertificateDer<'static>],
) {
    let chain = CertificateChain(
        certs
            .iter()
            .map(|c| browntls_pki::CertificateDer::from_slice(c.as_ref()))
            .collect(),
    );
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::Certificate(
            chain,
        ))),
    };
    transcript.add_message(&m);
    common.send_msg(m, false);
}

fn emit_cert_status(transcript: &mut HandshakeHash, common: &mut CommonState, ocsp: &[u8]) {
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::CertificateStatus(CertificateStatus::new(ocsp)),
        )),
    };
    transcript.add_message(&m);
    common.send_msg(m, false);
}

fn emit_server_kx(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    sigschemes: &[SignatureScheme],
    group: &'static dyn SupportedKxGroup,
    signing_key: &dyn crate::sign::SigningKey,
    randoms: &ConnectionRandoms,
) -> Result<Box<dyn ActiveKeyExchange>, Error> {
    let kx = group.start()?;
    let params = ServerEcdhParams::new(group.name(), kx.pub_key());

    // RFC 5246 §7.4.3: sign client_random || server_random || params.
    let mut msg = Vec::with_capacity(64 + 128);
    msg.extend_from_slice(&randoms.client);
    msg.extend_from_slice(&randoms.server);
    params.encode(&mut msg);

    let signer = signing_key.choose_scheme(sigschemes).ok_or_else(|| {
        common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            PeerIncompatible::NoSignatureSchemesInCommon,
        )
    })?;
    let sig = signer.sign(&msg)?;
    let skx = ServerKeyExchange {
        params: ServerKeyExchangeParams::Ecdh(params),
        dss: DigitallySignedStruct::new(signer.scheme(), sig),
    };
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::ServerKeyExchange(ServerKeyExchangePayload::Known(skx)),
        )),
    };
    transcript.add_message(&m);
    common.send_msg(m, false);
    Ok(kx)
}

/// Sends a CertificateRequest if the configuration wants client authentication.
fn emit_certificate_req(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    config: &ServerConfig,
) -> Result<bool, Error> {
    if !config.verifier.offer_client_auth() {
        return Ok(false);
    }
    let sigschemes = config.verifier.supported_verify_schemes();
    if sigschemes.is_empty() {
        return Err(Error::general(
            "client certificate verifier supports no signature schemes",
        ));
    }
    let cr = CertificateRequestPayload {
        certtypes: vec![
            ClientCertificateType::RSASign,
            ClientCertificateType::ECDSASign,
        ],
        sigschemes,
        canames: config.verifier.root_hint_subjects().to_vec(),
    };
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::CertificateRequest(cr),
        )),
    };
    trace!("Sending CertificateRequest {:?}", m);
    transcript.add_message(&m);
    common.send_msg(m, false);
    Ok(true)
}

fn emit_server_hello_done(transcript: &mut HandshakeHash, common: &mut CommonState) {
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::ServerHelloDone,
        )),
    };
    transcript.add_message(&m);
    common.send_msg(m, false);
}

fn emit_finished(
    secrets: &ConnectionSecrets,
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
) {
    let vh = transcript.current_hash();
    let verify_data = secrets.server_verify_data(&vh);
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::Finished(
            Payload::new(verify_data),
        ))),
    };
    transcript.add_message(&m);
    common.send_msg(m, true);
}

fn make_session_value(
    cx: &mut ServerContext<'_>,
    config: &ServerConfig,
    secrets: &ConnectionSecrets,
    suite: &'static Tls12CipherSuite,
    using_ems: bool,
) -> Result<ServerSessionValue, Error> {
    let now = config.current_time()?;
    let mut value = ServerSessionValue::new(
        cx.data.sni.as_ref(),
        ProtocolVersion::TLSv1_2,
        suite.common.suite,
        secrets.master_secret(),
        cx.common.peer_certificates.clone(),
        cx.common.alpn_protocol.clone(),
        cx.data.resumption_data.clone(),
        now,
        0,
    );
    if using_ems {
        value.set_extended_ms_used();
    }
    Ok(value)
}

/// Sends a NewSessionTicket (RFC 5077 §3.3) holding `value`.
fn emit_ticket(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
    config: &ServerConfig,
    value: ServerSessionValue,
) -> Result<(), Error> {
    let Some(ticket) = config.ticketer.encrypt(&value.get_encoding()) else {
        // A failed encryption yields an empty ticket, which the client ignores.
        return emit_empty_ticket(transcript, common);
    };
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::NewSessionTicket(NewSessionTicketPayload::new(
                config.ticketer.lifetime(),
                ticket,
            )),
        )),
    };
    transcript.add_message(&m);
    common.send_msg(m, false);
    Ok(())
}

fn emit_empty_ticket(
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
) -> Result<(), Error> {
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::NewSessionTicket(NewSessionTicketPayload::new(0, Vec::new())),
        )),
    };
    transcript.add_message(&m);
    common.send_msg(m, false);
    Ok(())
}

struct ExpectCertificate {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    randoms: ConnectionRandoms,
    session_id: SessionId,
    suite: &'static Tls12CipherSuite,
    using_ems: bool,
    using_etm: bool,
    server_kx: Box<dyn ActiveKeyExchange>,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectCertificate {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        let cert_chain =
            require_handshake_msg!(m, HandshakeType::Certificate, HandshakePayload::Certificate)?;
        self.transcript.add_message(&m);
        let cert_chain = cert_chain.clone().into_owned();

        let Some((end_entity, intermediates)) = cert_chain.0.split_first() else {
            // RFC 5246 §7.4.6: an empty list is allowed unless we insist.
            if self.config.verifier.client_auth_mandatory() {
                // RFC 5246 §7.4.6: a missing mandatory certificate is a
                // handshake_failure (certificate_required is TLS 1.3 only).
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::HandshakeFailure,
                    Error::NoCertificatesPresented,
                ));
            }
            debug!("client auth requested but no certificate supplied");
            return Ok(Box::new(ExpectClientKx {
                config: self.config,
                transcript: self.transcript,
                randoms: self.randoms,
                session_id: self.session_id,
                suite: self.suite,
                using_ems: self.using_ems,
                using_etm: self.using_etm,
                server_kx: self.server_kx,
                client_cert: None,
                send_ticket: self.send_ticket,
            }));
        };

        let now = self.config.current_time()?;
        self.config
            .verifier
            .verify_client_cert(end_entity, intermediates, now)
            .map_err(|err| crate::client::tls13::send_cert_path_error_alert(cx.common, err))?;

        Ok(Box::new(ExpectClientKx {
            config: self.config,
            transcript: self.transcript,
            randoms: self.randoms,
            session_id: self.session_id,
            suite: self.suite,
            using_ems: self.using_ems,
            using_etm: self.using_etm,
            server_kx: self.server_kx,
            client_cert: Some(cert_chain),
            send_ticket: self.send_ticket,
        }))
    }
}

struct ExpectClientKx {
    config: Arc<ServerConfig>,
    transcript: HandshakeHash,
    randoms: ConnectionRandoms,
    session_id: SessionId,
    suite: &'static Tls12CipherSuite,
    using_ems: bool,
    using_etm: bool,
    server_kx: Box<dyn ActiveKeyExchange>,
    client_cert: Option<CertificateChain<'static>>,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectClientKx {
    fn handle(self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        let mut st = *self;
        let client_kx = require_handshake_msg!(
            m,
            HandshakeType::ClientKeyExchange,
            HandshakePayload::ClientKeyExchange
        )?;
        st.transcript.add_message(&m);

        let peer = ClientEcdhParams::read_bytes(client_kx.bytes()).map_err(|err| {
            cx.common
                .send_fatal_alert(AlertDescription::DecodeError, err)
        })?;

        // RFC 7627 §4: the session hash covers the transcript through ClientKeyExchange.
        let ems_seed = st.using_ems.then(|| st.transcript.current_hash());
        let secrets = ConnectionSecrets::from_key_exchange(
            st.server_kx,
            &peer.public.0,
            ems_seed,
            st.randoms,
            st.suite,
        )
        .map_err(|err| match err {
            Error::PeerMisbehaved(_) => cx
                .common
                .send_fatal_alert(AlertDescription::IllegalParameter, err),
            other => other,
        })?;
        cx.common.kx_state.complete();

        st.config.key_log.log(
            "CLIENT_RANDOM",
            &secrets.randoms.client,
            secrets.master_secret(),
        );
        cx.common
            .start_encryption_tls12(&secrets, Side::Server, mac_order(st.using_etm));

        match st.client_cert {
            Some(client_cert) => Ok(Box::new(ExpectCertificateVerify {
                config: st.config,
                secrets,
                transcript: st.transcript,
                session_id: st.session_id,
                using_ems: st.using_ems,
                client_cert,
                send_ticket: st.send_ticket,
            })),
            None => Ok(Box::new(ExpectCcs {
                config: st.config,
                secrets,
                transcript: st.transcript,
                session_id: st.session_id,
                using_ems: st.using_ems,
                resuming: false,
                send_ticket: st.send_ticket,
            })),
        }
    }
}

struct ExpectCertificateVerify {
    config: Arc<ServerConfig>,
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
    session_id: SessionId,
    using_ems: bool,
    client_cert: CertificateChain<'static>,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectCertificateVerify {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        let sig = require_handshake_msg!(
            m,
            HandshakeType::CertificateVerify,
            HandshakePayload::CertificateVerify
        )?;

        if !self
            .config
            .verifier
            .supported_verify_schemes()
            .contains(&sig.scheme)
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }

        // RFC 5246 §7.4.8: the signature covers every handshake message so far.
        let Some(handshake_msgs) = self.transcript.take_handshake_buf() else {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::InternalError,
                Error::general("TLS 1.2 client authentication needs the raw transcript"),
            ));
        };
        let end_entity = self.client_cert.0.first().ok_or_else(|| {
            cx.common.send_fatal_alert(
                AlertDescription::DecodeError,
                Error::NoCertificatesPresented,
            )
        })?;
        self.config
            .verifier
            .verify_tls12_signature(&handshake_msgs, end_entity, sig)
            .map_err(|err| crate::client::tls13::send_cert_verify_error_alert(cx.common, err))?;

        trace!("client CertificateVerify OK");
        cx.common.peer_certificates = Some(self.client_cert);
        self.transcript.add_message(&m);

        Ok(Box::new(ExpectCcs {
            config: self.config,
            secrets: self.secrets,
            transcript: self.transcript,
            session_id: self.session_id,
            using_ems: self.using_ems,
            resuming: false,
            send_ticket: self.send_ticket,
        }))
    }
}

struct ExpectCcs {
    config: Arc<ServerConfig>,
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
    session_id: SessionId,
    using_ems: bool,
    resuming: bool,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectCcs {
    fn handle(self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        match m.payload {
            MessagePayload::ChangeCipherSpec(..) => {}
            payload => {
                return Err(crate::check::inappropriate_message(
                    &payload,
                    &[ContentType::ChangeCipherSpec],
                ));
            }
        }
        cx.common.record_layer.start_decrypting();
        Ok(Box::new(ExpectFinished {
            config: self.config,
            secrets: self.secrets,
            transcript: self.transcript,
            session_id: self.session_id,
            using_ems: self.using_ems,
            resuming: self.resuming,
            send_ticket: self.send_ticket,
        }))
    }
}

struct ExpectFinished {
    config: Arc<ServerConfig>,
    secrets: ConnectionSecrets,
    transcript: HandshakeHash,
    session_id: SessionId,
    using_ems: bool,
    resuming: bool,
    send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectFinished {
    fn handle(self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        let vh = st.transcript.current_hash();
        let expect_verify_data = st.secrets.client_verify_data(&vh);
        if !constant_time_eq(&expect_verify_data, finished.bytes()) {
            return Err(cx
                .common
                .send_fatal_alert(AlertDescription::DecryptError, Error::DecryptError));
        }
        let fin = FinishedMessageVerified::assertion();
        st.transcript.add_message(&m);

        if !st.resuming {
            // Full handshake: store the session, then finish our side.
            if st.send_ticket {
                let value = make_session_value(
                    cx,
                    &st.config,
                    &st.secrets,
                    st.secrets.suite(),
                    st.using_ems,
                )?;
                emit_ticket(&mut st.transcript, cx.common, &st.config, value)?;
            } else if !st.session_id.is_empty() {
                let value = make_session_value(
                    cx,
                    &st.config,
                    &st.secrets,
                    st.secrets.suite(),
                    st.using_ems,
                )?;
                let id = st.session_id.as_ref().to_vec();
                if st
                    .config
                    .session_storage
                    .put(id.clone(), value.get_encoding())
                {
                    cx.data.tls12_session = Some((st.config.session_storage.clone(), id));
                } else {
                    debug!("session not stored by the session cache");
                }
            }
            cx.common.send_change_cipher_spec();
            emit_finished(&st.secrets, &mut st.transcript, cx.common);
        }

        cx.common.start_traffic();
        Ok(Box::new(ExpectTraffic {
            secrets: st.secrets,
            renegotiation_requests: 0,
            _fin_verified: fin,
        }))
    }
}

struct ExpectTraffic {
    secrets: ConnectionSecrets,
    renegotiation_requests: u8,
    _fin_verified: FinishedMessageVerified,
}

impl State<ServerConnectionData> for ExpectTraffic {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        match m.payload {
            MessagePayload::ApplicationData(payload) => cx.common.take_received_plaintext(payload),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(..)),
                ..
            } => {
                // RFC 5746 §4.3: renegotiation is refused with a warning alert.
                self.renegotiation_requests = self.renegotiation_requests.saturating_add(1);
                if self.renegotiation_requests > MAX_RENEGOTIATION_REQUESTS {
                    return Err(cx.common.send_fatal_alert(
                        AlertDescription::UnexpectedMessage,
                        PeerMisbehaved::TooManyRenegotiationRequests,
                    ));
                }
                warning!("Refusing renegotiation request");
                cx.common
                    .send_warning_alert(AlertDescription::NoRenegotiation);
            }
            payload => {
                return Err(crate::check::inappropriate_handshake_message(
                    &payload,
                    &[ContentType::ApplicationData],
                    &[],
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
        self.secrets.export_keying_material(output, label, context)
    }

    fn extract_secrets(&self) -> Result<PartiallyExtractedSecrets, Error> {
        self.secrets.extract_secrets(Side::Server)
    }
}
