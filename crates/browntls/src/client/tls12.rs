//! The TLS 1.2 client handshake after the ServerHello (RFC 5246 §7.3,
//! RFC 8422, RFC 7627, RFC 5077, RFC 5746).

use alloc::boxed::Box;
use alloc::vec::Vec;

use browntls_pki::ServerName;

use super::client_conn::ClientConnectionData;
use super::common::{ClientAuthDetails, ClientHelloDetails, ServerCertDetails};
use super::hs::{ClientContext, NextStateOrError};
use super::{ClientConfig, hs, tls13};
use crate::common_state::{CommonState, ConnectionRandoms, HandshakeKind, KxState, Side};
use crate::conn::State;
use crate::ct::constant_time_eq;
use crate::enums::{AlertDescription, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace, warning};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::codec::Codec;
use crate::msgs::enums::ECPointFormat;
use crate::msgs::handshake::{
    CertificateChain, ClientEcdhParams, HandshakeMessagePayload, HandshakePayload,
    NewSessionTicketPayload, ServerEcdhParams, ServerHelloPayload, ServerKeyExchangeParams,
    SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::suites::PartiallyExtractedSecrets;
use crate::sync::Arc;
use crate::tls12::{ConnectionSecrets, Tls12CipherSuite};
use crate::verify::{DigitallySignedStruct, HandshakeSignatureValid, ServerCertVerified};

/// How many HelloRequests we answer with `no_renegotiation` before giving up.
const MAX_HELLO_REQUESTS: u8 = 16;

pub(super) struct CompleteServerHelloHandling {
    pub(super) config: Arc<ClientConfig>,
    pub(super) resuming_session: Option<persist::Tls12ClientSessionValue>,
    pub(super) server_name: ServerName<'static>,
    pub(super) randoms: ConnectionRandoms,
    pub(super) using_ems: bool,
    pub(super) transcript: HandshakeHash,
    pub(super) session_id: SessionId,
    pub(super) hello: ClientHelloDetails,
    pub(super) alpn_protocols: Vec<Vec<u8>>,
}

impl CompleteServerHelloHandling {
    pub(super) fn handle_server_hello(
        mut self,
        cx: &mut ClientContext<'_>,
        suite: &'static Tls12CipherSuite,
        server_hello: &ServerHelloPayload,
        tls13_supported: bool,
    ) -> NextStateOrError {
        let _ = tls13_supported;

        // RFC 5746 §3.4: on an initial handshake the server's renegotiation_info is empty.
        if let Some(ri) = &server_hello.extensions.renegotiation_info
            && !ri.0.is_empty()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerMisbehaved::UnsolicitedServerHelloExtension,
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
        // TLS 1.3-only extensions may not appear in a TLS 1.2 ServerHello.
        if server_hello.extensions.key_share.is_some()
            || server_hello.extensions.pre_shared_key.is_some()
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

        if self.config.require_ems && !self.using_ems {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerIncompatible::ExtendedMasterSecretExtensionRequired,
            ));
        }

        let must_issue_new_ticket = server_hello.extensions.session_ticket_ack.is_some();

        if let Some(resuming) = self.resuming_session.take() {
            if !server_hello.session_id.is_empty() && resuming.session_id == server_hello.session_id
            {
                debug!("Server agreed to resume");
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

                let secrets = ConnectionSecrets::new_resume(self.randoms, suite, resuming.secret());
                self.config.key_log.log(
                    "CLIENT_RANDOM",
                    &secrets.randoms.client,
                    secrets.master_secret(),
                );
                cx.common.start_encryption_tls12(&secrets, Side::Client);
                cx.common.peer_certificates = Some(resuming.server_cert_chain().clone());
                cx.common.handshake_kind = Some(HandshakeKind::Resumed);
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
                };
                // RFC 5077 §3.3: a new ticket, if any, precedes ChangeCipherSpec.
                return Ok(if must_issue_new_ticket {
                    Box::new(ExpectNewTicket { next })
                } else {
                    Box::new(next)
                });
            }
            // The server declined; forget the stale session.
            self.config
                .resumption
                .store
                .remove_tls12_session(&self.server_name);
        }

        if cx.common.handshake_kind.is_none() {
            cx.common.handshake_kind = Some(HandshakeKind::Full);
        }

        Ok(Box::new(ExpectCertificate {
            config: self.config,
            session_id: server_hello.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite,
            may_send_cert_status: server_hello.extensions.status_request_ack.is_some(),
            must_issue_new_ticket,
            hello: self.hello,
        }))
    }
}

struct ExpectCertificate {
    config: Arc<ClientConfig>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    may_send_cert_status: bool,
    must_issue_new_ticket: bool,
    hello: ClientHelloDetails,
}

impl State<ClientConnectionData> for ExpectCertificate {
    fn handle(
        mut self: Box<Self>,
        _cx: &mut ClientContext<'_>,
        m: Message<'_>,
    ) -> NextStateOrError {
        let server_cert_chain =
            require_handshake_msg!(m, HandshakeType::Certificate, HandshakePayload::Certificate)?;
        self.transcript.add_message(&m);
        let server_cert_chain = server_cert_chain.clone().into_owned();

        if self.may_send_cert_status {
            Ok(Box::new(ExpectCertificateStatusOrServerKx {
                config: self.config,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert_chain,
                must_issue_new_ticket: self.must_issue_new_ticket,
                hello: self.hello,
            }))
        } else {
            Ok(Box::new(ExpectServerKx {
                config: self.config,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: ServerCertDetails::new(server_cert_chain, Vec::new()),
                must_issue_new_ticket: self.must_issue_new_ticket,
                hello: self.hello,
            }))
        }
    }
}

struct ExpectCertificateStatusOrServerKx {
    config: Arc<ClientConfig>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert_chain: CertificateChain<'static>,
    must_issue_new_ticket: bool,
    hello: ClientHelloDetails,
}

impl State<ClientConnectionData> for ExpectCertificateStatusOrServerKx {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        match &m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ServerKeyExchange(..)),
                ..
            } => Box::new(ExpectServerKx {
                config: self.config,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: ServerCertDetails::new(self.server_cert_chain, Vec::new()),
                must_issue_new_ticket: self.must_issue_new_ticket,
                hello: self.hello,
            })
            .handle(cx, m),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateStatus(..)),
                ..
            } => Box::new(ExpectCertificateStatus {
                config: self.config,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert_chain: self.server_cert_chain,
                must_issue_new_ticket: self.must_issue_new_ticket,
                hello: self.hello,
            })
            .handle(cx, m),
            payload => Err(crate::check::inappropriate_handshake_message(
                payload,
                &[ContentType::Handshake],
                &[
                    HandshakeType::ServerKeyExchange,
                    HandshakeType::CertificateStatus,
                ],
            )),
        }
    }
}

struct ExpectCertificateStatus {
    config: Arc<ClientConfig>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert_chain: CertificateChain<'static>,
    must_issue_new_ticket: bool,
    hello: ClientHelloDetails,
}

impl State<ClientConnectionData> for ExpectCertificateStatus {
    fn handle(
        mut self: Box<Self>,
        _cx: &mut ClientContext<'_>,
        m: Message<'_>,
    ) -> NextStateOrError {
        let status = require_handshake_msg!(
            m,
            HandshakeType::CertificateStatus,
            HandshakePayload::CertificateStatus
        )?;
        let ocsp_response = status.clone().into_owned().into_inner();
        self.transcript.add_message(&m);
        trace!("Server stapled OCSP response is {:?}", ocsp_response.len());

        Ok(Box::new(ExpectServerKx {
            config: self.config,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert: ServerCertDetails::new(self.server_cert_chain, ocsp_response),
            must_issue_new_ticket: self.must_issue_new_ticket,
            hello: self.hello,
        }))
    }
}

/// The server's ECDHE parameters and the signature over them.
struct ServerKxDetails {
    params: ServerEcdhParams,
    sig: DigitallySignedStruct,
}

struct ExpectServerKx {
    config: Arc<ClientConfig>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    must_issue_new_ticket: bool,
    hello: ClientHelloDetails,
}

impl State<ClientConnectionData> for ExpectServerKx {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        let opaque_kx = require_handshake_msg!(
            m,
            HandshakeType::ServerKeyExchange,
            HandshakePayload::ServerKeyExchange
        )?;
        self.transcript.add_message(&m);

        let decoded = opaque_kx.unwrap_given_kxa(self.suite.kx).map_err(|err| {
            cx.common
                .send_fatal_alert(AlertDescription::DecodeError, err)
        })?;
        let ServerKeyExchangeParams::Ecdh(params) = decoded.params;

        // RFC 8422 §5.4: the group must be one we offered.
        if self
            .config
            .find_kx_group(params.curve_params.named_group, ProtocolVersion::TLSv1_2)
            .is_none()
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SelectedUnofferedKxGroup,
            ));
        }

        Ok(Box::new(ExpectServerDoneOrCertReq {
            config: self.config,
            session_id: self.session_id,
            server_name: self.server_name,
            randoms: self.randoms,
            using_ems: self.using_ems,
            transcript: self.transcript,
            suite: self.suite,
            server_cert: self.server_cert,
            server_kx: ServerKxDetails {
                params,
                sig: decoded.dss,
            },
            must_issue_new_ticket: self.must_issue_new_ticket,
            hello: self.hello,
        }))
    }
}

struct ExpectServerDoneOrCertReq {
    config: Arc<ClientConfig>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
    must_issue_new_ticket: bool,
    hello: ClientHelloDetails,
}

impl State<ClientConnectionData> for ExpectServerDoneOrCertReq {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        match &m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateRequest(certreq)),
                ..
            } => {
                self.transcript.add_message(&m);
                debug!("Got CertificateRequest {:?}", certreq);

                // RFC 5246 §7.4.4: the schemes must be non-empty (checked by the codec).
                let client_auth = ClientAuthDetails::resolve(
                    &*self.config.client_auth_cert_resolver,
                    Some(&certreq.canames),
                    &certreq.sigschemes,
                    None,
                );
                Ok(Box::new(ExpectServerDone {
                    config: self.config,
                    session_id: self.session_id,
                    server_name: self.server_name,
                    randoms: self.randoms,
                    using_ems: self.using_ems,
                    transcript: self.transcript,
                    suite: self.suite,
                    server_cert: self.server_cert,
                    server_kx: self.server_kx,
                    client_auth: Some(client_auth),
                    must_issue_new_ticket: self.must_issue_new_ticket,
                    hello: self.hello,
                }))
            }
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ServerHelloDone),
                ..
            } => Box::new(ExpectServerDone {
                config: self.config,
                session_id: self.session_id,
                server_name: self.server_name,
                randoms: self.randoms,
                using_ems: self.using_ems,
                transcript: self.transcript,
                suite: self.suite,
                server_cert: self.server_cert,
                server_kx: self.server_kx,
                client_auth: None,
                must_issue_new_ticket: self.must_issue_new_ticket,
                hello: self.hello,
            })
            .handle(cx, m),
            payload => Err(crate::check::inappropriate_handshake_message(
                payload,
                &[ContentType::Handshake],
                &[
                    HandshakeType::ServerHelloDone,
                    HandshakeType::CertificateRequest,
                ],
            )),
        }
    }
}

struct ExpectServerDone {
    config: Arc<ClientConfig>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    randoms: ConnectionRandoms,
    using_ems: bool,
    transcript: HandshakeHash,
    suite: &'static Tls12CipherSuite,
    server_cert: ServerCertDetails,
    server_kx: ServerKxDetails,
    client_auth: Option<ClientAuthDetails>,
    must_issue_new_ticket: bool,
    hello: ClientHelloDetails,
}

impl State<ClientConnectionData> for ExpectServerDone {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        let mut st = *self;
        match &m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ServerHelloDone),
                ..
            } => {}
            payload => {
                return Err(crate::check::inappropriate_handshake_message(
                    payload,
                    &[ContentType::Handshake],
                    &[HandshakeType::ServerHelloDone],
                ));
            }
        }
        st.transcript.add_message(&m);

        // 1. Verify the server's certificate chain.
        let (end_entity, intermediates) =
            st.server_cert.cert_chain.0.split_first().ok_or_else(|| {
                cx.common.send_fatal_alert(
                    AlertDescription::DecodeError,
                    Error::NoCertificatesPresented,
                )
            })?;
        let now = st.config.current_time()?;
        let cert_verified = st
            .config
            .verifier()
            .verify_server_cert(
                end_entity,
                intermediates,
                &st.server_name,
                &st.server_cert.ocsp_response,
                now,
            )
            .map_err(|err| tls13::send_cert_verify_error_alert(cx.common, err))?;

        // 2. Verify the signature over the key exchange parameters
        //    (RFC 5246 §7.4.3: client_random || server_random || params).
        let sig = &st.server_kx.sig;
        if !st.hello.offered_sigschemes.contains(&sig.scheme)
            || !st.suite.sign.contains(&sig.scheme)
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SignedKxWithWrongAlgorithm,
            ));
        }
        let mut message = Vec::with_capacity(64 + 128);
        message.extend_from_slice(&st.randoms.client);
        message.extend_from_slice(&st.randoms.server);
        st.server_kx.params.encode(&mut message);
        let sig_verified = st
            .config
            .verifier()
            .verify_tls12_signature(&message, end_entity, sig)
            .map_err(|err| tls13::send_cert_verify_error_alert(cx.common, err))?;

        cx.common.peer_certificates = Some(st.server_cert.cert_chain);

        // 3. Client certificate, if requested.
        if let Some(client_auth) = &st.client_auth {
            match client_auth {
                ClientAuthDetails::Empty { .. } => {
                    emit_certificate(&mut st.transcript, None, cx.common)
                }
                ClientAuthDetails::Verify { certkey, .. } => {
                    emit_certificate(&mut st.transcript, Some(certkey), cx.common)
                }
            }
        }

        // 4. Our key exchange, and the master secret.
        let group = st
            .config
            .find_kx_group(
                st.server_kx.params.curve_params.named_group,
                ProtocolVersion::TLSv1_2,
            )
            .ok_or_else(|| {
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SelectedUnofferedKxGroup,
                )
            })?;
        cx.common.kx_state = KxState::Started(group);
        let kx = group.start()?;
        emit_client_kx(&mut st.transcript, kx.pub_key(), cx.common);

        // RFC 7627 §4: the extended master secret uses the session hash,
        // which covers the transcript through ClientKeyExchange.
        let ems_seed = st.using_ems.then(|| st.transcript.current_hash());
        let secrets = ConnectionSecrets::from_key_exchange(
            kx,
            &st.server_kx.params.public.0,
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
        cx.common.start_encryption_tls12(&secrets, Side::Client);

        // 5. CertificateVerify over every handshake message so far.
        if let Some(ClientAuthDetails::Verify { signer, .. }) = &st.client_auth {
            emit_certverify(&mut st.transcript, &**signer, cx.common)?;
        }

        // 6. ChangeCipherSpec and Finished.
        cx.common.send_change_cipher_spec();
        emit_finished(&secrets, &mut st.transcript, cx.common);

        let next = ExpectCcs {
            config: st.config,
            secrets,
            resuming_session: None,
            session_id: st.session_id,
            server_name: st.server_name,
            using_ems: st.using_ems,
            transcript: st.transcript,
            ticket: None,
            resuming: false,
            cert_verified,
            sig_verified,
        };
        Ok(if st.must_issue_new_ticket {
            Box::new(ExpectNewTicket { next })
        } else {
            Box::new(next)
        })
    }
}

fn emit_certificate(
    transcript: &mut HandshakeHash,
    certkey: Option<&crate::sign::CertifiedKey>,
    common: &mut CommonState,
) {
    let chain = CertificateChain(
        certkey
            .map(|ck| {
                ck.cert
                    .iter()
                    .map(|c| browntls_pki::CertificateDer::from_slice(c.as_ref()))
                    .collect()
            })
            .unwrap_or_default(),
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

fn emit_client_kx(transcript: &mut HandshakeHash, pub_key: &[u8], common: &mut CommonState) {
    let ecdh = ClientEcdhParams {
        public: PayloadU8::new(pub_key.to_vec()),
    };
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::ClientKeyExchange(Payload::new(ecdh.get_encoding())),
        )),
    };
    transcript.add_message(&m);
    common.send_msg(m, false);
}

fn emit_certverify(
    transcript: &mut HandshakeHash,
    signer: &dyn crate::sign::Signer,
    common: &mut CommonState,
) -> Result<(), Error> {
    // RFC 5246 §7.4.8: the signature covers all handshake messages so far.
    let Some(message) = transcript.take_handshake_buf() else {
        return Err(Error::general(
            "TLS 1.2 client authentication needs the raw transcript",
        ));
    };
    let scheme = signer.scheme();
    let sig = signer.sign(&message)?;
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(
            HandshakePayload::CertificateVerify(DigitallySignedStruct::new(scheme, sig)),
        )),
    };
    transcript.add_message(&m);
    common.send_msg(m, false);
    Ok(())
}

fn emit_finished(
    secrets: &ConnectionSecrets,
    transcript: &mut HandshakeHash,
    common: &mut CommonState,
) {
    let vh = transcript.current_hash();
    let verify_data = secrets.client_verify_data(&vh);
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::Finished(
            Payload::new(verify_data),
        ))),
    };
    transcript.add_message(&m);
    common.send_msg(m, true);
}

struct ExpectNewTicket {
    next: ExpectCcs,
}

impl State<ClientConnectionData> for ExpectNewTicket {
    fn handle(
        mut self: Box<Self>,
        _cx: &mut ClientContext<'_>,
        m: Message<'_>,
    ) -> NextStateOrError {
        let nst: &NewSessionTicketPayload = require_handshake_msg!(
            m,
            HandshakeType::NewSessionTicket,
            HandshakePayload::NewSessionTicket
        )?;
        self.next.transcript.add_message(&m);
        if !nst.ticket.0.is_empty() {
            self.next.ticket = Some((nst.ticket.0.clone(), nst.lifetime_hint));
        }
        Ok(Box::new(self.next))
    }
}

struct ExpectCcs {
    config: Arc<ClientConfig>,
    secrets: ConnectionSecrets,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    using_ems: bool,
    transcript: HandshakeHash,
    ticket: Option<(Vec<u8>, u32)>,
    resuming: bool,
    cert_verified: ServerCertVerified,
    sig_verified: HandshakeSignatureValid,
}

impl State<ClientConnectionData> for ExpectCcs {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        match m.payload {
            MessagePayload::ChangeCipherSpec(..) => {}
            payload => {
                return Err(crate::check::inappropriate_message(
                    &payload,
                    &[ContentType::ChangeCipherSpec],
                ));
            }
        }
        // RFC 5246 §7.1: everything after this is protected.
        cx.common.record_layer.start_decrypting();
        Ok(Box::new(ExpectFinished {
            config: self.config,
            secrets: self.secrets,
            resuming_session: self.resuming_session,
            session_id: self.session_id,
            server_name: self.server_name,
            using_ems: self.using_ems,
            transcript: self.transcript,
            ticket: self.ticket,
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        }))
    }
}

struct ExpectFinished {
    config: Arc<ClientConfig>,
    secrets: ConnectionSecrets,
    resuming_session: Option<persist::Tls12ClientSessionValue>,
    session_id: SessionId,
    server_name: ServerName<'static>,
    using_ems: bool,
    transcript: HandshakeHash,
    ticket: Option<(Vec<u8>, u32)>,
    resuming: bool,
    cert_verified: ServerCertVerified,
    sig_verified: HandshakeSignatureValid,
}

impl ExpectFinished {
    fn save_session(&mut self, cx: &mut ClientContext<'_>) {
        let (ticket, lifetime) = self.ticket.take().unwrap_or_default();
        // Without a session ID or ticket there is nothing to resume with.
        if self.session_id.is_empty() && ticket.is_empty() {
            debug!("Session not saved: server didn't allocate id or ticket");
            return;
        }
        let Ok(now) = self.config.current_time() else {
            return;
        };
        let cert_chain = cx.common.peer_certificates.clone().unwrap_or_default();
        let value = persist::Tls12ClientSessionValue::new(
            self.secrets.suite(),
            self.session_id,
            ticket,
            self.secrets.master_secret(),
            Arc::new(cert_chain),
            now,
            lifetime,
            self.using_ems,
        );
        self.config
            .resumption
            .store
            .set_tls12_session(self.server_name.clone(), value);
    }
}

impl State<ClientConnectionData> for ExpectFinished {
    fn handle(self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        let mut st = *self;
        let finished =
            require_handshake_msg!(m, HandshakeType::Finished, HandshakePayload::Finished)?;

        let vh = st.transcript.current_hash();
        let expect_verify_data = st.secrets.server_verify_data(&vh);
        if !constant_time_eq(&expect_verify_data, finished.bytes()) {
            return Err(cx
                .common
                .send_fatal_alert(AlertDescription::DecryptError, Error::DecryptError));
        }
        st.transcript.add_message(&m);

        if st.resuming {
            // Abbreviated handshake: the server finished first; now we do.
            cx.common.send_change_cipher_spec();
            emit_finished(&st.secrets, &mut st.transcript, cx.common);
        }

        st.save_session(cx);
        if let Some(group) = cx.common.negotiated_key_exchange_group() {
            st.config
                .resumption
                .store
                .set_kx_hint(st.server_name.clone(), group.name());
        }
        cx.common.start_traffic();

        Ok(Box::new(ExpectTraffic {
            secrets: st.secrets,
            hello_requests: 0,
            _cert_verified: st.cert_verified,
            _sig_verified: st.sig_verified,
            _resuming_session: st.resuming_session,
        }))
    }
}

struct ExpectTraffic {
    secrets: ConnectionSecrets,
    hello_requests: u8,
    _cert_verified: ServerCertVerified,
    _sig_verified: HandshakeSignatureValid,
    _resuming_session: Option<persist::Tls12ClientSessionValue>,
}

impl State<ClientConnectionData> for ExpectTraffic {
    fn handle(mut self: Box<Self>, cx: &mut ClientContext<'_>, m: Message<'_>) -> NextStateOrError {
        match m.payload {
            MessagePayload::ApplicationData(payload) => cx.common.take_received_plaintext(payload),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::HelloRequest),
                ..
            } => {
                // RFC 5746 §4.2: we never renegotiate; say so and carry on.
                self.hello_requests = self.hello_requests.saturating_add(1);
                if self.hello_requests > MAX_HELLO_REQUESTS {
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
                    &[ContentType::ApplicationData, ContentType::Handshake],
                    &[HandshakeType::HelloRequest],
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
        self.secrets.export_keying_material(output, label, context);
        Ok(())
    }

    fn extract_secrets(&self) -> Result<PartiallyExtractedSecrets, Error> {
        self.secrets.extract_secrets(Side::Client)
    }
}
