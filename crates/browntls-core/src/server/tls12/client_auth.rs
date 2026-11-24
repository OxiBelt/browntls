//! Client authentication in the TLS 1.2 server handshake: the client's
//! Certificate and CertificateVerify (RFC 5246 §7.4.6, §7.4.8).

use alloc::boxed::Box;

use super::{ExpectCcs, ExpectClientKx};
use crate::common_state::ConnectionRandoms;
use crate::conn::State;
use crate::crypto::ActiveKeyExchange;
use crate::enums::{AlertDescription, HandshakeType};
use crate::error::{Error, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::log::{debug, trace};
use crate::msgs::handshake::{
    CertificateChain, HandshakeMessagePayload, HandshakePayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::revocation::finish_or_pause;
use crate::server::common::{ClientCertAwaitingProof, verify_client_cert};
use crate::server::hs::{NextStateOrError, ServerContext};
use crate::server::server_conn::{ServerConfig, ServerConnectionData};
use crate::sync::Arc;
use crate::tls12::{ConnectionSecrets, Tls12CipherSuite};

pub(super) struct ExpectCertificate {
    /// We acknowledged `client_certificate_url`: a CertificateURL message
    /// may come in place of the Certificate (RFC 6066 §5).
    pub(super) certificate_url: bool,
    pub(super) config: Arc<ServerConfig>,
    pub(super) transcript: HandshakeHash,
    pub(super) randoms: ConnectionRandoms,
    pub(super) session_id: SessionId,
    pub(super) suite: &'static Tls12CipherSuite,
    pub(super) using_ems: bool,
    pub(super) using_etm: bool,
    pub(super) server_kx: Box<dyn ActiveKeyExchange>,
    pub(super) send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectCertificate {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        if self.certificate_url
            && let MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::CertificateUrl(urls)),
                ..
            } = &m.payload
        {
            return super::certificate_url::pause(self, cx, &m, urls);
        }
        let cert_chain =
            require_handshake_msg!(m, HandshakeType::Certificate, HandshakePayload::Certificate)?;
        self.transcript.add_message(&m);
        let cert_chain = cert_chain.clone().into_owned();
        (*self).accept_chain(cx, cert_chain)
    }
}

impl ExpectCertificate {
    /// Goes on with the client's chain, from a Certificate message or
    /// fetched for a CertificateURL one: the transcript already has the
    /// message.
    pub(super) fn accept_chain(
        self,
        cx: &mut ServerContext<'_>,
        cert_chain: CertificateChain<'static>,
    ) -> NextStateOrError {
        let client_cert = if cert_chain.0.is_empty() {
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
            None
        } else {
            // A TLS 1.2 client has no way to staple evidence to its chain.
            Some(verify_client_cert(
                cx.common,
                &self.config,
                cert_chain,
                &[],
            )?)
        };

        Ok(Box::new(ExpectClientKx {
            config: self.config,
            transcript: self.transcript,
            randoms: self.randoms,
            session_id: self.session_id,
            suite: self.suite,
            using_ems: self.using_ems,
            using_etm: self.using_etm,
            server_kx: self.server_kx,
            client_cert,
            send_ticket: self.send_ticket,
        }))
    }
}

pub(super) struct ExpectCertificateVerify {
    pub(super) config: Arc<ServerConfig>,
    pub(super) secrets: ConnectionSecrets,
    pub(super) transcript: HandshakeHash,
    pub(super) session_id: SessionId,
    pub(super) using_ems: bool,
    pub(super) client_cert: ClientCertAwaitingProof,
    pub(super) send_ticket: bool,
}

impl State<ServerConnectionData> for ExpectCertificateVerify {
    fn handle(mut self: Box<Self>, cx: &mut ServerContext<'_>, m: Message<'_>) -> NextStateOrError {
        let sig = require_handshake_msg!(
            m,
            HandshakeType::CertificateVerify,
            HandshakePayload::CertificateVerify
        )?;

        // Only a scheme the CertificateRequest listed.
        if !super::client_auth_schemes(&self.config).contains(&sig.scheme) {
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
        let end_entity = self.client_cert.chain.0.first().ok_or_else(|| {
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
        self.transcript.add_message(&m);

        // The client holds the key: a status lookup, if the verifier needs
        // one, may start now. Its ChangeCipherSpec and Finished are read
        // once that completes.
        let st = *self;
        let ClientCertAwaitingProof {
            chain, revocation, ..
        } = st.client_cert;
        finish_or_pause(cx, revocation, move |cx, status| {
            cx.common.peer_certificates = Some(chain);
            cx.common.peer_revocation_status = status;
            Ok(Box::new(ExpectCcs {
                config: st.config,
                secrets: st.secrets,
                transcript: st.transcript,
                session_id: st.session_id,
                using_ems: st.using_ems,
                resuming: false,
                send_ticket: st.send_ticket,
            }))
        })
    }
}
