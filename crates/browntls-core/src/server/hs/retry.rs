//! The cookie of our HelloRetryRequest, as a second ClientHello brings it
//! back (RFC 9846 §4.3.2, RFC 9147 §5.1).

use super::super::cookie::RetryCookie;
use super::super::tls13;
use super::{ExpectClientHello, HandshakeHashOrBuffer, RetryChoice, ServerContext};
use crate::enums::{AlertDescription, ProtocolVersion};
use crate::error::{Error, PeerMisbehaved};
use crate::hash_hs::HandshakeHashBuffer;
use crate::log::debug;
use crate::msgs::codec::Codec;
use crate::msgs::handshake::{ClientHelloPayload, HandshakeMessagePayload};

impl ExpectClientHello {
    /// Checks the cookie of a second ClientHello, or continues a stateless
    /// retry (RFC 9846 §4.3.2) when a first message carries one of ours.
    pub(super) fn process_cookie(
        &mut self,
        client_hello: &ClientHelloPayload,
        cx: &mut ServerContext<'_>,
    ) -> Result<(), Error> {
        let received = client_hello.extensions.cookie.as_ref().map(|c| &c.0);
        if self.done_retry {
            // The client MUST copy the cookie it was sent.
            return match (&self.sent_cookie, received) {
                (None, _) => Ok(()),
                (Some(_), None) => Err(cx.common.send_fatal_alert(
                    AlertDescription::MissingExtension,
                    PeerMisbehaved::MissingCookieInSecondClientHello,
                )),
                (Some(sent), Some(received)) if sent == received => Ok(()),
                (Some(_), Some(_)) => Err(cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::InvalidHelloRetryRequestCookie,
                )),
            };
        }
        match (received, &self.config.hello_retry_cookies) {
            (Some(cookie), Some(sealer)) => {
                let sealer = sealer.clone();
                self.resume_from_cookie(&*sealer, cookie, client_hello, cx)
            }
            // RFC 9846 §4.3.2: a stateless server ignores change_cipher_spec
            // records ahead of a second ClientHello; ahead of any other it
            // is unexpected.
            _ if cx.common.received_middlebox_ccs > 0 => Err(cx.common.send_fatal_alert(
                AlertDescription::UnexpectedMessage,
                PeerMisbehaved::IllegalMiddleboxChangeCipherSpec,
            )),
            // Without a sealer we issue no cookies, and ignore one a client
            // sends in its first ClientHello.
            _ => Ok(()),
        }
    }

    /// Restores the state a HelloRetryRequest left in its cookie, so this
    /// connection continues the handshake from the second ClientHello.
    fn resume_from_cookie(
        &mut self,
        sealer: &dyn super::super::server_conn::ProducesTickets,
        cookie: &[u8],
        client_hello: &ClientHelloPayload,
        cx: &mut ServerContext<'_>,
    ) -> Result<(), Error> {
        // Without a clock the cookie cannot be checked: fail closed, with
        // an explicit alert also on the Acceptor path.
        let now = match self.config.current_time() {
            Ok(now) => now.as_secs(),
            Err(err) => {
                return Err(cx
                    .common
                    .send_fatal_alert(AlertDescription::InternalError, err));
            }
        };
        let invalid = |cx: &mut ServerContext<'_>| {
            cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::InvalidHelloRetryRequestCookie,
            )
        };
        // RFC 9147 §5.1: a DTLS cookie is valid only from the address it
        // was sent to.
        let dtls_peer_address = cx.common.dtls.as_deref().map(|d| d.peer_address());
        let Some(state) = RetryCookie::open(sealer, cookie, now, dtls_peer_address) else {
            return Err(invalid(cx));
        };
        // We issue no cookie when the first ClientHello offered ECH, so a
        // second one may not offer it either (RFC 9849 §7.1.1).
        if !matches!(cx.data.ech, crate::ech::server::ServerEch::NotOffered) {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::EchChangedOnRetry,
            ));
        }
        // The configuration may have changed since the cookie was issued.
        let Some(suite) = self
            .config
            .find_cipher_suite(state.suite)
            .and_then(|s| s.tls13())
        else {
            return Err(invalid(cx));
        };
        let Some(group) =
            self.config.kx_groups().iter().copied().find(|g| {
                g.name() == state.group && g.usable_for_version(ProtocolVersion::TLSv1_3)
            })
        else {
            return Err(invalid(cx));
        };
        if state.client_hello_hash.len() != suite.common.hash_provider.output_len() {
            return Err(invalid(cx));
        }
        // RFC 9846 §4.2.2: the second ClientHello repeats the first, apart
        // from what the HelloRetryRequest asked to change.
        if client_hello.session_id != state.session_id {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::RefusedToFollowHelloRetryRequest,
            ));
        }
        let sni = cx
            .data
            .sni
            .as_ref()
            .map(|name| name.as_ref().as_bytes())
            .unwrap_or_default();
        if sni != state.server_name.as_slice() {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::ServerNameDifferedOnRetry,
            ));
        }
        // A TLS HelloRetryRequest always names its group; a DTLS one may
        // only have asked for the cookie.
        let group_named = state.dtls.as_ref().is_none_or(|dtls| dtls.group_named);

        // RFC 9846 §4.1: message_hash(Hash(ClientHello1)), then the
        // HelloRetryRequest exactly as sent (it is rebuilt from the cookie).
        let mut transcript = HandshakeHashBuffer::new().start_hash(suite.common.hash_provider);
        transcript.add(
            &HandshakeMessagePayload::build_handshake_hash(&state.client_hello_hash).get_encoding(),
        );
        transcript.add_message(&tls13::hello_retry_request_message(
            suite,
            state.session_id,
            group_named.then(|| group.name()),
            Some(cookie.to_vec()),
            cx.common.is_dtls(),
        ));
        debug!("continuing a stateless HelloRetryRequest from its cookie");
        self.transcript = HandshakeHashOrBuffer::Hash(transcript);
        self.done_retry = true;
        self.retry_choice = Some(RetryChoice {
            suite,
            group,
            group_named,
        });
        self.sent_cookie = Some(cookie.to_vec());
        cx.common.handshake_kind =
            Some(crate::common_state::HandshakeKind::FullWithHelloRetryRequest);
        Ok(())
    }
}
