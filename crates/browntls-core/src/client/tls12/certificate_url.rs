//! The TLS 1.2 client's answer to a CertificateRequest when certificate
//! URLs are in play (RFC 6066 §5).

use super::{ClientAuthDetails, HandshakeMessagePayload, HandshakePayload, emit_certificate};
use crate::common_state::CommonState;
use crate::enums::ProtocolVersion;
use crate::hash_hs::HandshakeHash;
use crate::log::debug;
use crate::msgs::handshake::CertificateUrlPayload;
use crate::msgs::message::{Message, MessagePayload};

/// Sends our Certificate, or a CertificateURL message in its place when
/// the server acknowledged `client_certificate_url` and the chosen key has
/// URLs. Returns how the flight goes on: a key with no chain to send makes
/// it go on without CertificateVerify.
pub(super) fn emit_client_certificate(
    transcript: &mut HandshakeHash,
    client_auth: ClientAuthDetails,
    url_accepted: bool,
    common: &mut CommonState,
) -> ClientAuthDetails {
    let ClientAuthDetails::Verify { certkey, .. } = &client_auth else {
        emit_certificate(transcript, None, common);
        return client_auth;
    };
    if url_accepted && let Some(urls) = certkey.certificate_url() {
        debug!("Sending CertificateURL");
        let m = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::CertificateUrl(CertificateUrlPayload::from(urls)),
            )),
        };
        transcript.add_message(&m);
        common.send_msg(m, false);
        return client_auth;
    }
    if certkey.cert.is_empty() {
        // Nothing to send, so nothing to prove (RFC 5246 §7.4.6).
        debug!("Server did not accept certificate URLs; sending no certificate");
        emit_certificate(transcript, None, common);
        return ClientAuthDetails::Empty {
            auth_context_tls13: None,
        };
    }
    emit_certificate(transcript, Some(certkey), common);
    client_auth
}
