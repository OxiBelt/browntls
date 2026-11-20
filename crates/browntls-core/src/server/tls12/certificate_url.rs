//! Client certificate URLs in the TLS 1.2 server handshake (RFC 6066 §5):
//! when the extension is acknowledged, and the pause while the application
//! fetches the chain a CertificateURL message names. Nothing here opens a
//! connection to any URL.

use alloc::boxed::Box;

use super::client_auth::ExpectCertificate;
use crate::certificate_url::PendingCertificateUrl;
use crate::conn::State;
use crate::enums::{AlertDescription, CertificateType};
use crate::error::Error;
use crate::log::debug;
use crate::msgs::handshake::{CertificateChain, CertificateUrlPayload, ClientHelloPayload};
use crate::msgs::message::Message;
use crate::server::hs::{NegotiatedCertTypes, NextStateOrError, ServerContext};
use crate::server::server_conn::{ServerConfig, ServerConnectionData};

/// Whether a full TLS 1.2 handshake acknowledges `client_certificate_url`:
/// the client offered it, a policy is configured, a CertificateRequest
/// will be sent, and the client certificate is X.509 (not an RFC 7250 raw
/// public key, which has no URL form).
pub(super) fn acknowledged(
    config: &ServerConfig,
    client_hello: &ClientHelloPayload,
    cert_types: &NegotiatedCertTypes,
) -> bool {
    client_hello.extensions.client_certificate_url.is_some()
        && config.client_certificate_url.is_some()
        && config.verifier.offer_client_auth()
        && cert_types.client != Some(CertificateType::RawPublicKey)
}

/// Takes a CertificateURL message: refuses what the policy does not allow
/// (`certificate_unobtainable`, before the application sees any URL), or
/// pauses the handshake with a query for the application.
pub(super) fn pause(
    mut st: Box<ExpectCertificate>,
    cx: &mut ServerContext<'_>,
    m: &Message<'_>,
    urls: &CertificateUrlPayload,
) -> NextStateOrError {
    st.transcript.add_message(m);
    let Some(policy) = &st.config.client_certificate_url else {
        return Err(cx.common.send_fatal_alert(
            AlertDescription::InternalError,
            Error::general("client_certificate_url acknowledged without a policy"),
        ));
    };
    let pending = PendingCertificateUrl::new(policy, urls)
        .map_err(|err| cx.common.send_fatal_alert(AlertDescription::from(err), err))?;
    debug!("waiting for the client certificate chain named by URL");
    cx.common.pending_certificate_url = Some(Box::new(pending));
    Ok(Box::new(WaitForCertificateUrl(st)))
}

/// The handshake while the application fetches the client's chain. Input
/// is not processed meanwhile; the answer resumes it with the chain.
struct WaitForCertificateUrl(Box<ExpectCertificate>);

impl State<ServerConnectionData> for WaitForCertificateUrl {
    fn handle(
        self: Box<Self>,
        cx: &mut ServerContext<'_>,
        _message: Message<'_>,
    ) -> NextStateOrError {
        Err(cx.common.send_fatal_alert(
            AlertDescription::InternalError,
            Error::general("handshake input processed during client certificate URL fetch"),
        ))
    }

    fn resume_client_certificate_url(
        self: Box<Self>,
        cx: &mut ServerContext<'_>,
        chain: CertificateChain<'static>,
    ) -> NextStateOrError {
        // RFC 6066 §5: the chain is then processed as usual.
        (*self.0).accept_chain(cx, chain)
    }
}
