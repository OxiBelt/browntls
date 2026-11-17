//! The public methods on the connection types.

use alloc::vec::Vec;

use browntls_pki::CertificateDer;

use super::connection::Connection;
use super::messages::{make_request, tls13_schemes};
use super::{AuthenticatorRequestExtensions, request_digest};
use crate::client::ClientConnection;
use crate::common_state::Side;
use crate::error::Error;
use crate::server::ServerConnection;
use crate::sign::CertifiedKey;

impl ClientConnection {
    /// Builds an authenticator request (a `ClientCertificateRequest`,
    /// RFC 9261 §4) asking the server to prove possession of another
    /// certificate. `context` (1 to 255 bytes) must be unique on this
    /// connection and should be unpredictable to the server.
    pub fn request_authenticator(
        &mut self,
        context: &[u8],
        extensions: &AuthenticatorRequestExtensions,
    ) -> Result<Vec<u8>, Error> {
        let data = &self.core.data;
        data.authenticators.check_request(context)?;
        let defaults = data.config.verifier().supported_verify_schemes();
        let request = make_request(Side::Client, context, extensions, defaults)?;
        let digest = request_digest(data.config.crypto_provider(), &request)?;
        self.core.data.authenticators.add_request(context, digest);
        Ok(request)
    }

    /// Answers the server's authenticator `request` (a TLS 1.3
    /// `CertificateRequest`) with `certified_key` (RFC 9261 §5), or with
    /// an empty authenticator declining it when `certified_key` is
    /// `None` or cannot sign with any scheme the request allows.
    pub fn authenticator(
        &mut self,
        request: &[u8],
        certified_key: Option<&CertifiedKey>,
    ) -> Result<Vec<u8>, Error> {
        let (out, context) = {
            let conn = connection(self, Side::Client)?;
            conn.make_authenticator(
                Some(request),
                certified_key,
                &[],
                &self.core.data.authenticators,
            )?
        };
        self.core.data.authenticators.made.push(context);
        Ok(out)
    }

    /// Validates the server's `authenticator` answering our `request`,
    /// or a spontaneous one when `request` is `None` (RFC 9261 §5).
    ///
    /// `request` must be one this connection made with
    /// [`Self::request_authenticator`] and not yet answered.
    ///
    /// The chain is verified for this connection's server name (the
    /// name given to [`ClientConnection::new`] and sent as SNI), and the
    /// signature checked, by the configured server certificate
    /// verifier. Secondary host names are not supported: requests carry
    /// no `server_name` extension, and a certificate valid only for
    /// another name is rejected. Returns the certificates, end entity
    /// first, or `None` for an empty authenticator (the server
    /// declined).
    pub fn validate_authenticator(
        &mut self,
        request: Option<&[u8]>,
        authenticator: &[u8],
    ) -> Result<Option<Vec<CertificateDer<'static>>>, Error> {
        let (chain, answered) = {
            let data = &self.core.data;
            let config = &data.config;
            let verifier = config.verifier();
            let now = config
                .time_provider
                .current_time()
                .ok_or(Error::FailedToGetCurrentTime)?;
            let offered = tls13_schemes(&verifier.supported_verify_schemes());
            let conn = connection(self, Side::Client)?;
            conn.validate(
                request,
                authenticator,
                &offered,
                &data.authenticators,
                |ee, intermediates| {
                    verifier
                        .verify_server_cert(ee, intermediates, &data.server_name, &[], now)
                        .map(|_| ())
                },
                |msg, ee, dss| verifier.verify_tls13_signature(msg, ee, dss),
            )?
        };
        self.core.data.authenticators.record(answered);
        Ok(chain)
    }
}

impl ServerConnection {
    /// Builds an authenticator request (a TLS 1.3 `CertificateRequest`,
    /// RFC 9261 §4) asking the client to prove possession of a
    /// certificate. `context` (1 to 255 bytes) must be unique on this
    /// connection and should be unpredictable to the client.
    pub fn request_authenticator(
        &mut self,
        context: &[u8],
        extensions: &AuthenticatorRequestExtensions,
    ) -> Result<Vec<u8>, Error> {
        let state = &self.core.data.authenticators;
        state.contexts.check_request(context)?;
        let config = state.config.as_ref().ok_or(Error::HandshakeNotComplete)?;
        let defaults = config.verifier.supported_verify_schemes();
        let request = make_request(Side::Server, context, extensions, defaults)?;
        let digest = request_digest(config.crypto_provider(), &request)?;
        self.core
            .data
            .authenticators
            .contexts
            .add_request(context, digest);
        Ok(request)
    }

    /// Answers the client's authenticator `request` (a
    /// `ClientCertificateRequest`) with `certified_key`, or, with
    /// `request` `None`, authenticates spontaneously with a fresh random
    /// context and a scheme from the client's `signature_algorithms`
    /// (RFC 9261 §5). Declines with an empty authenticator when
    /// answering a request without a usable `certified_key`.
    pub fn authenticator(
        &mut self,
        request: Option<&[u8]>,
        certified_key: Option<&CertifiedKey>,
    ) -> Result<Vec<u8>, Error> {
        let (out, context) = {
            let conn = connection(self, Side::Server)?;
            let state = &self.core.data.authenticators;
            conn.make_authenticator(
                request,
                certified_key,
                &state.client_sig_schemes,
                &state.contexts,
            )?
        };
        self.core.data.authenticators.contexts.made.push(context);
        Ok(out)
    }

    /// Validates the client's `authenticator` answering our `request`
    /// (RFC 9261 §5), which must be one this connection made with
    /// [`Self::request_authenticator`] and not yet answered. The chain
    /// and signature are checked by the
    /// configured client certificate verifier. Returns the
    /// certificates, end entity first, or `None` for an empty
    /// authenticator (the client declined).
    pub fn validate_authenticator(
        &mut self,
        request: &[u8],
        authenticator: &[u8],
    ) -> Result<Option<Vec<CertificateDer<'static>>>, Error> {
        let (chain, answered) = {
            let state = &self.core.data.authenticators;
            let config = state.config.as_ref().ok_or(Error::HandshakeNotComplete)?;
            let verifier = &config.verifier;
            let now = config
                .time_provider
                .current_time()
                .ok_or(Error::FailedToGetCurrentTime)?;
            let conn = connection(self, Side::Server)?;
            conn.validate(
                Some(request),
                authenticator,
                &[],
                &state.contexts,
                |ee, intermediates| {
                    verifier
                        .verify_client_cert(ee, intermediates, now)
                        .map(|_| ())
                },
                |msg, ee, dss| verifier.verify_tls13_signature(msg, ee, dss),
            )?
        };
        self.core.data.authenticators.contexts.record(answered);
        Ok(chain)
    }
}

/// The connection's exporter, suite and provider, after the handshake.
fn connection<Data: crate::conn::SideData + HasProvider>(
    conn: &crate::conn::ConnectionCommon<Data>,
    side: Side,
) -> Result<Connection<'_>, Error> {
    if conn.is_handshaking() {
        return Err(Error::HandshakeNotComplete);
    }
    let provider = conn
        .core
        .data
        .provider()
        .ok_or(Error::HandshakeNotComplete)?;
    Ok(Connection {
        side,
        suite: conn.negotiated_cipher_suite(),
        provider,
        export: conn,
    })
}

/// Where a side's crypto provider lives.
pub(crate) trait HasProvider {
    fn provider(&self) -> Option<&crate::crypto::CryptoProvider>;
}

impl HasProvider for crate::client::ClientConnectionData {
    fn provider(&self) -> Option<&crate::crypto::CryptoProvider> {
        Some(self.config.crypto_provider())
    }
}

impl HasProvider for crate::server::ServerConnectionData {
    fn provider(&self) -> Option<&crate::crypto::CryptoProvider> {
        self.authenticators
            .config
            .as_ref()
            .map(|c| &**c.crypto_provider())
    }
}
