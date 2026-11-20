//! The public methods on the connection types.
//!
//! Each side's methods are written once, in a macro that defines them on
//! the buffered connection (with `std`) and on the unbuffered one, so both
//! have the same signatures and documentation. Their bodies are one-line
//! calls into the functions below, which work on the [`ConnectionCore`]
//! that both APIs drive: the context lists, request digests, verifier
//! calls and clock are the same code for both.

use alloc::vec::Vec;

use browntls_pki::CertificateDer;

use super::connection::connection;
use super::messages::{make_request, tls13_schemes};
use super::{AuthenticatorRequestExtensions, request_digest};
use crate::client::ClientConnectionData;
use crate::common_state::Side;
use crate::conn::ConnectionCore;
use crate::error::Error;
use crate::server::ServerConnectionData;
use crate::sign::CertifiedKey;

// ------------------------------------------------------------------ client

fn client_request(
    core: &mut ConnectionCore<ClientConnectionData>,
    context: &[u8],
    extensions: &AuthenticatorRequestExtensions,
) -> Result<Vec<u8>, Error> {
    let data = &mut core.data;
    data.authenticators.check_request(context)?;
    let defaults = data.config.verifier().supported_verify_schemes();
    let request = make_request(Side::Client, context, extensions, defaults)?;
    let digest = request_digest(data.config.crypto_provider(), &request)?;
    data.authenticators.add_request(context, digest);
    Ok(request)
}

fn client_answer(
    core: &mut ConnectionCore<ClientConnectionData>,
    request: &[u8],
    certified_key: Option<&CertifiedKey>,
) -> Result<Vec<u8>, Error> {
    let (out, context) = connection(core, Side::Client)?.make_authenticator(
        Some(request),
        certified_key,
        &[],
        &core.data.authenticators,
    )?;
    core.data.authenticators.made.push(context);
    Ok(out)
}

fn client_validate(
    core: &mut ConnectionCore<ClientConnectionData>,
    request: Option<&[u8]>,
    authenticator: &[u8],
) -> Result<Option<Vec<CertificateDer<'static>>>, Error> {
    let (chain, answered) = {
        let conn = connection(core, Side::Client)?;
        let data = &core.data;
        let config = &data.config;
        let verifier = config.verifier();
        let now = config
            .time_provider
            .current_time()
            .ok_or(Error::FailedToGetCurrentTime)?;
        let offered = tls13_schemes(&verifier.supported_verify_schemes());
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
    core.data.authenticators.record(answered);
    Ok(chain)
}

/// Defines the client methods on `$conn`, a client connection type whose
/// `core` (reached through `Deref`) is a `ConnectionCore`.
macro_rules! client_methods {
    ($conn:ty) => {
        impl $conn {
            /// Builds an authenticator request (a `ClientCertificateRequest`,
            /// RFC 9261 §4) asking the server to prove possession of another
            /// certificate. `context` (1 to 255 bytes) must be unique on this
            /// connection and should be unpredictable to the server.
            ///
            /// May be called before the handshake has completed. Fails with
            /// [`Error::General`], recording nothing, for a context of the
            /// wrong length or already used in a request on this connection,
            /// once 256 requests have been made, or when no TLS 1.3 signature
            /// scheme is left to ask for.
            pub fn request_authenticator(
                &mut self,
                context: &[u8],
                extensions: &AuthenticatorRequestExtensions,
            ) -> Result<Vec<u8>, Error> {
                client_request(&mut self.core, context, extensions)
            }

            /// Answers the server's authenticator `request` (a TLS 1.3
            /// `CertificateRequest`) with `certified_key` (RFC 9261 §5), or with
            /// an empty authenticator declining it when `certified_key` is
            /// `None` or cannot sign with any scheme the request allows.
            ///
            /// Fails with [`Error::HandshakeNotComplete`] until the handshake
            /// has completed (also when the handshake itself failed), with
            /// the connection's error if it fails after that,
            /// for a malformed request or one of the wrong type, for a context
            /// already answered on this connection
            /// ([`PeerMisbehaved::ReusedAuthenticatorContext`](crate::PeerMisbehaved::ReusedAuthenticatorContext)),
            /// once 256 authenticators have been made, and on a TLS 1.2
            /// connection without the extended master secret, whose exporter
            /// is refused.
            pub fn authenticator(
                &mut self,
                request: &[u8],
                certified_key: Option<&CertifiedKey>,
            ) -> Result<Vec<u8>, Error> {
                client_answer(&mut self.core, request, certified_key)
            }

            /// Validates the server's `authenticator` answering our `request`,
            /// or a spontaneous one when `request` is `None` (RFC 9261 §5).
            ///
            /// `request` must be one this connection made with
            /// [`Self::request_authenticator`] and not yet answered.
            ///
            /// The chain is verified for this connection's server name (the
            /// name given to [`Self::new`] and sent as SNI), and the
            /// signature checked, by the configured server certificate
            /// verifier, at the time of the configured time provider.
            /// Secondary host names are not supported: requests carry no
            /// `server_name` extension, and a certificate valid only for
            /// another name is rejected. Returns the certificates, end entity
            /// first, or `None` for an empty authenticator (the server
            /// declined).
            ///
            /// Fails with [`Error::HandshakeNotComplete`] until the handshake
            /// has completed (also when the handshake itself failed), with
            /// the connection's error if it fails after that (which may be
            /// [`Error::DecryptError`] too, for a bad record: check the
            /// connection before blaming the authenticator), with
            /// [`Error::FailedToGetCurrentTime`] when the time provider gives
            /// no time (the default without `std`), and for a `request` not
            /// made or already answered here, a malformed authenticator, a
            /// context already used, a spontaneous authenticator once 256
            /// have been validated, a `Finished` that does not verify
            /// ([`Error::DecryptError`]), a signature scheme the request did
            /// not allow, or a chain or signature the verifier rejects. A
            /// failed validation records nothing.
            pub fn validate_authenticator(
                &mut self,
                request: Option<&[u8]>,
                authenticator: &[u8],
            ) -> Result<Option<Vec<CertificateDer<'static>>>, Error> {
                client_validate(&mut self.core, request, authenticator)
            }
        }
    };
}

#[cfg(feature = "std")]
client_methods!(crate::client::ClientConnection);
client_methods!(crate::client::UnbufferedClientConnection);

// ------------------------------------------------------------------ server

fn server_request(
    core: &mut ConnectionCore<ServerConnectionData>,
    context: &[u8],
    extensions: &AuthenticatorRequestExtensions,
) -> Result<Vec<u8>, Error> {
    let state = &mut core.data.authenticators;
    state.contexts.check_request(context)?;
    let config = state.config.as_ref().ok_or(Error::HandshakeNotComplete)?;
    let defaults = config.verifier.supported_verify_schemes();
    let request = make_request(Side::Server, context, extensions, defaults)?;
    let digest = request_digest(config.crypto_provider(), &request)?;
    state.contexts.add_request(context, digest);
    Ok(request)
}

fn server_answer(
    core: &mut ConnectionCore<ServerConnectionData>,
    request: Option<&[u8]>,
    certified_key: Option<&CertifiedKey>,
) -> Result<Vec<u8>, Error> {
    let state = &core.data.authenticators;
    let (out, context) = connection(core, Side::Server)?.make_authenticator(
        request,
        certified_key,
        &state.client_sig_schemes,
        &state.contexts,
    )?;
    core.data.authenticators.contexts.made.push(context);
    Ok(out)
}

fn server_validate(
    core: &mut ConnectionCore<ServerConnectionData>,
    request: &[u8],
    authenticator: &[u8],
) -> Result<Option<Vec<CertificateDer<'static>>>, Error> {
    let (chain, answered) = {
        let conn = connection(core, Side::Server)?;
        let state = &core.data.authenticators;
        let config = state.config.as_ref().ok_or(Error::HandshakeNotComplete)?;
        let verifier = &config.verifier;
        let now = config
            .time_provider
            .current_time()
            .ok_or(Error::FailedToGetCurrentTime)?;
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
    core.data.authenticators.contexts.record(answered);
    Ok(chain)
}

/// Defines the server methods on `$conn`, a server connection type whose
/// `core` (reached through `Deref`) is a `ConnectionCore`.
macro_rules! server_methods {
    ($conn:ty) => {
        impl $conn {
            /// Builds an authenticator request (a TLS 1.3 `CertificateRequest`,
            /// RFC 9261 §4) asking the client to prove possession of a
            /// certificate. `context` (1 to 255 bytes) must be unique on this
            /// connection and should be unpredictable to the client.
            ///
            /// Fails with [`Error::HandshakeNotComplete`] until the ClientHello
            /// has been processed, and with [`Error::General`], recording
            /// nothing, for a context of the wrong length or already used in
            /// a request on this connection, once 256 requests have been
            /// made, or when no TLS 1.3 signature scheme is left to ask for.
            pub fn request_authenticator(
                &mut self,
                context: &[u8],
                extensions: &AuthenticatorRequestExtensions,
            ) -> Result<Vec<u8>, Error> {
                server_request(&mut self.core, context, extensions)
            }

            /// Answers the client's authenticator `request` (a
            /// `ClientCertificateRequest`) with `certified_key`, or, with
            /// `request` `None`, authenticates spontaneously with a fresh random
            /// context and a scheme from the client's `signature_algorithms`
            /// (RFC 9261 §5). Declines with an empty authenticator when
            /// answering a request without a usable `certified_key`.
            ///
            /// Fails with [`Error::HandshakeNotComplete`] until the handshake
            /// has completed (also when the handshake itself failed), with
            /// the connection's error if it fails after that,
            /// for a malformed request or one of the wrong type, for a context
            /// already answered on this connection
            /// ([`PeerMisbehaved::ReusedAuthenticatorContext`](crate::PeerMisbehaved::ReusedAuthenticatorContext)),
            /// once 256 authenticators have been made, for a spontaneous
            /// authenticator without a certificate whose key can sign with a
            /// scheme the client offered, and on a TLS 1.2 connection without
            /// the extended master secret, whose exporter is refused.
            pub fn authenticator(
                &mut self,
                request: Option<&[u8]>,
                certified_key: Option<&CertifiedKey>,
            ) -> Result<Vec<u8>, Error> {
                server_answer(&mut self.core, request, certified_key)
            }

            /// Validates the client's `authenticator` answering our `request`
            /// (RFC 9261 §5), which must be one this connection made with
            /// [`Self::request_authenticator`] and not yet answered. The chain
            /// and signature are checked by the configured client certificate
            /// verifier, at the time of the configured time provider. Returns
            /// the certificates, end entity first, or `None` for an empty
            /// authenticator (the client declined).
            ///
            /// Fails with [`Error::HandshakeNotComplete`] until the handshake
            /// has completed (also when the handshake itself failed), with
            /// the connection's error if it fails after that (which may be
            /// [`Error::DecryptError`] too, for a bad record: check the
            /// connection before blaming the authenticator), with
            /// [`Error::FailedToGetCurrentTime`] when the time provider gives
            /// no time (the default without `std`), and for a `request` not
            /// made or already answered here, a malformed authenticator, a
            /// `Finished` that does not verify ([`Error::DecryptError`]), a
            /// signature scheme the request did not allow, or a chain or
            /// signature the verifier rejects. A failed validation records
            /// nothing.
            pub fn validate_authenticator(
                &mut self,
                request: &[u8],
                authenticator: &[u8],
            ) -> Result<Option<Vec<CertificateDer<'static>>>, Error> {
                server_validate(&mut self.core, request, authenticator)
            }
        }
    };
}

#[cfg(feature = "std")]
server_methods!(crate::server::ServerConnection);
server_methods!(crate::server::UnbufferedServerConnection);
