//! Exported authenticators (RFC 9261).
//!
//! After a handshake, either side can prove possession of a further
//! certificate's key, bound to the connection through the TLS exporter,
//! without renegotiation or post-handshake authentication. The messages
//! travel over the application protocol (for example HTTP/2 secondary
//! certificates), not over the TLS record layer:
//!
//! 1. One side builds an *authenticator request* with
//!    `request_authenticator`: a `ClientCertificateRequest` (handshake type
//!    17) from a client, a TLS 1.3 `CertificateRequest` (type 13) from a
//!    server.
//! 2. The peer answers with `authenticator`: `Certificate`,
//!    `CertificateVerify` and `Finished` handshake messages (TLS 1.3
//!    formats, whatever the version), or an *empty authenticator* (a lone
//!    `Finished`) to decline. A server may also authenticate spontaneously,
//!    without a request.
//! 3. The requester checks it with `validate_authenticator`, which verifies
//!    the chain and signature through the connection's configured
//!    certificate verifier and returns the certificates.
//!
//! The three methods exist on both sides of both connection APIs, with the
//! same signatures, checks and errors: `ClientConnection` and
//! `ServerConnection` (with the `std` feature), and
//! [`UnbufferedClientConnection`](crate::client::UnbufferedClientConnection)
//! and
//! [`UnbufferedServerConnection`](crate::server::UnbufferedServerConnection)
//! (also without `std`). Both APIs run the same code on the connection's state
//! machine, so the checks below hold for both; an unbuffered connection is used
//! between calls to `process_tls_records`, since the messages never touch its
//! records. QUIC connections do not offer exported authenticators. Without
//! `std` the configurations' default time provider has no clock, so
//! `validate_authenticator` fails with [`Error::FailedToGetCurrentTime`] unless
//! one is configured (`builder_with_details`).
//!
//! The `Handshake Context` and `Finished MAC Key` come from the exporter
//! (RFC 9261 §5.1) with the labels `EXPORTER-{client,server} authenticator
//! handshake context` and `EXPORTER-{client,server} authenticator finished
//! key` of the side creating the authenticator, a zero-length context (in
//! TLS 1.2 its length octets enter the RFC 5705 seed; in TLS 1.3 it is the
//! same as no context) and the length of the connection's hash. The
//! CertificateVerify signature covers 64 octets of 0x20, `"Exported
//! Authenticator"`, a zero octet and `Hash(Handshake Context || request ||
//! Certificate)` (§5.2.2); `Finished`
//! is `HMAC(Finished MAC Key, Hash(Handshake Context || request ||
//! Certificate || CertificateVerify))` (§5.2.3).
//!
//! TLS 1.3 connections, and TLS 1.2 connections with the extended master
//! secret (without it the exporter is refused, RFC 7627 §5.4), are
//! supported. Each `certificate_request_context` is used at most once per
//! connection: a second request, authenticator or validation with a context
//! already used fails. `validate_authenticator` accepts only a request this
//! connection made (recognised by a digest of its bytes) and not yet
//! answered. Each side keeps three lists of at most 256 entries: requests
//! it made, authenticators it made and spontaneous authenticators it
//! validated; a full list makes further requests, authenticators or
//! spontaneous validations fail (fail closed), and since the lists are
//! separate, a peer cannot stop answers to our own requests from
//! validating.
//!
//! No interoperability with other implementations has been tested; browntls
//! talks to itself only.

mod api;
mod connection;
mod messages;
#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use crate::crypto::CryptoProvider;
use crate::enums::SignatureScheme;
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::msgs::base::PayloadU8;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::DistinguishedName;

use self::messages::read_message;

const CERTIFICATE: u8 = 11;
const CERTIFICATE_REQUEST: u8 = 13;
const CERTIFICATE_VERIFY: u8 = 15;
const CLIENT_CERTIFICATE_REQUEST: u8 = 17;
const FINISHED: u8 = 20;

/// How many entries each list of a side's [`AuthenticatorState`] holds: the
/// requests it made, the authenticators it made, and the spontaneous
/// authenticators it validated. Each list is capped separately, so a peer
/// filling one (with requests to answer or spontaneous authenticators)
/// cannot stop answers to our own requests from validating.
const MAX_CONTEXTS: usize = 256;

/// The length of the context a server picks for a spontaneous authenticator.
const SPONTANEOUS_CONTEXT_LEN: usize = 32;

/// The CertificateVerify context string (RFC 9261 §5.2.2).
const SIGNATURE_CONTEXT: &[u8] = b"Exported Authenticator";

/// Optional content of an authenticator request (RFC 9261 §4).
#[derive(Clone, Debug, Default)]
pub struct AuthenticatorRequestExtensions {
    /// The `signature_algorithms` to accept. `None` uses the TLS 1.3
    /// schemes of the connection's certificate verifier.
    pub signature_schemes: Option<Vec<SignatureScheme>>,
    /// `certificate_authorities` to send, if any.
    pub certificate_authorities: Option<Vec<DistinguishedName>>,
}

/// The `certificate_request_context` of an authenticator (RFC 9261 §7.2,
/// the "get context" API), for example to match a spontaneous server
/// authenticator with application state before validating it. Fails for an
/// empty authenticator, which carries no Certificate.
pub fn authenticator_context(authenticator: &[u8]) -> Result<Vec<u8>, Error> {
    let mut r = Reader::init(authenticator);
    let (typ, body) = read_message(&mut r)?;
    if typ != CERTIFICATE {
        return Err(InvalidMessage::UnexpectedMessage("exported authenticator Certificate").into());
    }
    let mut body = Reader::init(body);
    Ok(PayloadU8::read(&mut body)?.0)
}

/// A request we made: its context, a digest of its bytes and whether an
/// authenticator answering it has been validated.
#[derive(Debug)]
struct Requested {
    context: Vec<u8>,
    digest: Vec<u8>,
    answered: bool,
}

/// What a successful validation answered, to be recorded.
enum Answered {
    /// The request at this index of [`AuthenticatorState::requested`].
    Request(usize),
    /// A spontaneous server authenticator with this context.
    Spontaneous(Vec<u8>),
}

/// The contexts one side has used.
#[derive(Debug, Default)]
pub(crate) struct AuthenticatorState {
    /// Requests we made.
    requested: Vec<Requested>,
    /// Contexts of authenticators we made.
    made: Vec<Vec<u8>>,
    /// Contexts of spontaneous server authenticators we validated.
    spontaneous: Vec<Vec<u8>>,
}

impl AuthenticatorState {
    fn check_request(&self, context: &[u8]) -> Result<(), Error> {
        if self.requested.iter().any(|r| r.context == context) {
            return Err(Error::General(
                "certificate_request_context already used in a request on this connection".into(),
            ));
        }
        if self.requested.len() >= MAX_CONTEXTS {
            return Err(Error::General(
                "too many exported authenticator requests on this connection".into(),
            ));
        }
        Ok(())
    }

    fn add_request(&mut self, context: &[u8], digest: Vec<u8>) {
        self.requested.push(Requested {
            context: context.to_vec(),
            digest,
            answered: false,
        });
    }

    /// Before making an authenticator with `context`.
    fn check_make(&self, context: &[u8]) -> Result<(), Error> {
        if self.made.iter().any(|c| c == context) {
            return Err(PeerMisbehaved::ReusedAuthenticatorContext.into());
        }
        if self.made.len() >= MAX_CONTEXTS {
            return Err(Error::General(
                "too many exported authenticators made on this connection".into(),
            ));
        }
        Ok(())
    }

    /// The unanswered request we made whose bytes have `digest`.
    fn find_request(&self, digest: &[u8]) -> Result<usize, Error> {
        let index = self
            .requested
            .iter()
            .position(|r| r.digest == digest)
            .ok_or_else(|| {
                Error::General("not an authenticator request made on this connection".into())
            })?;
        if self.requested[index].answered {
            return Err(PeerMisbehaved::ReusedAuthenticatorContext.into());
        }
        Ok(index)
    }

    /// Before validating a spontaneous authenticator with `context`.
    fn check_spontaneous(&self, context: &[u8]) -> Result<(), Error> {
        if self.spontaneous.iter().any(|c| c == context)
            || self.requested.iter().any(|r| r.context == context)
        {
            return Err(PeerMisbehaved::ReusedAuthenticatorContext.into());
        }
        if self.spontaneous.len() >= MAX_CONTEXTS {
            return Err(Error::General(
                "too many spontaneous exported authenticators on this connection".into(),
            ));
        }
        Ok(())
    }

    fn record(&mut self, answered: Answered) {
        match answered {
            Answered::Request(index) => self.requested[index].answered = true,
            Answered::Spontaneous(context) => self.spontaneous.push(context),
        }
    }
}

/// A digest of a request's bytes, to recognise it when an answer arrives:
/// the hash of the provider's first cipher suite, which does not depend on
/// the negotiated suite (a request may be made during the handshake).
fn request_digest(provider: &CryptoProvider, request: &[u8]) -> Result<Vec<u8>, Error> {
    let suite = provider
        .cipher_suites
        .first()
        .ok_or_else(|| Error::General("the crypto provider has no cipher suites".into()))?;
    Ok(suite.hash_provider().hash(request).as_ref().to_vec())
}

/// Server-side state: what the handshake left for exported authenticators.
#[derive(Debug, Default)]
pub(crate) struct ServerAuthenticatorState {
    pub(crate) config: Option<crate::sync::Arc<crate::server::ServerConfig>>,
    /// The client's `signature_algorithms`, for spontaneous authenticators.
    pub(crate) client_sig_schemes: Vec<SignatureScheme>,
    pub(crate) contexts: AuthenticatorState,
}
