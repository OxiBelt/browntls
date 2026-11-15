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

use alloc::vec;
use alloc::vec::Vec;

use browntls_pki::CertificateDer;

use crate::common_state::Side;
use crate::crypto::hash::Hash;
use crate::crypto::tls13::{Hkdf, OkmBlock};
use crate::crypto::{CryptoProvider, zeroize_vec};
use crate::ct::constant_time_eq;
use crate::enums::SignatureScheme;
use crate::error::{Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
use crate::msgs::base::PayloadU8;
use crate::msgs::codec::{Codec, Reader, u24};
use crate::msgs::handshake::{
    CertificatePayloadTls13, CertificateRequestExtensions, CertificateRequestPayloadTls13,
    DistinguishedName, MAX_HANDSHAKE_SIZE,
};
use crate::sign::CertifiedKey;
use crate::suites::SupportedCipherSuite;
use crate::verify::{DigitallySignedStruct, HandshakeSignatureValid};

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

/// The connection-bound keys for authenticators created by one side.
struct Keys {
    hash: &'static dyn Hash,
    hmac: &'static dyn Hkdf,
    handshake_context: Vec<u8>,
    finished_key: OkmBlock,
}

impl Keys {
    /// `export` is the connection's exporter (label, output).
    fn new(
        suite: Option<SupportedCipherSuite>,
        provider: &CryptoProvider,
        creator: Side,
        export: &dyn Exporter,
    ) -> Result<Self, Error> {
        #[cfg(not(feature = "tls12"))]
        let _ = provider;
        let suite = suite.ok_or(Error::HandshakeNotComplete)?;
        let hash = suite.hash_provider();
        // HMAC with the connection's hash: a TLS 1.3 suite's HKDF provides
        // it; for TLS 1.2, any TLS 1.3 suite of the provider with that hash.
        let hmac = match suite {
            SupportedCipherSuite::Tls13(s) => Some(s.hkdf_provider),
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(_) => provider.cipher_suites.iter().find_map(|cs| {
                cs.tls13()
                    .filter(|s| s.common.hash_provider.algorithm() == hash.algorithm())
                    .map(|s| s.hkdf_provider)
            }),
        }
        .ok_or_else(|| {
            Error::General("no HMAC for the connection's hash in the crypto provider".into())
        })?;
        let (context_label, key_label): (&[u8], &[u8]) = match creator {
            Side::Client => (
                b"EXPORTER-client authenticator handshake context",
                b"EXPORTER-client authenticator finished key",
            ),
            Side::Server => (
                b"EXPORTER-server authenticator handshake context",
                b"EXPORTER-server authenticator finished key",
            ),
        };
        let mut handshake_context = vec![0u8; hash.output_len()];
        export.export(context_label, &mut handshake_context)?;
        let mut key = vec![0u8; hash.output_len()];
        export.export(key_label, &mut key)?;
        let finished_key = OkmBlock::new(&key);
        zeroize_vec(&mut key);
        Ok(Self {
            hash,
            hmac,
            handshake_context,
            finished_key,
        })
    }

    fn transcript(&self, request: &[u8]) -> alloc::boxed::Box<dyn crate::crypto::hash::Context> {
        let mut ctx = self.hash.start();
        ctx.update(&self.handshake_context);
        ctx.update(request);
        ctx
    }

    fn finished(&self, transcript: alloc::boxed::Box<dyn crate::crypto::hash::Context>) -> Vec<u8> {
        let hash = transcript.finish();
        self.hmac
            .hmac_sign(&self.finished_key, hash.as_ref())
            .as_ref()
            .to_vec()
    }
}

/// The bytes a CertificateVerify signs (RFC 9261 §5.2.2).
fn signed_message(transcript_hash: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64 + SIGNATURE_CONTEXT.len() + 1 + transcript_hash.len());
    msg.resize(64, 0x20);
    msg.extend_from_slice(SIGNATURE_CONTEXT);
    msg.push(0);
    msg.extend_from_slice(transcript_hash);
    msg
}

/// A handshake message: type, 24-bit length, body.
fn frame(typ: u8, body: &[u8]) -> Result<Vec<u8>, Error> {
    let len = u24::from_usize(body.len())
        .filter(|len| len.0 <= MAX_HANDSHAKE_SIZE)
        .ok_or_else(|| Error::General("exported authenticator message too large".into()))?;
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(typ);
    len.encode(&mut out);
    out.extend_from_slice(body);
    Ok(out)
}

/// Reads one handshake message: (type, body).
fn read_message<'a>(r: &mut Reader<'a>) -> Result<(u8, &'a [u8]), InvalidMessage> {
    let typ = u8::read(r)?;
    let len = u24::read(r)?.0;
    if len > MAX_HANDSHAKE_SIZE {
        return Err(InvalidMessage::HandshakePayloadTooLarge);
    }
    let body = r.take(len as usize).ok_or(InvalidMessage::MissingData(
        "exported authenticator message",
    ))?;
    Ok((typ, body))
}

/// A parsed authenticator request.
struct Request<'a> {
    bytes: &'a [u8],
    context: Vec<u8>,
    schemes: Vec<SignatureScheme>,
}

fn parse_request(bytes: &[u8], expected_type: u8) -> Result<Request<'_>, Error> {
    let mut r = Reader::init(bytes);
    let (typ, body) = read_message(&mut r)?;
    r.expect_empty("authenticator request")?;
    if typ != expected_type {
        return Err(InvalidMessage::UnexpectedMessage("authenticator request type").into());
    }
    let req = CertificateRequestPayloadTls13::read_bytes(body)?;
    // RFC 9846 §4.3 applies to the extensions as in a CertificateRequest.
    if crate::tls13::extensions::first_disallowed(
        req.extensions.unknown.iter().copied(),
        crate::tls13::extensions::Tls13Message::CertificateRequest,
    )
    .is_some()
    {
        return Err(PeerMisbehaved::DisallowedCertificateRequestExtension.into());
    }
    // RFC 9261 §4: signature_algorithms MUST be present.
    let Some(schemes) = req.extensions.signature_algorithms else {
        return Err(PeerIncompatible::SignatureAlgorithmsExtensionRequired.into());
    };
    if req.context.0.is_empty() {
        return Err(PeerMisbehaved::IllegalCertificateRequestContext.into());
    }
    Ok(Request {
        bytes,
        context: req.context.0,
        schemes: tls13_schemes(&schemes),
    })
}

fn tls13_schemes(schemes: &[SignatureScheme]) -> Vec<SignatureScheme> {
    schemes
        .iter()
        .copied()
        .filter(SignatureScheme::supported_in_tls13)
        .collect()
}

/// Builds a request from `requester` (RFC 9261 §4).
fn make_request(
    requester: Side,
    context: &[u8],
    extensions: &AuthenticatorRequestExtensions,
    default_schemes: Vec<SignatureScheme>,
) -> Result<Vec<u8>, Error> {
    if context.is_empty() || context.len() > 255 {
        return Err(Error::General(
            "certificate_request_context must be 1 to 255 bytes".into(),
        ));
    }
    let schemes = tls13_schemes(
        extensions
            .signature_schemes
            .as_deref()
            .unwrap_or(&default_schemes),
    );
    if schemes.is_empty() {
        return Err(Error::General(
            "an authenticator request needs a TLS 1.3 signature scheme".into(),
        ));
    }
    let payload = CertificateRequestPayloadTls13 {
        context: PayloadU8::new(context.to_vec()),
        extensions: CertificateRequestExtensions {
            signature_algorithms: Some(schemes),
            authorities: extensions.certificate_authorities.clone(),
            ..Default::default()
        },
    };
    let typ = match requester {
        Side::Client => CLIENT_CERTIFICATE_REQUEST,
        Side::Server => CERTIFICATE_REQUEST,
    };
    frame(typ, &payload.get_encoding())
}

/// The connection-level inputs of [`make_authenticator`] and [`validate`].
/// The connection's exporter, without context.
trait Exporter {
    /// Fills `output` from the exporter with `label` and an empty context.
    fn export(&self, label: &[u8], output: &mut [u8]) -> Result<(), Error>;
}

#[cfg(feature = "std")]
impl<Data: crate::conn::SideData> Exporter for crate::conn::ConnectionCommon<Data> {
    fn export(&self, label: &[u8], output: &mut [u8]) -> Result<(), Error> {
        // RFC 9261 §5.1: "context_value is empty (zero length)". In TLS 1.2
        // (RFC 5705) a zero-length context differs from no context: its
        // two length octets enter the PRF seed. In TLS 1.3 both hash the
        // empty string.
        self.export_keying_material(output, label, Some(&[]))
            .map(|_| ())
    }
}

struct Connection<'a> {
    side: Side,
    suite: Option<SupportedCipherSuite>,
    provider: &'a CryptoProvider,
    export: &'a dyn Exporter,
}

impl Connection<'_> {
    fn keys(&self, creator: Side) -> Result<Keys, Error> {
        Keys::new(self.suite, self.provider, creator, self.export)
    }

    /// Builds our authenticator (RFC 9261 §5) answering `request` (from the
    /// peer), or a spontaneous one when we are the server and `request` is
    /// `None`. Returns the authenticator and its context.
    fn make_authenticator(
        &self,
        request: Option<&[u8]>,
        certified_key: Option<&CertifiedKey>,
        spontaneous_schemes: &[SignatureScheme],
        state: &AuthenticatorState,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let (request_bytes, context, schemes) = match request {
            Some(bytes) => {
                let expected = match self.side {
                    Side::Server => CLIENT_CERTIFICATE_REQUEST,
                    Side::Client => CERTIFICATE_REQUEST,
                };
                let req = parse_request(bytes, expected)?;
                (req.bytes, req.context, req.schemes)
            }
            None if self.side == Side::Server => {
                let mut context = vec![0u8; SPONTANEOUS_CONTEXT_LEN];
                self.provider.secure_random.fill(&mut context)?;
                (&[][..], context, tls13_schemes(spontaneous_schemes))
            }
            None => {
                return Err(Error::General(
                    "only a server may create an authenticator without a request".into(),
                ));
            }
        };
        state.check_make(&context)?;
        let keys = self.keys(self.side)?;

        let signing = certified_key
            .filter(|ck| !ck.cert.is_empty())
            .and_then(|ck| Some((ck, ck.key.choose_scheme(&schemes)?)));
        let Some((certified_key, signer)) = signing else {
            if request.is_none() {
                return Err(Error::General(
                    "a spontaneous authenticator needs a certificate whose key can sign with a \
                     scheme the client offered"
                        .into(),
                ));
            }
            // RFC 9261 §5.2.5: the empty authenticator, a Finished over a
            // Certificate with no entries.
            let certificate = frame(
                CERTIFICATE,
                &CertificatePayloadTls13 {
                    context: PayloadU8::new(context.clone()),
                    entries: Vec::new(),
                }
                .get_encoding(),
            )?;
            let mut transcript = keys.transcript(request_bytes);
            transcript.update(&certificate);
            return Ok((frame(FINISHED, &keys.finished(transcript))?, context));
        };

        let mut payload = CertificatePayloadTls13::new(certified_key.cert.iter(), None);
        payload.context = PayloadU8::new(context.clone());
        let certificate = frame(CERTIFICATE, &payload.get_encoding())?;
        let mut transcript = keys.transcript(request_bytes);
        transcript.update(&certificate);
        let signature = signer.sign(&signed_message(transcript.fork_finish().as_ref()))?;
        let certificate_verify = frame(
            CERTIFICATE_VERIFY,
            &DigitallySignedStruct::new(signer.scheme(), signature).get_encoding(),
        )?;
        transcript.update(&certificate_verify);
        let finished = frame(FINISHED, &keys.finished(transcript))?;

        let mut out = certificate;
        out.extend_from_slice(&certificate_verify);
        out.extend_from_slice(&finished);
        Ok((out, context))
    }

    /// Validates the peer's `authenticator` answering our `request`, or a
    /// spontaneous server authenticator when we are the client and
    /// `request` is `None`. Returns the certificates (`None` for an empty
    /// authenticator) and what was answered.
    ///
    /// A `request` must be one this side made (compared by digest) and not
    /// yet answered.
    #[allow(clippy::type_complexity)]
    fn validate(
        &self,
        request: Option<&[u8]>,
        authenticator: &[u8],
        spontaneous_schemes: &[SignatureScheme],
        state: &AuthenticatorState,
        verify_chain: impl FnOnce(&CertificateDer<'_>, &[CertificateDer<'_>]) -> Result<(), Error>,
        verify_signature: impl FnOnce(
            &[u8],
            &CertificateDer<'_>,
            &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error>,
    ) -> Result<(Option<Vec<CertificateDer<'static>>>, Answered), Error> {
        let creator = self.side.peer();
        let request_index = match request {
            Some(bytes) => Some(state.find_request(&request_digest(self.provider, bytes)?)?),
            None => None,
        };
        let request = match request {
            Some(bytes) => {
                let ours = match self.side {
                    Side::Client => CLIENT_CERTIFICATE_REQUEST,
                    Side::Server => CERTIFICATE_REQUEST,
                };
                Some(parse_request(bytes, ours)?)
            }
            None if creator == Side::Server => None,
            None => {
                return Err(Error::General(
                    "only a server may send an authenticator without a request".into(),
                ));
            }
        };
        let request_bytes = request.as_ref().map(|r| r.bytes).unwrap_or_default();

        let mut r = Reader::init(authenticator);
        let (typ, body) = read_message(&mut r)?;
        let keys = self.keys(creator)?;

        // An empty authenticator: a lone Finished declining the request.
        if typ == FINISHED {
            r.expect_empty("exported authenticator")?;
            let (Some(request), Some(index)) = (&request, request_index) else {
                return Err(Error::NoCertificatesPresented);
            };
            let certificate = frame(
                CERTIFICATE,
                &CertificatePayloadTls13 {
                    context: PayloadU8::new(request.context.clone()),
                    entries: Vec::new(),
                }
                .get_encoding(),
            )?;
            let mut transcript = keys.transcript(request_bytes);
            transcript.update(&certificate);
            if !constant_time_eq(&keys.finished(transcript), body) {
                return Err(Error::DecryptError);
            }
            return Ok((None, Answered::Request(index)));
        }

        if typ != CERTIFICATE {
            return Err(
                InvalidMessage::UnexpectedMessage("exported authenticator Certificate").into(),
            );
        }
        let certificate = &authenticator[..r.used()];
        let payload = CertificatePayloadTls13::read_bytes(body)?;
        let context = payload.context.0.clone();
        match &request {
            Some(request) if request.context != context => {
                return Err(PeerMisbehaved::IllegalCertificateRequestContext.into());
            }
            None if context.is_empty() => {
                return Err(PeerMisbehaved::IllegalCertificateRequestContext.into());
            }
            _ => {}
        }
        if request.is_none() {
            state.check_spontaneous(&context)?;
        }
        // RFC 9261 §5.2.1: a Certificate with no entries is not sent; the
        // empty authenticator omits it.
        if payload.entries.is_empty() {
            return Err(Error::NoCertificatesPresented);
        }
        // Entry extensions must answer extensions of the request; ours
        // carry none that a certificate entry may answer.
        if payload
            .entries
            .iter()
            .any(|e| e.status.is_some() || e.sct_list.is_some() || e.delegated_credential.is_some())
        {
            return Err(PeerMisbehaved::UnsolicitedCertExtension.into());
        }

        let cv_start = r.used();
        let (typ, cv_body) = read_message(&mut r)?;
        if typ != CERTIFICATE_VERIFY {
            return Err(InvalidMessage::UnexpectedMessage(
                "exported authenticator CertificateVerify",
            )
            .into());
        }
        let certificate_verify = &authenticator[cv_start..r.used()];
        let dss = DigitallySignedStruct::read_bytes(cv_body)?;
        let (typ, finished) = read_message(&mut r)?;
        if typ != FINISHED {
            return Err(
                InvalidMessage::UnexpectedMessage("exported authenticator Finished").into(),
            );
        }
        r.expect_empty("exported authenticator")?;

        let mut transcript = keys.transcript(request_bytes);
        transcript.update(certificate);
        let signed = signed_message(transcript.fork_finish().as_ref());
        transcript.update(certificate_verify);
        if !constant_time_eq(&keys.finished(transcript), finished) {
            return Err(Error::DecryptError);
        }

        // RFC 9261 §5.2.2: a TLS 1.3 scheme from the request (or, for a
        // spontaneous authenticator, from our ClientHello).
        let allowed = match &request {
            Some(request) => request.schemes.clone(),
            None => tls13_schemes(spontaneous_schemes),
        };
        if !allowed.contains(&dss.scheme) {
            return Err(PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme.into());
        }

        let chain: Vec<CertificateDer<'static>> = payload
            .into_certificate_chain()
            .0
            .into_iter()
            .map(CertificateDer::into_owned)
            .collect();
        let (end_entity, intermediates) =
            chain.split_first().ok_or(Error::NoCertificatesPresented)?;
        verify_chain(end_entity, intermediates)?;
        verify_signature(&signed, end_entity, &dss)?;
        let answered = match request_index {
            Some(index) => Answered::Request(index),
            None => Answered::Spontaneous(context),
        };
        Ok((Some(chain), answered))
    }
}

#[cfg(feature = "std")]
mod api {
    use alloc::vec::Vec;

    use browntls_pki::CertificateDer;

    use super::{
        AuthenticatorRequestExtensions, Connection, make_request, request_digest, tls13_schemes,
    };
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_lists_are_capped_separately() {
        let mut state = AuthenticatorState::default();
        state.add_request(b"ours", vec![1]);
        // A peer fills the list of spontaneous authenticators...
        for i in 0..MAX_CONTEXTS {
            let context = (i as u32).to_be_bytes().to_vec();
            state.check_spontaneous(&context).unwrap();
            state.record(Answered::Spontaneous(context));
        }
        assert!(matches!(
            state.check_spontaneous(b"one more"),
            Err(Error::General(_))
        ));
        // ...and of authenticators we made (one per request it sends).
        for i in 0..MAX_CONTEXTS {
            let context = (i as u32).to_be_bytes().to_vec();
            state.check_make(&context).unwrap();
            state.made.push(context);
        }
        assert!(state.check_make(b"one more").is_err());
        // Answers to our own request still validate, once.
        let index = state.find_request(&[1]).unwrap();
        state.record(Answered::Request(index));
        assert_eq!(
            state.find_request(&[1]),
            Err(PeerMisbehaved::ReusedAuthenticatorContext.into())
        );
        // A request we did not make is refused.
        assert!(matches!(state.find_request(&[2]), Err(Error::General(_))));
        // A spontaneous authenticator may not take a requested context.
        let mut state = AuthenticatorState::default();
        state.add_request(b"ours", vec![1]);
        assert_eq!(
            state.check_spontaneous(b"ours"),
            Err(PeerMisbehaved::ReusedAuthenticatorContext.into())
        );
    }
}
