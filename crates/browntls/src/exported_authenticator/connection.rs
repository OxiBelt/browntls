//! The connection-bound keys (RFC 9261 §5.1) and the creation and
//! validation of authenticators (§5.2) on one side of a connection.

use alloc::vec;
use alloc::vec::Vec;

use browntls_pki::CertificateDer;

use super::messages::{frame, parse_request, read_message, signed_message, tls13_schemes};
use super::{
    Answered, AuthenticatorState, CERTIFICATE, CERTIFICATE_REQUEST, CERTIFICATE_VERIFY,
    CLIENT_CERTIFICATE_REQUEST, FINISHED, SPONTANEOUS_CONTEXT_LEN, request_digest,
};
use crate::common_state::Side;
use crate::crypto::hash::Hash;
use crate::crypto::tls13::{Hkdf, OkmBlock};
use crate::crypto::{CryptoProvider, zeroize_vec};
use crate::ct::constant_time_eq;
use crate::enums::SignatureScheme;
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
use crate::msgs::base::PayloadU8;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::handshake::CertificatePayloadTls13;
use crate::sign::CertifiedKey;
use crate::suites::SupportedCipherSuite;
use crate::verify::{DigitallySignedStruct, HandshakeSignatureValid};

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

/// The connection's exporter, without context.
pub(super) trait Exporter {
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

pub(super) struct Connection<'a> {
    pub(super) side: Side,
    pub(super) suite: Option<SupportedCipherSuite>,
    pub(super) provider: &'a CryptoProvider,
    pub(super) export: &'a dyn Exporter,
}

impl Connection<'_> {
    fn keys(&self, creator: Side) -> Result<Keys, Error> {
        Keys::new(self.suite, self.provider, creator, self.export)
    }

    /// Builds our authenticator (RFC 9261 §5) answering `request` (from the
    /// peer), or a spontaneous one when we are the server and `request` is
    /// `None`. Returns the authenticator and its context.
    pub(super) fn make_authenticator(
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
    pub(super) fn validate(
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
