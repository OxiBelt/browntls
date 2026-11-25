//! Test doubles and wire helpers: verifiers that advertise the ML-DSA
//! schemes on top of the provider's, resolvers that record the schemes they
//! are given, a key that claims an ML-DSA scheme, readers for the
//! `signature_algorithms` lists of hellos and certificate requests, and
//! editors of plaintext handshake messages. All but the ML-DSA items are
//! general: the `rsa_pkcs1_legacy_rules` target uses them too.

#![allow(unreachable_pub)]

use std::sync::{Arc, Mutex};

use browntls_core::client::ResolvesClientCert;
use browntls_core::server::{ClientHello, ResolvesServerCert};
use browntls_core::sign::{CertifiedKey, Signer, SigningKey};
use browntls_core::{Error, SignatureAlgorithm, SignatureScheme};

use crate::common::{
    Chain, PinnedClientVerifier, PinnedServerVerifier, SchemeRecordingClientVerifier,
    SchemeRecordingServerVerifier,
};

/// The three schemes of `draft-ietf-tls-mldsa-06`, in code point order.
pub const ML_DSA: [SignatureScheme; 3] = [
    SignatureScheme::ML_DSA_44,
    SignatureScheme::ML_DSA_65,
    SignatureScheme::ML_DSA_87,
];

/// The provider's default schemes.
pub fn default_schemes() -> Vec<SignatureScheme> {
    crate::prov::SUPPORTED_SIG_ALGS.supported_schemes()
}

/// The provider's default schemes followed by the ML-DSA ones, as an
/// ML-DSA opt-in table lists them.
pub fn with_ml_dsa() -> Vec<SignatureScheme> {
    let mut schemes = default_schemes();
    schemes.extend(ML_DSA);
    schemes
}

pub fn has_any_ml_dsa(schemes: &[SignatureScheme]) -> bool {
    schemes.iter().any(|scheme| ML_DSA.contains(scheme))
}

pub fn has_all_ml_dsa(schemes: &[SignatureScheme]) -> bool {
    ML_DSA.iter().all(|scheme| schemes.contains(scheme))
}

/// A client's verifier pinning `chain` that advertises the ML-DSA schemes
/// too (it cannot verify an ML-DSA signature, and is never given one).
pub fn server_verifier(chain: &Chain) -> Arc<SchemeRecordingServerVerifier> {
    SchemeRecordingServerVerifier::new(PinnedServerVerifier::new(chain), &with_ml_dsa())
}

/// A server's client verifier pinning `chain` that advertises the ML-DSA
/// schemes too.
pub fn client_verifier(chain: &Chain, mandatory: bool) -> Arc<SchemeRecordingClientVerifier> {
    SchemeRecordingClientVerifier::new(PinnedClientVerifier::new(chain, mandatory), &with_ml_dsa())
}

/// A client certificate resolver that records the `sigschemes` of every
/// request and answers with `key`.
#[derive(Debug)]
pub struct RecordingClientResolver {
    key: Option<Arc<CertifiedKey>>,
    seen: Mutex<Vec<Vec<SignatureScheme>>>,
}

impl RecordingClientResolver {
    pub fn new(key: Option<CertifiedKey>) -> Arc<Self> {
        Arc::new(Self {
            key: key.map(Arc::new),
            seen: Mutex::new(Vec::new()),
        })
    }

    pub fn seen(&self) -> Vec<Vec<SignatureScheme>> {
        self.seen.lock().unwrap().clone()
    }
}

impl ResolvesClientCert for RecordingClientResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.seen.lock().unwrap().push(sigschemes.to_vec());
        self.key.clone()
    }

    fn has_certs(&self) -> bool {
        self.key.is_some()
    }
}

/// A server certificate resolver that records the schemes of every
/// ClientHello it is given and answers with `key`.
#[derive(Debug)]
pub struct RecordingServerResolver {
    key: Arc<CertifiedKey>,
    seen: Mutex<Vec<Vec<SignatureScheme>>>,
}

impl RecordingServerResolver {
    pub fn new(key: CertifiedKey) -> Arc<Self> {
        Arc::new(Self {
            key: Arc::new(key),
            seen: Mutex::new(Vec::new()),
        })
    }

    pub fn seen(&self) -> Vec<Vec<SignatureScheme>> {
        self.seen.lock().unwrap().clone()
    }
}

impl ResolvesServerCert for RecordingServerResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.seen
            .lock()
            .unwrap()
            .push(client_hello.signature_schemes().to_vec());
        Some(self.key.clone())
    }
}

/// A key that claims to sign with `claims` only, records every list of
/// schemes it is offered, and reports `algorithm` as its TLS 1.2 family.
/// Its signer must never be used: it panics.
#[derive(Debug)]
pub struct ClaimingKey {
    claims: SignatureScheme,
    algorithm: SignatureAlgorithm,
    ignores_offer: bool,
    offered: Mutex<Vec<Vec<SignatureScheme>>>,
}

impl ClaimingKey {
    /// A key that chooses `claims` only when it is offered.
    pub fn new(claims: SignatureScheme, algorithm: SignatureAlgorithm) -> Arc<Self> {
        Self::build(claims, algorithm, false)
    }

    /// A misbehaving key that chooses `claims` whatever it is offered.
    pub fn ignoring_offer(claims: SignatureScheme, algorithm: SignatureAlgorithm) -> Arc<Self> {
        Self::build(claims, algorithm, true)
    }

    fn build(claims: SignatureScheme, algorithm: SignatureAlgorithm, ignores: bool) -> Arc<Self> {
        Arc::new(Self {
            claims,
            algorithm,
            ignores_offer: ignores,
            offered: Mutex::new(Vec::new()),
        })
    }

    pub fn offered(&self) -> Vec<Vec<SignatureScheme>> {
        self.offered.lock().unwrap().clone()
    }
}

impl SigningKey for ClaimingKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.offered.lock().unwrap().push(offered.to_vec());
        (self.ignores_offer || offered.contains(&self.claims))
            .then(|| Box::new(PanickingSigner(self.claims)) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

#[derive(Debug)]
struct PanickingSigner(SignatureScheme);

impl Signer for PanickingSigner {
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, Error> {
        panic!("asked to sign with {:?}", self.0)
    }

    fn scheme(&self) -> SignatureScheme {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// The `signature_algorithms` extension type (RFC 9846 §4.2.3).
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
/// The `delegated_credential` extension type (RFC 9345 §4.1).
pub const EXT_DELEGATED_CREDENTIAL: u16 = 34;

pub fn u16_at(buf: &[u8], at: usize) -> usize {
    usize::from(u16::from_be_bytes([buf[at], buf[at + 1]]))
}

fn u24_at(buf: &[u8], at: usize) -> usize {
    (usize::from(buf[at]) << 16) | u16_at(buf, at + 1)
}

fn put_u16(buf: &mut [u8], at: usize, value: usize) {
    buf[at..at + 2].copy_from_slice(&u16::try_from(value).unwrap().to_be_bytes());
}

/// A `SignatureSchemeList` without its length prefix.
pub fn schemes_of(list: &[u8]) -> Vec<SignatureScheme> {
    assert_eq!(list.len() % 2, 0);
    list.chunks(2)
        .map(|pair| SignatureScheme::from(u16::from_be_bytes([pair[0], pair[1]])))
        .collect()
}

/// A length-prefixed `SignatureSchemeList` that fills `body`.
pub fn prefixed_schemes(body: &[u8]) -> Vec<SignatureScheme> {
    assert_eq!(u16_at(body, 0) + 2, body.len());
    schemes_of(&body[2..])
}

pub fn encode_schemes(schemes: &[SignatureScheme]) -> Vec<u8> {
    schemes
        .iter()
        .flat_map(|scheme| u16::from(*scheme).to_be_bytes())
        .collect()
}

/// The scheme list of extension `typ` in the ClientHello at the start of
/// `flight`, if it has that extension.
pub fn hello_schemes(flight: &[u8], typ: u16) -> Option<Vec<SignatureScheme>> {
    crate::common::hello_wire::hello_extensions(flight, true)
        .into_iter()
        .find(|(t, _)| *t == typ)
        .map(|(_, body)| prefixed_schemes(&body))
}

/// Finds the TLS 1.2 CertificateRequest (handshake type 13, RFC 5246
/// §7.4.4) in a plaintext server `flight` whose handshake messages each
/// lie within one record, inserts `extra` at the front of its
/// `supported_signature_algorithms` (fixing the three lengths around it)
/// and returns the schemes it listed before.
pub fn add_to_tls12_certificate_request(
    flight: &mut Vec<u8>,
    extra: &[SignatureScheme],
) -> Vec<SignatureScheme> {
    let mut record = 0;
    while record + 5 <= flight.len() {
        let record_len = u16_at(flight, record + 3);
        let end = record + 5 + record_len;
        let mut msg = record + 5;
        while flight[record] == 22 && msg + 4 <= end {
            let len = u24_at(flight, msg + 1);
            if flight[msg] == 13 {
                let algs = msg + 4 + 1 + usize::from(flight[msg + 4]);
                let algs_len = u16_at(flight, algs);
                let listed = schemes_of(&flight[algs + 2..algs + 2 + algs_len]);
                let bytes = encode_schemes(extra);
                let added = bytes.len();
                flight.splice(algs + 2..algs + 2, bytes);
                put_u16(flight, algs, algs_len + added);
                // The 24-bit message length: its low 16 bits suffice here.
                assert_eq!(flight[msg + 1], 0);
                put_u16(flight, msg + 2, len + added);
                put_u16(flight, record + 3, record_len + added);
                return listed;
            }
            msg += 4 + len;
        }
        record = end;
    }
    panic!("no TLS 1.2 CertificateRequest in the flight")
}

/// The `signature_algorithms` of an exported authenticator request (a
/// TLS 1.3 CertificateRequest or a ClientCertificateRequest, RFC 9261 §4).
pub fn request_schemes(request: &[u8]) -> Vec<SignatureScheme> {
    assert_eq!(u24_at(request, 1) + 4, request.len());
    let mut at = 4 + 1 + usize::from(request[4]);
    let end = at + 2 + u16_at(request, at);
    assert_eq!(end, request.len());
    at += 2;
    while at < end {
        let len = u16_at(request, at + 2);
        if u16_at(request, at) == usize::from(EXT_SIGNATURE_ALGORITHMS) {
            return prefixed_schemes(&request[at + 4..at + 4 + len]);
        }
        at += 4 + len;
    }
    panic!("no signature_algorithms in the request")
}

/// An authenticator request of handshake type `typ` with `context` and
/// only `signature_algorithms` listing `schemes`, as a peer that does not
/// filter ML-DSA would build it.
pub fn raw_request(typ: u8, context: &[u8], schemes: &[SignatureScheme]) -> Vec<u8> {
    let list = encode_schemes(schemes);
    let mut ext = Vec::new();
    ext.extend_from_slice(&EXT_SIGNATURE_ALGORITHMS.to_be_bytes());
    ext.extend_from_slice(&u16::try_from(list.len() + 2).unwrap().to_be_bytes());
    ext.extend_from_slice(&u16::try_from(list.len()).unwrap().to_be_bytes());
    ext.extend_from_slice(&list);
    let mut body = vec![u8::try_from(context.len()).unwrap()];
    body.extend_from_slice(context);
    body.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&ext);
    let mut msg = vec![typ, 0];
    msg.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
    msg.extend_from_slice(&body);
    msg
}

/// The `handshake_failure` alert description (RFC 9846 §6).
pub const HANDSHAKE_FAILURE: u8 = 40;
/// The `illegal_parameter` alert description (RFC 9846 §6).
pub const ILLEGAL_PARAMETER: u8 = 47;

/// Where the first handshake message of type `typ` starts in the plaintext
/// part of `flight` (up to a ChangeCipherSpec), as `(record, message)`
/// offsets. Each message must lie within one record.
pub fn find_message(flight: &[u8], typ: u8) -> Option<(usize, usize)> {
    let mut record = 0;
    while record + 5 <= flight.len() && flight[record] != 20 {
        let end = record + 5 + u16_at(flight, record + 3);
        let mut msg = record + 5;
        while flight[record] == 22 && msg + 4 <= end {
            if flight[msg] == typ {
                return Some((record, msg));
            }
            assert_eq!(flight[msg + 1], 0, "message under 64 KiB");
            msg += 4 + u16_at(flight, msg + 2);
        }
        record = end;
    }
    None
}

/// Replaces the `signature_algorithms` of the ClientHello at the start of
/// `flight` with `schemes`, fixing the five lengths around it.
pub fn set_hello_schemes(flight: &mut Vec<u8>, schemes: &[SignatureScheme]) {
    let (record, msg) = find_message(flight, 1).unwrap();
    assert_eq!((record, msg), (0, 5));
    let mut at = msg + 4 + 2 + 32;
    at += 1 + usize::from(flight[at]);
    at += 2 + u16_at(flight, at);
    at += 1 + usize::from(flight[at]);
    let block = at;
    let end = block + 2 + u16_at(flight, block);
    at += 2;
    while at < end {
        let len = u16_at(flight, at + 2);
        if u16_at(flight, at) == usize::from(EXT_SIGNATURE_ALGORITHMS) {
            let list = encode_schemes(schemes);
            let mut body = u16::try_from(list.len()).unwrap().to_be_bytes().to_vec();
            body.extend_from_slice(&list);
            let delta = body.len() as isize - len as isize;
            let adjust = |buf: &mut Vec<u8>, at: usize| {
                let new = u16_at(buf, at) as isize + delta;
                put_u16(buf, at, usize::try_from(new).unwrap());
            };
            flight.splice(at + 4..at + 4 + len, body);
            adjust(flight, at + 2);
            adjust(flight, block);
            adjust(flight, msg + 2);
            adjust(flight, record + 3);
            return;
        }
        at += 4 + len;
    }
    panic!("no signature_algorithms in the ClientHello")
}

/// Rewrites the scheme of the `DigitallySignedStruct` at `at`.
pub fn set_scheme(flight: &mut [u8], at: usize, scheme: u16) {
    flight[at..at + 2].copy_from_slice(&scheme.to_be_bytes());
}

/// The `signature_algorithms` of the first datagram of a DTLS client
/// (RFC 9147 §5.3: a 13-byte record header and a 12-byte handshake header).
pub fn dtls_hello_schemes(datagram: &[u8]) -> Vec<SignatureScheme> {
    assert_eq!((datagram[0], datagram[13]), (22, 1), "a DTLS ClientHello");
    let mut at = 13 + 12 + 2 + 32;
    at += 1 + usize::from(datagram[at]); // session_id
    at += 1 + usize::from(datagram[at]); // cookie
    at += 2 + u16_at(datagram, at); // cipher_suites
    at += 1 + usize::from(datagram[at]); // compression_methods
    let end = at + 2 + u16_at(datagram, at);
    at += 2;
    while at < end {
        let len = u16_at(datagram, at + 2);
        if u16_at(datagram, at) == usize::from(EXT_SIGNATURE_ALGORITHMS) {
            return prefixed_schemes(&datagram[at + 4..at + 4 + len]);
        }
        at += 4 + len;
    }
    panic!("no signature_algorithms")
}
