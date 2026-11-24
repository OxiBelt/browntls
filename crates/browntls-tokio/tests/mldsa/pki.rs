//! ML-DSA TLS 1.3 identities made with nothing but the library's public
//! API, for the crates whose tests have no ML-DSA certificate builder: a
//! private key is the RFC 9881 §6 PKCS #8 `seed` form of a fixed seed
//! (test data, nothing secret), loaded with
//! `crypto::native::sign::any_ml_dsa_type`, whose signer (pure ML-DSA,
//! empty context: also the RFC 9881 §3 certificate signature) signs a
//! minimal RFC 5280 certificate.
//!
//! The including crate root names the library as `tls` (`browntls_core`
//! or the facade `browntls`), so that the items are reached the way that
//! crate's tests reach them.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::sync::{Arc, Mutex};

use crate::tls::client::WebPkiServerVerifier;
use crate::tls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use crate::tls::crypto::CryptoProvider;
use crate::tls::crypto::native::{self, sign::any_ml_dsa_type};
use crate::tls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use crate::tls::server::WebPkiClientVerifier;
use crate::tls::server::danger::{ClientCertVerified, ClientCertVerifier};
use crate::tls::sign::SigningKey;
use crate::tls::{DigitallySignedStruct, DistinguishedName, Error, RootCertStore, SignatureScheme};

/// An ML-DSA parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Set {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

pub const SETS: [Set; 3] = [Set::MlDsa44, Set::MlDsa65, Set::MlDsa87];

impl Set {
    /// The TLS 1.3 scheme (`draft-ietf-tls-mldsa-06`, 0x0904 to 0x0906).
    pub fn scheme(self) -> SignatureScheme {
        match self {
            Self::MlDsa44 => SignatureScheme::ML_DSA_44,
            Self::MlDsa65 => SignatureScheme::ML_DSA_65,
            Self::MlDsa87 => SignatureScheme::ML_DSA_87,
        }
    }

    /// The RFC 9881 §2 `AlgorithmIdentifier`: `id-ml-dsa-*`
    /// (2.16.840.1.101.3.4.3.17 to .19), parameters absent.
    fn alg_id(self) -> Vec<u8> {
        let last = match self {
            Self::MlDsa44 => 0x11,
            Self::MlDsa65 => 0x12,
            Self::MlDsa87 => 0x13,
        };
        let oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, last];
        tlv(0x30, &tlv(0x06, &oid))
    }
}

/// A DER TLV (definite length).
fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    let mut out = vec![tag];
    match len {
        0..=0x7f => out.push(len as u8),
        0x80..=0xff => out.extend([0x81, len as u8]),
        _ => {
            let len = u16::try_from(len).unwrap();
            out.push(0x82);
            out.extend(len.to_be_bytes());
        }
    }
    out.extend_from_slice(contents);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// RFC 9881 §6: `OneAsymmetricKey` version 0 with the private key in the
/// `seed [0] IMPLICIT OCTET STRING (SIZE (32))` form.
pub fn pkcs8_seed(set: Set, seed: &[u8; 32]) -> PrivatePkcs8KeyDer<'static> {
    let private_key = tlv(0x04, &tlv(0x80, seed));
    PrivatePkcs8KeyDer::from(seq(&[&[0x02, 0x01, 0x00], &set.alg_id(), &private_key]))
}

/// `Name` with one `commonName`.
fn name(common_name: &str) -> Vec<u8> {
    let attribute = seq(&[
        &tlv(0x06, &[0x55, 0x04, 0x03]),
        &tlv(0x0c, common_name.as_bytes()),
    ]);
    seq(&[&tlv(0x31, &attribute)])
}

fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let critical: &[u8] = if critical { &[0x01, 0x01, 0xff] } else { &[] };
    seq(&[&tlv(0x06, oid), critical, &tlv(0x04, value)])
}

/// What the end entity is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// `serverAuth`, dNSName `localhost`.
    Server,
    /// `clientAuth`.
    Client,
}

struct Key {
    set: Set,
    signer: Arc<dyn SigningKey>,
    pkcs8: PrivatePkcs8KeyDer<'static>,
}

impl Key {
    fn new(set: Set, seed: u8) -> Self {
        let pkcs8 = pkcs8_seed(set, &[seed; 32]);
        let signer = any_ml_dsa_type(&pkcs8).unwrap();
        Self { set, signer, pkcs8 }
    }

    /// A certificate for `subject` (with this key's public key unless
    /// `subject_key` is given) signed by this key.
    fn certify(&self, serial: u8, subject: &str, key: &Self, extensions: &[Vec<u8>]) -> Vec<u8> {
        let spki = key.signer.public_key().unwrap();
        let validity = seq(&[&tlv(0x17, b"250101000000Z"), &tlv(0x18, b"20491231235959Z")]);
        let tbs = seq(&[
            &tlv(0xa0, &[0x02, 0x01, 0x02]),
            &[0x02, 0x01, serial],
            &self.set.alg_id(),
            &name("browntls ML-DSA test CA"),
            &validity,
            &name(subject),
            spki.as_ref(),
            &tlv(
                0xa3,
                &seq(&extensions.iter().map(Vec::as_slice).collect::<Vec<_>>()),
            ),
        ]);
        let signature = self
            .signer
            .choose_scheme(&[self.set.scheme()])
            .unwrap()
            .sign(&tbs)
            .unwrap();
        let bits = [&[0][..], &signature].concat();
        seq(&[&tbs, &self.set.alg_id(), &tlv(0x03, &bits)])
    }
}

/// A root (self-signed) and an end entity it certified, both ML-DSA keys
/// of one parameter set.
#[derive(Debug)]
pub struct Identity {
    pub set: Set,
    pub root: CertificateDer<'static>,
    pub end_entity: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

impl Identity {
    pub fn new(set: Set, purpose: Purpose) -> Self {
        let (root_seed, ee_seed) = match purpose {
            Purpose::Server => (0x11, 0x22),
            Purpose::Client => (0x33, 0x44),
        };
        let root = Key::new(set, root_seed);
        let ee = Key::new(set, ee_seed);
        // basicConstraints, keyUsage, extKeyUsage, subjectAltName.
        let (bc, ku, eku, san) = (
            [0x55, 0x1d, 0x13],
            [0x55, 0x1d, 0x0f],
            [0x55, 0x1d, 0x25],
            [0x55, 0x1d, 0x11],
        );
        let ca = [
            extension(&bc, true, &seq(&[&[0x01, 0x01, 0xff]])),
            // keyCertSign and cRLSign.
            extension(&ku, true, &[0x03, 0x02, 0x01, 0x06]),
        ];
        let root_cert = root.certify(1, "browntls ML-DSA test CA", &root, &ca);
        let mut ee_extensions = vec![
            extension(&bc, true, &seq(&[])),
            // digitalSignature.
            extension(&ku, true, &[0x03, 0x02, 0x07, 0x80]),
        ];
        // id-kp-serverAuth or id-kp-clientAuth (1.3.6.1.5.5.7.3.1 or .2).
        let kp = |n: u8| tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, n]);
        match purpose {
            Purpose::Server => {
                ee_extensions.push(extension(&eku, false, &seq(&[&kp(1)])));
                ee_extensions.push(extension(&san, false, &seq(&[&tlv(0x82, b"localhost")])));
            }
            Purpose::Client => ee_extensions.push(extension(&eku, false, &seq(&[&kp(2)]))),
        }
        let ee_cert = root.certify(2, "browntls ML-DSA test end entity", &ee, &ee_extensions);
        Self {
            set,
            root: CertificateDer::from(root_cert),
            end_entity: CertificateDer::from(ee_cert),
            key: ee.pkcs8,
        }
    }

    pub fn chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.end_entity.clone()]
    }

    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key.clone_key())
    }

    pub fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.root.clone()).unwrap();
        Arc::new(roots)
    }

    /// The library's server verifier for this root, with the opt-in table,
    /// recording the scheme of each handshake signature.
    pub fn server_verifier(&self) -> Arc<Recorder<WebPkiServerVerifier>> {
        let inner = WebPkiServerVerifier::builder_with_provider(self.roots(), opt_in())
            .build()
            .unwrap();
        Recorder::new(inner)
    }

    /// The library's client verifier (authentication mandatory), likewise.
    pub fn client_verifier(&self) -> Arc<Recorder<dyn ClientCertVerifier>> {
        let inner: Arc<dyn ClientCertVerifier> =
            WebPkiClientVerifier::builder_with_provider(self.roots(), opt_in())
                .build()
                .unwrap();
        Arc::new(Recorder {
            inner,
            seen: Mutex::default(),
        })
    }
}

/// The native provider with both halves of the ML-DSA opt-in.
pub fn opt_in() -> Arc<CryptoProvider> {
    let mut provider = native::default_provider();
    provider.signature_verification_algorithms = native::SUPPORTED_SIG_ALGS_WITH_ML_DSA_TLS13;
    provider.key_provider = native::KEY_PROVIDER_WITH_ML_DSA;
    Arc::new(provider)
}

pub fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

/// Wraps a verifier, recording the scheme of every handshake signature it
/// checks.
#[derive(Debug)]
pub struct Recorder<V: ?Sized> {
    inner: Arc<V>,
    seen: Mutex<Vec<SignatureScheme>>,
}

impl<V: ?Sized> Recorder<V> {
    fn new(inner: Arc<V>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            seen: Mutex::default(),
        })
    }

    pub fn seen(&self) -> Vec<SignatureScheme> {
        self.seen.lock().unwrap().clone()
    }

    fn record(&self, dss: &DigitallySignedStruct) {
        self.seen.lock().unwrap().push(dss.scheme);
    }
}

impl ServerCertVerifier for Recorder<WebPkiServerVerifier> {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.record(dss);
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.record(dss);
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

impl ClientCertVerifier for Recorder<dyn ClientCertVerifier> {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.record(dss);
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.record(dss);
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
