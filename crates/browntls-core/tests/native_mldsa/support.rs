//! Provider-independent helpers of the ML-DSA certificate tests
//! (`native_mldsa.rs`, `rustcrypto_mldsa.rs`): ML-DSA keys held by
//! `browntls_crypto::mldsa` and by the RustCrypto `ml-dsa` crate, issuers,
//! chains and their verification through a given provider.
//!
//! The including crate root declares `ml_dsa` and `x509` (the
//! `browntls-pki` test support files) next to this module.

#![allow(dead_code, unreachable_pub)]

use std::sync::Arc;
use std::time::Duration;

use browntls_core::client::WebPkiServerVerifier;
use browntls_core::client::danger::ServerCertVerifier as _;
use browntls_core::crypto::CryptoProvider;
use browntls_core::pki_types::{
    CertificateDer, CertificateRevocationListDer, ServerName, UnixTime,
};
use browntls_core::server::WebPkiClientVerifier;
use browntls_core::{CertificateError, Error, RootCertStore};
use browntls_crypto::mldsa;
use sha2::Digest as _;

use crate::ml_dsa::{Key, Set};
use crate::x509::{CLIENT_AUTH, CertSpec, Signed, basic_constraints, ext_key_usage, key_usage, ku};

/// The verification time: 2025-06-15, inside the builder's validity.
pub const NOW: u64 = 1_750_000_000;

pub fn now() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(NOW))
}

// ---------------------------------------------------------------------------
// Keys: one seed, two implementations
// ---------------------------------------------------------------------------

/// Which implementation signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Impl {
    /// `browntls_crypto::mldsa`.
    Native,
    /// The RustCrypto `ml-dsa` crate.
    Oracle,
}

enum NativeKey {
    K44(Box<mldsa::SigningKey<mldsa::MlDsa44>>),
    K65(Box<mldsa::SigningKey<mldsa::MlDsa65>>),
    K87(Box<mldsa::SigningKey<mldsa::MlDsa87>>),
}

/// An ML-DSA key held by both implementations, from the same FIPS 204 seed
/// (`ML-DSA.KeyGen_internal` is deterministic, so both hold one key pair).
pub struct MlKey {
    pub set: Set,
    /// The oracle's key, also what `x509_builder` takes for the
    /// identifiers and the `SubjectPublicKeyInfo`.
    pub oracle: Key,
    native: NativeKey,
}

impl core::fmt::Debug for MlKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MlKey({:?})", self.set)
    }
}

impl MlKey {
    pub fn new(set: Set, label: &str) -> Self {
        let seed: [u8; 32] =
            sha2::Sha256::digest(format!("browntls native ML-DSA test {set:?} {label}")).into();
        let b32 = ::ml_dsa::B32::from(seed);
        let (oracle, native) = match set {
            Set::MlDsa44 => (
                Key::MlDsa44(Box::new(::ml_dsa::SigningKey::from_seed(&b32))),
                NativeKey::K44(Box::new(mldsa::SigningKey::from_seed(&seed))),
            ),
            Set::MlDsa65 => (
                Key::MlDsa65(Box::new(::ml_dsa::SigningKey::from_seed(&b32))),
                NativeKey::K65(Box::new(mldsa::SigningKey::from_seed(&seed))),
            ),
            Set::MlDsa87 => (
                Key::MlDsa87(Box::new(::ml_dsa::SigningKey::from_seed(&b32))),
                NativeKey::K87(Box::new(mldsa::SigningKey::from_seed(&seed))),
            ),
        };
        let key = Self {
            set,
            oracle,
            native,
        };
        assert_eq!(key.native_public_key(), key.oracle.public_key(), "{set:?}");
        key
    }

    /// The raw public key (`pkEncode`) from `browntls_crypto`.
    pub fn native_public_key(&self) -> Vec<u8> {
        match &self.native {
            NativeKey::K44(k) => k.verifying_key().as_bytes().to_vec(),
            NativeKey::K65(k) => k.verifying_key().as_bytes().to_vec(),
            NativeKey::K87(k) => k.verifying_key().as_bytes().to_vec(),
        }
    }

    /// Pure ML-DSA, deterministic, empty context (RFC 9881 §3).
    pub fn sign(&self, by: Impl, msg: &[u8]) -> Vec<u8> {
        match (by, &self.native) {
            (Impl::Oracle, _) => self.oracle.sign(msg),
            (Impl::Native, NativeKey::K44(k)) => {
                k.sign_deterministic(msg, b"").unwrap().as_ref().to_vec()
            }
            (Impl::Native, NativeKey::K65(k)) => {
                k.sign_deterministic(msg, b"").unwrap().as_ref().to_vec()
            }
            (Impl::Native, NativeKey::K87(k)) => {
                k.sign_deterministic(msg, b"").unwrap().as_ref().to_vec()
            }
        }
    }

    /// Hedged signing by `browntls_crypto` (fresh randomness).
    pub fn sign_hedged(&self, msg: &[u8]) -> Vec<u8> {
        let rng = &browntls_crypto::rand::OsRng;
        match &self.native {
            NativeKey::K44(k) => k.sign(msg, b"", rng).unwrap().as_ref().to_vec(),
            NativeKey::K65(k) => k.sign(msg, b"", rng).unwrap().as_ref().to_vec(),
            NativeKey::K87(k) => k.sign(msg, b"", rng).unwrap().as_ref().to_vec(),
        }
    }
}

/// A certificate or CRL issuer: an ML-DSA key with the implementation that
/// signs, or a classical (ECDSA P-256) key.
#[derive(Clone, Copy, Debug)]
pub enum Issuer<'a> {
    MlDsa(&'a MlKey, Impl),
    Classical(&'a Key),
}

impl Issuer<'_> {
    /// The key `x509_builder` uses for identifiers and the SPKI.
    pub fn key(&self) -> &Key {
        match self {
            Self::MlDsa(k, _) => &k.oracle,
            Self::Classical(k) => k,
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            Self::MlDsa(k, by) => k.sign(*by, msg),
            Self::Classical(k) => k.sign(msg),
        }
    }

    /// `tbs` signed and labelled with this issuer's signature algorithm.
    pub fn signed(&self, tbs: Vec<u8>) -> Signed {
        let sig = self.sign(&tbs);
        Signed {
            tbs,
            alg: self.key().sig_alg().as_bytes().to_vec(),
            bits: [&[0u8][..], &sig].concat(),
        }
    }

    pub fn sign_cert(&self, spec: &CertSpec) -> Vec<u8> {
        self.signed(spec.tbs(self.key())).der()
    }
}

// ---------------------------------------------------------------------------
// Chains
// ---------------------------------------------------------------------------

/// What the end entity is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// `serverAuth`, dNSName `example.com`.
    Server,
    /// `clientAuth`.
    Client,
}

/// `root -> intermediates -> end entity`, each certificate built by
/// `x509_builder` and signed by its issuer.
#[derive(Debug)]
pub struct Chain {
    pub root: Vec<u8>,
    /// Nearest the end entity first, as a TLS peer sends them.
    pub intermediates: Vec<Vec<u8>>,
    pub ee: Vec<u8>,
}

/// Builds a chain. `intermediates` are given nearest the root first, each
/// with the `keyUsage` bits of its certificate (`None`: keyCertSign and
/// cRLSign).
pub fn build_chain(
    root: Issuer<'_>,
    intermediates: &[(Issuer<'_>, Option<&[u8]>)],
    ee: &Key,
    purpose: Purpose,
) -> Chain {
    let root_cert = root.sign_cert(&CertSpec::ca("root", "root", root.key()));
    let mut issuer = ("root".to_string(), root);
    let mut ints = Vec::new();
    for (i, (key, bits)) in intermediates.iter().enumerate() {
        let subject = format!("intermediate {i}");
        let mut spec = CertSpec::ca(&subject, &issuer.0, key.key());
        if let Some(bits) = bits {
            spec = spec.key_usage(Some(bits));
        }
        ints.push(issuer.1.sign_cert(&spec));
        issuer = (subject, *key);
    }
    let spec = match purpose {
        Purpose::Server => CertSpec::ee("end entity", &issuer.0, ee),
        Purpose::Client => CertSpec::bare("end entity", &issuer.0, ee).with(vec![
            basic_constraints(false, None),
            key_usage(&[ku::DIGITAL_SIGNATURE]),
            ext_key_usage(&[CLIENT_AUTH]),
        ]),
    };
    let ee = issuer.1.sign_cert(&spec);
    ints.reverse();
    Chain {
        root: root_cert,
        intermediates: ints,
        ee,
    }
}

impl Chain {
    pub fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(&self.root[..])).unwrap();
        Arc::new(roots)
    }

    pub fn intermediates(&self) -> Vec<CertificateDer<'_>> {
        self.intermediates
            .iter()
            .map(|c| CertificateDer::from(&c[..]))
            .collect()
    }

    /// Server authentication through [`WebPkiServerVerifier`] built with
    /// `provider`, checking revocation against `crls` if any.
    pub fn verify_server(
        &self,
        provider: Arc<CryptoProvider>,
        crls: &[Vec<u8>],
    ) -> Result<(), Error> {
        let verifier = WebPkiServerVerifier::builder_with_provider(self.roots(), provider)
            .with_crls(
                crls.iter()
                    .map(|crl| CertificateRevocationListDer::from(crl.clone())),
            )
            .build()
            .unwrap();
        verifier
            .verify_server_cert(
                &CertificateDer::from(&self.ee[..]),
                &self.intermediates(),
                &ServerName::try_from("example.com").unwrap(),
                &[],
                now(),
            )
            .map(|_| ())
    }

    /// Client authentication through [`WebPkiClientVerifier`].
    pub fn verify_client(&self, provider: Arc<CryptoProvider>) -> Result<(), Error> {
        let verifier = WebPkiClientVerifier::builder_with_provider(self.roots(), provider)
            .build()
            .unwrap();
        verifier
            .verify_client_cert(
                &CertificateDer::from(&self.ee[..]),
                &self.intermediates(),
                now(),
            )
            .map(|_| ())
    }
}

/// The `browntls-pki` error inside `CertificateError::Other`.
pub fn other_pki_error(result: Result<(), Error>) -> browntls_pki::Error {
    match result {
        Err(Error::InvalidCertificate(CertificateError::Other(other))) => other
            .0
            .downcast_ref::<browntls_pki::Error>()
            .expect("a browntls-pki error")
            .clone(),
        other => panic!("not CertificateError::Other: {other:?}"),
    }
}

pub const UNSUPPORTED: Error =
    Error::InvalidCertificate(CertificateError::UnsupportedSignatureAlgorithm);
pub const BAD_SIGNATURE: Error = Error::InvalidCertificate(CertificateError::BadSignature);
