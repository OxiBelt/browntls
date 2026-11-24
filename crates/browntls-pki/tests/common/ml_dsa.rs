//! ML-DSA (FIPS 204) test support for RFC 9881: signing keys derived at run
//! time from fixed seeds, an issuer abstraction shared with ECDSA P-256 for
//! mixed chains, and test-only `SignatureVerificationAlgorithm`s backed by
//! the RustCrypto `ml-dsa` crate as an independent oracle.
//!
//! No private key is stored: every ML-DSA key is `ML-DSA.KeyGen_internal`
//! over SHA-256 of a fixed label, and P-256 keys come from `rcgen` (ring).
//! Signing is pure ML-DSA, deterministic, with the empty context string
//! (RFC 9881 §3); verification uses the same empty context.

#![allow(dead_code, unreachable_pub, clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};

use browntls_pki::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id};
use ml_dsa::{
    EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature, SigningKey,
    VerifyingKey, signature::Keypair as _, signature::Signer as _,
};
use rcgen::{KeyPair, PublicKeyData as _, SigningKey as _};
use sha2::Digest as _;

/// An ML-DSA parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Set {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

pub const SETS: [Set; 3] = [Set::MlDsa44, Set::MlDsa65, Set::MlDsa87];

impl Set {
    /// The RFC 9881 §2 identifier (parameters absent), used both as the
    /// `SubjectPublicKeyInfo` algorithm and as the signature algorithm.
    pub fn alg_id(self) -> AlgorithmIdentifier {
        match self {
            Self::MlDsa44 => alg_id::ML_DSA_44,
            Self::MlDsa65 => alg_id::ML_DSA_65,
            Self::MlDsa87 => alg_id::ML_DSA_87,
        }
    }

    /// FIPS 204 Table 2 public key length.
    pub fn public_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// FIPS 204 Table 2 signature length.
    pub fn signature_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// The test verification algorithm for this set.
    pub fn alg(self) -> &'static MlDsaAlg {
        match self {
            Self::MlDsa44 => &ML_DSA_44,
            Self::MlDsa65 => &ML_DSA_65,
            Self::MlDsa87 => &ML_DSA_87,
        }
    }
}

// ---------------------------------------------------------------------------
// Verification (the oracle)
// ---------------------------------------------------------------------------

/// Pure ML-DSA verification with the empty context. A key or signature of
/// the wrong length, or one that does not decode, is a failure.
fn verify<P: MlDsaParams>(key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (
        EncodedVerifyingKey::<P>::try_from(key),
        Signature::<P>::try_from(sig),
    ) else {
        return false;
    };
    VerifyingKey::<P>::decode(&key).verify_with_context(msg, &[], &sig)
}

/// A test-only ML-DSA verification algorithm (RFC 9881 identifiers).
#[derive(Debug)]
pub struct MlDsaAlg {
    set: Set,
}

impl SignatureVerificationAlgorithm for MlDsaAlg {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let ok = match self.set {
            Set::MlDsa44 => verify::<MlDsa44>(public_key, message, signature),
            Set::MlDsa65 => verify::<MlDsa65>(public_key, message, signature),
            Set::MlDsa87 => verify::<MlDsa87>(public_key, message, signature),
        };
        if ok { Ok(()) } else { Err(InvalidSignature) }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.set.alg_id()
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.set.alg_id()
    }
}

pub static ML_DSA_44: MlDsaAlg = MlDsaAlg { set: Set::MlDsa44 };
pub static ML_DSA_65: MlDsaAlg = MlDsaAlg { set: Set::MlDsa65 };
pub static ML_DSA_87: MlDsaAlg = MlDsaAlg { set: Set::MlDsa87 };

/// The three ML-DSA test algorithms.
pub static ML_DSA_ALGS: &[&dyn SignatureVerificationAlgorithm] =
    &[&ML_DSA_44, &ML_DSA_65, &ML_DSA_87];

/// Wraps an algorithm and counts the signatures it is asked to verify and
/// how many it accepts, so tests can assert which algorithms a validation
/// actually exercised. Use one instance per test (tests run in parallel).
#[derive(Debug)]
pub struct Counted<'a> {
    inner: &'a dyn SignatureVerificationAlgorithm,
    calls: AtomicUsize,
    accepted: AtomicUsize,
}

impl<'a> Counted<'a> {
    pub fn new(inner: &'a dyn SignatureVerificationAlgorithm) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
            accepted: AtomicUsize::new(0),
        }
    }

    /// `(calls, accepted)`.
    pub fn counts(&self) -> (usize, usize) {
        (
            self.calls.load(Ordering::Relaxed),
            self.accepted.load(Ordering::Relaxed),
        )
    }

    pub fn reset(&self) {
        self.calls.store(0, Ordering::Relaxed);
        self.accepted.store(0, Ordering::Relaxed);
    }
}

impl SignatureVerificationAlgorithm for Counted<'_> {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let result = self.inner.verify_signature(public_key, message, signature);
        if result.is_ok() {
            self.accepted.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.inner.public_key_alg_id()
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.inner.signature_alg_id()
    }
}

// ---------------------------------------------------------------------------
// Signing keys
// ---------------------------------------------------------------------------

/// A signing key: ML-DSA from a fixed seed, or ECDSA P-256 (SHA-256).
pub enum Key {
    MlDsa44(Box<SigningKey<MlDsa44>>),
    MlDsa65(Box<SigningKey<MlDsa65>>),
    MlDsa87(Box<SigningKey<MlDsa87>>),
    P256(Box<KeyPair>),
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::MlDsa44(_) => "Key::MlDsa44",
            Self::MlDsa65(_) => "Key::MlDsa65",
            Self::MlDsa87(_) => "Key::MlDsa87",
            Self::P256(_) => "Key::P256",
        })
    }
}

/// The 32-byte FIPS 204 seed ξ for `(set, label)`: SHA-256 of a fixed
/// string, so keys are reproducible and nothing secret is stored.
fn seed(set: Set, label: &str) -> [u8; 32] {
    sha2::Sha256::digest(format!("browntls RFC 9881 test key {set:?} {label}")).into()
}

impl Key {
    /// The ML-DSA key of parameter set `set` derived from `label`.
    pub fn ml_dsa(set: Set, label: &str) -> Self {
        let seed = ml_dsa::B32::from(seed(set, label));
        match set {
            Set::MlDsa44 => Self::MlDsa44(Box::new(SigningKey::from_seed(&seed))),
            Set::MlDsa65 => Self::MlDsa65(Box::new(SigningKey::from_seed(&seed))),
            Set::MlDsa87 => Self::MlDsa87(Box::new(SigningKey::from_seed(&seed))),
        }
    }

    /// A fresh ECDSA P-256 key.
    pub fn p256() -> Self {
        Self::P256(Box::new(
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap(),
        ))
    }

    pub fn set(&self) -> Option<Set> {
        match self {
            Self::MlDsa44(_) => Some(Set::MlDsa44),
            Self::MlDsa65(_) => Some(Set::MlDsa65),
            Self::MlDsa87(_) => Some(Set::MlDsa87),
            Self::P256(_) => None,
        }
    }

    /// The `SubjectPublicKeyInfo` algorithm (identifier contents).
    pub fn key_alg(&self) -> AlgorithmIdentifier {
        self.set().map_or(alg_id::ECDSA_P256, Set::alg_id)
    }

    /// The signature algorithm this key signs with (identifier contents).
    pub fn sig_alg(&self) -> AlgorithmIdentifier {
        self.set().map_or(alg_id::ECDSA_SHA256, Set::alg_id)
    }

    /// The raw public key: the `subjectPublicKey` BIT STRING octets (the
    /// FIPS 204 `pkEncode` output for ML-DSA, an uncompressed point for
    /// P-256).
    pub fn public_key(&self) -> Vec<u8> {
        match self {
            Self::MlDsa44(k) => k.verifying_key().encode().to_vec(),
            Self::MlDsa65(k) => k.verifying_key().encode().to_vec(),
            Self::MlDsa87(k) => k.verifying_key().encode().to_vec(),
            Self::P256(k) => k.der_bytes().to_vec(),
        }
    }

    /// Signs `msg`: pure ML-DSA with the empty context (deterministic), or
    /// a DER ECDSA signature.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            Self::MlDsa44(k) => k.sign(msg).encode().to_vec(),
            Self::MlDsa65(k) => k.sign(msg).encode().to_vec(),
            Self::MlDsa87(k) => k.sign(msg).encode().to_vec(),
            Self::P256(k) => k.sign(msg).unwrap(),
        }
    }
}

// ---------------------------------------------------------------------------
// Algorithm identifiers that must never match an RFC 9881 algorithm
// ---------------------------------------------------------------------------

/// `AlgorithmIdentifier` contents for an OID given as its encoded arcs,
/// with parameters absent.
pub fn oid_alg(oid: &[u8]) -> Vec<u8> {
    let mut out = vec![0x06, oid.len() as u8];
    out.extend_from_slice(oid);
    out
}

/// The NIST `sigAlgs` arc 2.16.840.1.101.3.4.3 followed by `last`.
pub fn nist_sig_alg(last: u8) -> Vec<u8> {
    oid_alg(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, last])
}

/// `id-ml-dsa-*` with an explicit NULL parameter, forbidden by RFC 9881 §2.
pub fn with_null_params(alg: AlgorithmIdentifier) -> Vec<u8> {
    [alg.as_bytes(), &[0x05, 0x00]].concat()
}

/// Identifiers that are not RFC 9881 ML-DSA and must be unsupported in
/// either position: round 3 Dilithium (1.3.6.1.4.1.2.267.7.4.4, .6.5,
/// .8.7), ML-KEM (2.16.840.1.101.3.4.4.1-3) and HashML-DSA with SHA-512
/// (2.16.840.1.101.3.4.3.32-34, deliberately not supported, RFC 9881
/// §8.3).
pub fn foreign_alg_ids() -> Vec<(&'static str, Vec<u8>)> {
    let dilithium =
        |a: u8, b: u8| oid_alg(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x02, 0x82, 0x0b, 0x07, a, b]);
    let ml_kem = |n: u8| oid_alg(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, n]);
    vec![
        ("dilithium2 (round 3)", dilithium(4, 4)),
        ("dilithium3 (round 3)", dilithium(6, 5)),
        ("dilithium5 (round 3)", dilithium(8, 7)),
        ("id-alg-ml-kem-512", ml_kem(1)),
        ("id-alg-ml-kem-768", ml_kem(2)),
        ("id-alg-ml-kem-1024", ml_kem(3)),
        ("id-hash-ml-dsa-44-with-sha512", nist_sig_alg(32)),
        ("id-hash-ml-dsa-65-with-sha512", nist_sig_alg(33)),
        ("id-hash-ml-dsa-87-with-sha512", nist_sig_alg(34)),
    ]
}
